import os
import re
import json
from pathlib import Path


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def _rel(path, rootdir):
    """Return a path relative to the triage root directory."""
    try:
        return str(Path(path).relative_to(rootdir))
    except Exception:
        return str(path)


def _is_writable(path):
    """Heuristic: user-writable or world-writable directories."""
    writable_dirs = [
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/run/user",
    ]
    return any(str(path).startswith(w) for w in writable_dirs)


def _cmd_suspicious(cmd):
    """Detect suspicious commands in service/cron/profile."""
    indicators = [
        r"curl\s+.*\|", r"wget\s+.*\|", r"base64", r"python\s+-c",
        r"nc\s+-e", r"bash\s+-i", r"/tmp/", r"/dev/shm/", r"chmod\s+\+s",
        r"chattr\s+\+\w", r"scp.*:", r"ssh.*@", r"socat",
    ]
    return any(re.search(i, cmd) for i in indicators)


def _high_entropy(s, threshold=4.0):
    """Detect high‑entropy service names used by malware."""
    if not s:
        return False
    import math
    freq = {c: s.count(c) for c in set(s)}
    entropy = -sum((freq[c]/len(s)) * math.log2(freq[c]/len(s)) for c in freq)
    return entropy >= threshold and len(s) >= 6


# ---------------------------------------------------------
# SYSTEMD ANALYSIS
# ---------------------------------------------------------

def check_systemd(rootdir):
    results = []
    service_dirs = [
        Path(rootdir) / "etc/systemd/system",
        Path(rootdir) / "usr/lib/systemd/system",
        Path(rootdir) / "lib/systemd/system",
    ]

    for sdir in service_dirs:
        if not sdir.exists():
            continue

        for svc in sdir.rglob("*.service"):
            try:
                content = svc.read_text(errors="ignore")
            except Exception:
                continue

            svc_name = svc.name.replace(".service", "")
            exec_matches = re.findall(r"ExecStart\s*=\s*(.*)", content)

            for exec_cmd in exec_matches:
                exec_cmd = exec_cmd.strip()

                entry = {
                    "artifact": _rel(svc, rootdir),
                    "indicator": "",
                    "severity": "",
                    "description": "",
                    "execstart": exec_cmd,
                    "service_name": svc_name
                }

                # Suspicious entropy service name
                if _high_entropy(svc_name):
                    entry.update({
                        "indicator": "High entropy service name",
                        "severity": "high",
                        "description": "Service name resembles randomly generated malware loader."
                    })
                    results.append(entry)

                # ExecStart writable path
                if _is_writable(exec_cmd):
                    entry.update({
                        "indicator": "Executable in writable directory",
                        "severity": "high",
                        "description": f"ExecStart uses a writable path: {exec_cmd}"
                    })
                    results.append(entry)

                # Suspicious command
                if _cmd_suspicious(exec_cmd):
                    entry.update({
                        "indicator": "Suspicious ExecStart command",
                        "severity": "high",
                        "description": "ExecStart contains potentially malicious command patterns."
                    })
                    results.append(entry)

    return results


# ---------------------------------------------------------
# CRON ANALYSIS
# ---------------------------------------------------------

def check_cron(rootdir):
    results = []
    cron_paths = [
        Path(rootdir) / "etc/crontab",
        Path(rootdir) / "etc/cron.d",
        Path(rootdir) / "var/spool/cron",
    ]

    for cpath in cron_paths:
        if not cpath.exists():
            continue

        files = [cpath] if cpath.is_file() else cpath.rglob("*")

        for cronfile in files:
            if not cronfile.is_file():
                continue

            try:
                lines = cronfile.read_text(errors="ignore").splitlines()
            except:
                continue

            for line in lines:
                line_strip = line.strip()
                if not line_strip or line_strip.startswith("#"):
                    continue

                # Detect schedule + command
                # cron format: m h dom mon dow command...
                parts = line_strip.split(None, 5)
                if len(parts) < 6:
                    continue

                cmd = parts[5]

                entry = {
                    "artifact": _rel(cronfile, rootdir),
                    "command": cmd,
                    "indicator": "",
                    "severity": "",
                    "description": ""
                }

                if _is_writable(cmd):
                    entry.update({
                        "indicator": "Writable-path cron job",
                        "severity": "high",
                        "description": f"Cron executes script from writable path: {cmd}"
                    })
                    results.append(entry)

                if _cmd_suspicious(cmd):
                    entry.update({
                        "indicator": "Suspicious cron job command",
                        "severity": "high",
                        "description": "Cron job contains suspicious patterns."
                    })
                    results.append(entry)

                # Every minute cron job → often persistence
                if parts[0] == "*" and parts[1] == "*":
                    entry.update({
                        "indicator": "High-frequency cron job",
                        "severity": "medium",
                        "description": "Executes every minute – common persistence trick."
                    })
                    results.append(entry)

    return results


# ---------------------------------------------------------
# SHELL PROFILE ANALYSIS
# ---------------------------------------------------------

def check_shell_profiles(rootdir):
    results = []

    profile_candidates = [
        "etc/profile",
        "etc/bash.bashrc",
        "etc/profile.d",
        "root/.bashrc",
        "root/.profile",
    ]

    # add user home profiles
    for home in (Path(rootdir) / "home").glob("*"):
        profile_candidates.append(f"home/{home.name}/.bashrc")
        profile_candidates.append(f"home/{home.name}/.profile")

    for relp in profile_candidates:
        p = Path(rootdir) / relp
        if not p.exists():
            continue

        files = [p] if p.is_file() else p.rglob("*")

        for f in files:
            if not f.is_file():
                continue

            try:
                content = f.read_text(errors="ignore")
            except:
                continue

            for line in content.splitlines():
                line_strip = line.strip()
                if not line_strip or line_strip.startswith("#"):
                    continue

                if _cmd_suspicious(line_strip):
                    results.append({
                        "artifact": _rel(f, rootdir),
                        "indicator": "Suspicious profile command",
                        "severity": "high",
                        "description": "Potential persistence via shell profile modification.",
                        "line": line_strip
                    })

                if "alias" in line_strip and "=" in line_strip:
                    results.append({
                        "artifact": _rel(f, rootdir),
                        "indicator": "Suspicious alias",
                        "severity": "medium",
                        "description": "Shell alias may override system binaries.",
                        "line": line_strip
                    })

    return results


# ---------------------------------------------------------
# SSH Persistence
# ---------------------------------------------------------

def check_ssh(rootdir):
    results = []

    ssh_dirs = [
        Path(rootdir) / "root/.ssh",
        *(Path(rootdir) / "home").glob("*/.ssh"),
    ]

    for sdir in ssh_dirs:
        if not sdir.exists():
            continue

        for f in sdir.glob("*"):
            if not f.is_file():
                continue

            if f.name == "authorized_keys":
                results.append({
                    "artifact": _rel(f, rootdir),
                    "indicator": "Authorized key persistence",
                    "severity": "medium",
                    "description": "SSH authorized_keys allows persistent access."
                })

            if f.name.endswith("config"):
                try:
                    txt = f.read_text(errors="ignore")
                    if "ProxyCommand" in txt or "Match" in txt:
                        results.append({
                            "artifact": _rel(f, rootdir),
                            "indicator": "Suspicious SSH config",
                            "severity": "high",
                            "description": "SSH client config might enable tunneling or covert channels."
                        })
                except:
                    pass

    return results


# ---------------------------------------------------------
# MAIN ENTRYPOINT
# ---------------------------------------------------------

def analyze(rootdir):
    """
    rootdir is the TRIAGE ROOT, i.e. the directory containing:
        files_and_dirs/
        commands/
        capture/
        etc.
    """
    fdir = Path(rootdir) / "files_and_dirs"
    if not fdir.exists():
        raise RuntimeError(f"files_and_dirs missing in triage directory: {rootdir}")

    results = []

    # systemd, cron, profiles, ssh
    results.extend(check_systemd(fdir))
    results.extend(check_cron(fdir))
    results.extend(check_shell_profiles(fdir))
    results.extend(check_ssh(fdir))

    return results
