import os
import re
import json
from pathlib import Path
from lib.finding import new_finding

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

                finding = new_finding()
                finding['type'] = "persistence"
                finding['artifact'] = _rel(svc, rootdir)
                finding['meta']['execstart'] = exec_cmd
                finding['meta']['service_name'] = svc_name
                # Suspicious entropy service name
                if _high_entropy(svc_name):
                    finding.update({
                        "indicator": "High entropy service name",
                        "message": "Service name resembles randomly generated malware loader."
                    })
                    results.append(finding)

                # ExecStart writable path
                if _is_writable(exec_cmd):
                    finding.update({
                        "indicator": "Executable in writable directory",
                        "message": f"ExecStart uses a writable path: {exec_cmd}"
                    })
                    results.append(finding)

                # Suspicious command
                if _cmd_suspicious(exec_cmd):
                    finding.update({
                        "indicator": "Suspicious ExecStart command",
                        "message": "ExecStart contains potentially malicious command patterns."
                    })
                    results.append(finding)

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

                finding = new_finding()
                finding['type'] = "persistence"
                finding['artifact'] = _rel(cronfile, rootdir)
                finding['meta']['command'] = cmd

                if _is_writable(cmd):
                    finding.update({
                        "indicator": "Writable-path cron job",
                        "message": f"Cron executes script from writable path: {cmd}"
                    })
                    results.append(finding)

                if _cmd_suspicious(cmd):
                    finding.update({
                        "indicator": "Suspicious cron job command",
                        "message": "Cron job contains suspicious patterns."
                    })
                    results.append(finding)

                # Every minute cron job → often persistence
                if parts[0] == "*" and parts[1] == "*":
                    finding.update({
                        "indicator": "High-frequency cron job",
                        "message": "Executes every minute – common persistence trick."
                    })
                    results.append(finding)

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
                    finding = new_finding()
                    finding['type'] = "persistence"
                    finding['artifact'] = _rel(f, rootdir)
                    finding['indicator'] = "Suspicious profile command"
                    finding['message'] = "Potential persistence via shell profile modification."
                    finding['meta']['line'] = line_strip
                    results.append(finding)

                if "alias" in line_strip and "=" in line_strip:
                    finding = new_finding()
                    finding['type'] = "persistence"
                    finding['artifact'] = _rel(f, rootdir)
                    finding['indicator'] = "Suspicious alias"
                    finding['message'] = "Shell alias may override system binaries."
                    finding['meta']['line'] = line_strip
                    results.append(finding)

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
                finding = new_finding()
                finding['type'] = "persistence"
                finding['artifact'] = _rel(f, rootdir)
                finding['indicator'] = "Authorized key persistence"
                finding['message'] = "SSH authorized_keys allows persistent access."
                results.append(finding)

            if f.name.endswith("config"):
                try:
                    txt = f.read_text(errors="ignore")
                    if "ProxyCommand" in txt or "Match" in txt:
                        finding = new_finding()
                        finding['type'] = "persistence"
                        finding['artifact'] = _rel(f, rootdir)
                        finding['indicator'] = "Suspicious SSH config"
                        finding['message'] = "SSH client config might enable tunneling or covert channels."
                        results.append(finding)
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
