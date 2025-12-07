# modules/mod_logs.py
from pathlib import Path
import re
import logging
import gzip

def _open_log(path):
    """Open normal or gzipped log file in text mode"""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", errors="ignore")
    else:
        return open(path, "r", errors="ignore")


def analyze(rootdir):
    """
    Parse authentication logs across major Linux distributions.

    Supports:
      - Debian/Ubuntu: auth.log*
      - RHEL/CentOS/Fedora: secure*
      - Handles rotated .gz files
    Extracts:
      - Sudo authentication failures
      - SSH login failures/successes
      - Desktop login failures (GDM/LightDM/login)
    """
    results = []
    log_dir = Path(rootdir) / "files_and_dirs/var/log"

    # Regex patterns
    sudo_fail_re = re.compile(
        r"sudo: pam_unix\(sudo:auth\): authentication failure; "
        r"logname=(?P<logname>\S+) uid=(?P<uid>\d+) euid=(?P<euid>\d+) "
        r"tty=(?P<tty>\S+) ruser=(?P<ruser>\S*) rhost=(?P<rhost>\S*)\s*user=(?P<user>\S+)"
    )

    desktop_fail_re = re.compile(
        r"(gdm|lightdm|login).*authentication failure.*user=(?P<user>\S+)"
    )

    ssh_failed_re = re.compile(r"Failed password for (?P<user>\S+) from (?P<ip>\S+) port")
    ssh_success_re = re.compile(r"Accepted .* for (?P<user>\S+) from (?P<ip>\S+)")

    # Collect all relevant logs (Debian/Ubuntu + RHEL/CentOS)
    log_files = list(log_dir.glob("auth.log*")) + list(log_dir.glob("secure*"))

    for log_file in log_files:
        logging.info(f"Checking log file: {log_file}")
        try:
            with _open_log(log_file) as f:
                lines = f.readlines()
        except Exception:
            continue

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Sudo failures
            match = sudo_fail_re.search(line)
            if match:
                results.append({
                    "artifact": str(log_file),
                    "indicator": "Sudo authentication failure",
                    "description": f"Sudo authentication failed for user {match['user']} on tty {match['tty']}",
                    "line": line,
                    "user": match['user'],
                    "logname": match['logname'],
                    "tty": match['tty'],
                    "uid": match['uid'],
                    "euid": match['euid'],
                    "rhost": match['rhost']
                })
                continue

            # Desktop login failures
            match = desktop_fail_re.search(line)
            if match:
                results.append({
                    "artifact": str(log_file),
                    "indicator": "Desktop authentication failure",
                    "description": f"Failed desktop login for user {match['user']}",
                    "line": line,
                    "user": match['user']
                })
                continue

            # SSH failures
            match = ssh_failed_re.search(line)
            if match:
                results.append({
                    "artifact": str(log_file),
                    "indicator": "SSH authentication failure",
                    "description": f"Failed SSH login for user {match['user']} from {match['ip']}",
                    "line": line,
                    "user": match['user'],
                    "ip": match['ip']
                })
                continue

            # SSH successes
            match = ssh_success_re.search(line)
            if match:
                results.append({
                    "artifact": str(log_file),
                    "indicator": "SSH login success",
                    "description": f"Successful SSH login for user {match['user']} from {match['ip']}",
                    "line": line,
                    "user": match['user'],
                    "ip": match['ip']
                })
                continue

    return results
