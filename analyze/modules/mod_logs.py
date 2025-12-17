# modules/mod_logs.py
import re
import logging
import gzip
from pathlib import Path
from lib.finding import new_finding

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
                finding = new_finding()
                finding['type'] = 'logs'
                finding['message'] = f"Sudo authentication failed for user {match['user']} on tty {match['tty']}"
                finding['artifact'] = str(log_file)
                finding['indicator'] = "Sudo authentication failure"
                finding['meta'] = {
                                      "line": line,
                                      "user": match['user'],
                                      "logname": match['logname'],
                                      "tty": match['tty'],
                                      "uid": match['uid'],
                                      "euid": match['euid'],
                                      "rhost": match['rhost']
                                  }
                results.append(finding)
                continue

            # Desktop login failures
            match = desktop_fail_re.search(line)
            if match:
                finding = new_finding()
                finding['type'] = 'logs'
                finding['message'] = f"Failed desktop login for user {match['user']}"
                finding['artifact'] = str(log_file)
                finding['indicator'] = "Desktop authentication failure"
                finding['meta'] = {
                                      "line": line,
                                      "user": match['user']
                                  }
                results.append(finding)
                continue

            # SSH failures
            match = ssh_failed_re.search(line)
            if match:
                finding = new_finding()
                finding['type'] = 'logs'
                finding['message'] = f"Failed SSH login for user {match['user']} from {match['ip']}"
                finding['artifact'] = str(log_file)
                finding['indicator'] = "SSH authentication failure"
                finding['meta'] = {
                                      "line": line,
                                      "user": match['user'],
                                      "ip": match['ip']
                                  }
                results.append(finding)
                continue

            # SSH successes
            match = ssh_success_re.search(line)
            if match:
                finding = new_finding()
                finding['type'] = 'logs'
                finding['message'] = f"Successful SSH login for user {match['user']} from {match['ip']}"
                finding['artifact'] = str(log_file)
                finding['indicator'] = "SSH login success"
                finding['meta'] = {
                                      "line": line,
                                      "user": match['user'],
                                      "ip": match['ip']
                                  }
                results.append(finding)
    return results
