import subprocess
import hashlib
import os
import re
import shutil
import logging
import glob
import stat
import pwd
import grp
import json
import socket
import psutil
from datetime import datetime
from pathlib import Path
from collections import defaultdict

def _command(cmd):
    logging.info(f"Running command: {cmd}")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True,
            errors="ignore"
        )
    except Exception as e:
        raise RuntimeError(f"Failed to execute grep: {e}")
    return proc.stdout, proc.stderr


def basic_info(outdir):
    logging.info("Gather basic information for info.json")
    ip_stdout, ip_stderr  = _command('ip a')
    uname_stdout, uname_stderr  = _command('uname -a')
    os_stdout, os_stderr  = _command('cat /etc/os-release')
    now = datetime.now().strftime('%s')
    hostname  = socket.gethostname()
    with open(os.path.join(outdir, "info.json"), 'w+') as f:
         f.write(json.dumps({"date": int(now), "hostname": hostname, "ips": ip_stdout, "uname": uname_stdout, 'os_release': os_stdout}))


def _store_output(outdir, outfile, cmd, stdout, stderr):
    logging.info(f"Store command output: {outfile}")
    outdir = os.path.join(outdir, 'commands')
    os.makedirs(outdir, exist_ok=True)
    if stdout:
        with open(os.path.join(outdir, f"stdout.{outfile}"), 'a+') as f:
            f.write(f'#command:{cmd}\n')
            f.write(stdout+'\n')
    if stderr:
        with open(os.path.join(outdir, f"stderr.{outfile}"), 'a+') as f:
            f.write(f'#command:{cmd}\n')
            f.write(stderr+'\n')

def _copy_with_full_path(src_path, outdir):
    os.makedirs(outdir, exist_ok=True)
    base_name = os.path.basename(os.path.normpath(src_path))
    dest_path = os.path.join(outdir, base_name)
    src_path = os.path.abspath(src_path)  # ensure absolute path
    rel_path = src_path.lstrip(os.sep)    # remove leading slash
    dest_path = os.path.join(outdir, rel_path)

    if os.path.isdir(src_path):
        shutil.copytree(
            src_path,
            dest_path,
            symlinks=True,
            copy_function=shutil.copy2,
            dirs_exist_ok=True
        )
    elif os.path.isfile(src_path):
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        shutil.copy2(src_path, dest_path)
    else:
        logging.warning(f"Source path does not exist: {src_path}")

def commands(outdir, config):
    logging.info(f"Collecting command outputs")
    for cmd in config['list']:
        stdout, stderr = _command(cmd)
        _store_output(outdir, f"{cmd.split()[0]}.txt", cmd, stdout, stderr)

def files_and_dirs(outdir, config):
    for p in config['list']:
        logging.info(f"Copying path {p}")
        expanded_paths = glob.glob(p)
        for ep in  expanded_paths:
            _copy_with_full_path(ep, os.path.join(outdir, "files_and_dirs"))

def luks(outdir, config):
    """
    Return a list of LUKS-encrypted block devices on the system.
    Uses lsblk + fstype detection.
    """
    luks_devices = []

    # Use lsblk to list devices and their FSTYPE
    result = subprocess.run(
        ["lsblk", "-o", "NAME,FSTYPE", "-rn"],
        capture_output=True,
        text=True,
        check=True
    )

    for line in result.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) == 2:
            name, fstype = parts
            if "crypto_LUKS" in fstype or "LUKS" in fstype:
                luks_devices.append(f"/dev/{name}")

    for luksdev in luks_devices:
        cmd = f"cryptsetup luksDump {luksdev}"
        stdout, stderr = _command(cmd)
        _store_output(outdir, f"{cmd.split()[0]}.txt", cmd, stdout, stderr)

def _get_md5(file_path, chunk_size=8192):
    """
    Calculate MD5 hash of a file.
    """
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            md5.update(chunk)
    return md5.hexdigest()

def _get_sha1(file_path, chunk_size=8192):
    """
    Calculate SHA-1 hash of a file.
    """
    sha1 = hashlib.sha1()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha1.update(chunk)
    return sha1.hexdigest()

def _get_sha256(file_path, chunk_size=8192):
    """
    Calculate SHA-256 hash of a file.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def _store_checksums(outdir, filename, content):
    outdir = os.path.join(outdir, 'checksums')
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, filename), 'w+') as f:
        for c in content:
            f.write(f"{c}\n")

def checksums(outdir, config):
    md5s = []
    sha1s = []
    sha256s = []
    file_list = []
    for fp in config['list']:
        if os.path.isfile(fp):
            file_list.append(fp)
        elif os.path.isdir(fp):
            for sfp in Path(fp).rglob("*"):
                if os.path.isfile(str(sfp)):
                    file_list.append(str(sfp))

    for fp in file_list:
        logging.info(f"Calculating hashes for {fp}")
        md5_hash = _get_md5(fp)
        sha1_hash = _get_sha1(fp)
        sha256_hash = _get_sha256(fp)
        md5s.append(f"{fp} - {md5_hash}")
        sha1s.append(f"{fp} - {sha1_hash}")
        sha256s.append(f"{fp} - {sha256_hash}")
    _store_checksums(outdir,'md5.txt', md5s)
    _store_checksums(outdir,'sha1.txt', sha1s)
    _store_checksums(outdir,'sha256.txt', sha256s)

def file_permissions(outdir, config):
    outfile = os.path.join(outdir, "file_permissions.txt")
    os.makedirs(outdir, exist_ok=True)

    with open(outfile, "w") as f:
        for fp in config['list']:
            for sfp in Path(fp).rglob("*"):
                logging.info(f"Getting file permissions for path: {sfp}")
                try:
                    s = os.lstat(sfp)

                    # Numeric permissions without "0o" prefix
                    numeric = f"{s.st_mode & 0o777:o}"

                    # Symbolic permissions
                    symbolic = stat.filemode(s.st_mode)

                    # Owner / group
                    owner = pwd.getpwuid(s.st_uid).pw_name
                    group = grp.getgrgid(s.st_gid).gr_name

                    size = s.st_size
                    mtime = s.st_mtime

                    f.write(
                        f"{sfp} "
                        f"{numeric} "
                        f"{symbolic} "
                        f"{owner}:{group} "
                        f"{size} "
                        f"{mtime}\n"
                    )

                except Exception as e:
                    f.write(f"{sfp} ERROR: {e}\n")


# ---------------- systemd helpers ---------------- #

def _get_systemd_unit(pid):
    try:
        with open(f"/proc/{pid}/cgroup") as f:
            for line in f:
                m = re.search(r"/([^/]+\.service)", line)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return ""


def _get_systemd_fragment(unit):
    try:
        proc = subprocess.run(
            ["systemctl", "show", "-p", "FragmentPath", unit],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            return proc.stdout.partition("=")[2].strip()
    except Exception:
        pass
    return ""


# ---------------- path extraction ---------------- #

PATH_RE = re.compile(
    r'(?<![\w-])(/(?:[A-Za-z0-9._+-]+/)*[A-Za-z0-9._+-]+)'
)
EXCLUDE_PREFIXES = ("/proc", "/sys", "/dev", "/run")


def _extract_paths(text):
    return {
        p for p in PATH_RE.findall(text)
        if not p.startswith(EXCLUDE_PREFIXES)
        and (os.path.isfile(p) or os.path.isdir(p))
    }


def _extract_environment_files(text):
    paths = set()
    for line in text.splitlines():
        if not line.strip().startswith("EnvironmentFile"):
            continue
        _, _, value = line.partition("=")
        for token in value.split():
            token = token.lstrip("-")
            paths |= {
                p for p in glob.glob(token)
                if os.path.isfile(p) or os.path.isdir(p)
            }
    return paths


def _get_unit_paths(unit_path):
    paths = set()
    try:
        with open(unit_path) as f:
            content = f.read()
        paths |= _extract_paths(content)
        paths |= _extract_environment_files(content)
    except Exception:
        return paths

    dropin = f"{unit_path}.d"
    if os.path.isdir(dropin):
        for name in os.listdir(dropin):
            if name.endswith(".conf"):
                try:
                    with open(os.path.join(dropin, name)) as f:
                        content = f.read()
                    paths |= _extract_paths(content)
                    paths |= _extract_environment_files(content)
                except Exception:
                    pass

    return paths


# ---------------- network pre-scan ---------------- #

def _scan_network():
    net = defaultdict(lambda: {"tcp": [], "udp": []})
    seen = set()

    for conn in psutil.net_connections(kind="inet"):
        if not conn.pid or not conn.laddr:
            continue

        if conn.type == socket.SOCK_STREAM:
            if conn.status != psutil.CONN_LISTEN:
                continue
            proto = "tcp"
        elif conn.type == socket.SOCK_DGRAM:
            proto = "udp"
        else:
            continue

        key = (conn.pid, proto, conn.laddr.ip, conn.laddr.port)
        if key in seen:
            continue
        seen.add(key)

        net[conn.pid][proto].append({
            "bind": conn.laddr.ip,
            "port": conn.laddr.port,
        })

    return net


# ---------------- unified process scan ---------------- #

def processes(outdir, config):
    systemd_cache = {}
    network = _scan_network()
    result = []

    for proc in psutil.process_iter(["pid", "ppid", "name"]):
        try:
            pid = proc.pid
            entry = {
                "pid": pid,
                "ppid": proc.ppid(),
                "process": proc.name(),
                "exec": proc.exe(),
                "cmdline": " ".join(proc.cmdline()),
                "systemd": "",
                "related_paths": [],
                "network": network.get(pid, {"tcp": [], "udp": []}),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        # --- systemd ---
        unit = _get_systemd_unit(pid)
        if unit:
            entry["systemd"] = systemd_cache.setdefault(
                unit, _get_systemd_fragment(unit)
            )

        # --- related paths ---
        paths = set()
        paths.add(entry["exec"])
        paths |= _extract_paths(entry["cmdline"])

        if entry["systemd"]:
            paths |= _get_unit_paths(entry["systemd"])

        entry["related_paths"] = sorted(paths)
        result.append(entry)

    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "processes.json"), "w") as f:
        json.dump(result, f, indent=2)
