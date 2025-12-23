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
from pathlib import Path

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


#####################
# Module: listeners #
#####################

def _get_exec_path(pid):
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except Exception:
        return ""

def _extract_paths(text):
    PATH_RE = re.compile(
        r'(?<![\w-])'          # avoid --flag=/path
        r'(/(?:[A-Za-z0-9._+-]+/)*[A-Za-z0-9._+-]+)'
    )
    EXCLUDE_PREFIXES = (
        "/proc",
        "/sys",
        "/dev",
        "/run",
    )
    paths = set()
    for match in PATH_RE.findall(text):
        if match.startswith(EXCLUDE_PREFIXES):
            continue
        paths.add(match)
    return paths

def _extract_environment_files(text):
    paths = set()

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if not line.startswith("EnvironmentFile"):
            continue

        # EnvironmentFile=/path or EnvironmentFile=-/path
        _, _, value = line.partition("=")
        value = value.strip()
        if not value:
            continue

        # systemd allows multiple files separated by whitespace
        for token in value.split():
            optional = token.startswith("-")
            path = token[1:] if optional else token

            # Handle globs
            matches = glob.glob(path)
            for p in matches:
                if os.path.isfile(p) or os.path.isdir(p):
                    paths.add(p)

    return paths

def _get_cmdline_paths(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read()
        argv = raw.split(b"\x00")
        argv = [a.decode(errors="ignore") for a in argv if a]
    except Exception:
        return set()

    paths = set()

    for i, arg in enumerate(argv):
        # Case 1: argument itself contains a path
        for p in _extract_paths(arg):
            if os.path.isfile(p) or os.path.isdir(p):
                paths.add(p)

        # Case 2: flag followed by path (e.g. --config /etc/foo.conf)
        if arg.startswith("-") and i + 1 < len(argv):
            for p in _extract_paths(argv[i + 1]):
                if os.path.isfile(p) or os.path.isdir(p):
                    paths.add(p)

    return paths

def _get_unit_paths(unit_path):
    paths = set()

    try:
        with open(unit_path, "r") as f:
            content = f.read()
            # regular path extraction
            for p in _extract_paths(content):
                if os.path.isfile(p) or os.path.isdir(p):
                    paths.add(p)
            # EnvironmentFile extraction
            paths |= _extract_environment_files(content)
    except Exception:
        return paths

    # Drop-in directory: foo.service.d/*.conf
    dropin_dir = f"{unit_path}.d"
    if os.path.isdir(dropin_dir):
        for name in os.listdir(dropin_dir):
            if not name.endswith(".conf"):
                continue
            try:
                with open(os.path.join(dropin_dir, name), "r") as f:
                    content = f.read()
                    for p in _extract_paths(content):
                        if os.path.isfile(p) or os.path.isdir(p):
                            paths.add(p)
                    paths |= _extract_environment_files(content)
            except Exception:
                pass

    return paths


def _get_systemd_unit(pid):
    """
    Returns systemd unit name (e.g. ssh.service) or empty string
    """
    try:
        with open(f"/proc/{pid}/cgroup", "r") as f:
            for line in f:
                # system.slice/ssh.service
                match = re.search(r"/([^/]+\.service)", line)
                if match:
                    return match.group(1)
    except Exception:
        pass
    return ""

def _get_systemd_fragment(unit):
    """
    Returns full path to unit file or empty string
    """
    try:
        proc = subprocess.run(
            ["systemctl", "show", "-p", "FragmentPath", unit],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            _, _, value = proc.stdout.partition("=")
            return value.strip()
    except Exception:
        pass
    return ""

def _get_listeners():
    cmd = "ss -H -l -n -p -u -t"
    stdout, stderr = _command(cmd)

    result = {"tcp": [], "udp": []}

    pid_re = re.compile(r'pid=(\d+)')
    proc_re = re.compile(r'\("([^"]+)"')
    port_re = re.compile(r':(\d+)$')
    addr_re = re.compile(r'(.*):\d+$')

    # Cache systemd lookups (huge speed win)
    systemd_cache = {}

    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue

        protocol = parts[0]
        local_addr = parts[4]
        bind_match = addr_re.search(local_addr)
        port_match = port_re.search(local_addr)
        if not port_match or not bind_match:
            continue
        bind = bind_match.group(1)
        port = int(port_match.group(1))

        pid_match = pid_re.search(line)
        proc_match = proc_re.search(line)
        if not pid_match or not proc_match:
            continue

        pid = int(pid_match.group(1))
        process = proc_match.group(1)

        exec_path = _get_exec_path(pid)

        # --- systemd handling ---
        systemd_unit = _get_systemd_unit(pid)
        systemd_path = ""

        if systemd_unit:
            if systemd_unit not in systemd_cache:
                systemd_cache[systemd_unit] = _get_systemd_fragment(systemd_unit)
            systemd_path = systemd_cache[systemd_unit]

        # --- related paths ---
        related_paths = set()

        # from cmdline
        related_paths |= _get_cmdline_paths(pid)

        # from systemd unit
        if systemd_path:
            related_paths |= _get_unit_paths(systemd_path)

        entry = {
            "pid": pid,
            "protocol": protocol,
            "bind": bind,
            "port": port,
            "process": process,
            "exec": exec_path,
            "systemd": systemd_path,
            "related_paths": sorted(related_paths),
        }

        if protocol in result:
            result[protocol].append(entry)
    return result

def listeners(outdir, config):
    """
    Get details of network listening processes
    """
    listener_data = _get_listeners()
    with open(os.path.join(outdir, "listeners.json"), 'w+') as f:
        f.write(json.dumps(listener_data, indent=2))
