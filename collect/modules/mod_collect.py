import subprocess
import hashlib
import os
import shutil
import logging
import tarfile
import glob
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

def _store_output(outdir, outfile, stdout, stderr):
    logging.info(f"Store command output: {outfile}")
    outdir = os.path.join(outdir, 'commands')
    os.makedirs(outdir, exist_ok=True)
    if stdout:
        with open(os.path.join(outdir, f"stdout.{outfile}"), 'w+') as f:
            f.write(stdout)
    if stderr:
        with open(os.path.join(outdir, f"stdout.{outfile}"), 'w+') as f:
            f.write(stdout)

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

def _tar_files_and_dirs(outdir, target_dir_name="files_and_dirs"):
    src_path = os.path.join(outdir, target_dir_name)
    if not os.path.exists(src_path):
        raise FileNotFoundError(f"Source directory does not exist: {src_path}")

    tar_path = os.path.join(outdir, f"{target_dir_name}.tar.gz")

    # Create tar.gz archive
    with tarfile.open(tar_path, "w:gz") as tar:
        # Add the directory, keeping its name inside the archive
        tar.add(src_path, arcname=target_dir_name)

    # Remove the original directory
    shutil.rmtree(src_path)


def commands(outdir, commands):
    logging.info(f"Collecting command outputs")
    for cmd in commands:
        stdout, stderr = _command(cmd)
        _store_output(outdir, f"{cmd.replace(' ', '_').replace('-','_').replace('/', '_').replace('=', '_')}.txt", stdout, stderr)

def files_and_dirs(outdir, paths, compress=False):
    for p in paths:
        logging.info(f"Copying path {p}")
        expanded_paths = glob.glob(p)
        for ep in  expanded_paths:
            _copy_with_full_path(ep, os.path.join(outdir, "files_and_dirs"))
    logging.info("Compressing collected files and directories")
    _tar_files_and_dirs(outdir)

def find_luks_devices(outdir):
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
        _store_output(outdir, f"{cmd.replace(' ', '_').replace('-','_').replace('/', '_').replace('=', '_')}.txt", stdout, stderr)

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

def checksums(outdir, paths):
    md5s = []
    sha1s = []
    sha256s = []
    file_list = []
    for fp in paths:
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

def selinux(outdir):
    pass

