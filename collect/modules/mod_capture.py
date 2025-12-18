from scapy.all import sniff, AsyncSniffer, PcapWriter,PcapReader
import os
import logging
import time
import sys
import subprocess
import hashlib
import shutil
import signal
import tempfile
from datetime import datetime, timezone
from pathlib import Path


# ------------------------
# Network capture
# ------------------------

def _pcap_to_text(pcap):
    """
    Write captured pcap content text file for easy text based IP pattern matching etc.
    """
    out = f"{pcap}.txt"
    logging.info(f"[+] Writing capture content to text file: {out}")

    with PcapReader(pcap) as reader, open(out, "w") as f:
        for i, pkt in enumerate(reader, start=1):
            try:
                f.write(f"{i}: {pkt.summary()}\n")
            except Exception as e:
                f.write(f"{i}: <Failed to parse packet: {e}>\n")

def network(outdir, config):
    timeout = config['timeout']
    ifaces = config['interfaces']
    outdir = os.path.join(outdir, "capture")
    os.makedirs(outdir, exist_ok=True)
    outfile = os.path.join(outdir, f"{'_'.join(ifaces)}.pcap")

    logging.info(f"[+] Starting packet capture for {str(timeout)} seconds → {outfile}")
    writer = PcapWriter(outfile, append=False, sync=True)

    def handle_packet(pkt):
        writer.write(pkt)

    sniffer = AsyncSniffer(
        iface=ifaces,
        prn=handle_packet,
        store=False
    )

    sniffer.start()
    sniffer.join(timeout)
    sniffer.stop()
    writer.flush()
    writer.close()
    logging.info("[+] Capture complete.")
    _pcap_to_text(outfile)


# ------------------------
# LiME memory acquisition helpers
# ------------------------
class LiMEError(RuntimeError):
    pass


def _sha256_of_file(path, chunk_size=8 * 1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _wait_for_file_stable(path, idle_seconds=5, poll_interval=1, timeout=None):
    start = time.time()
    last_size = -1
    stable_for = 0

    while True:
        if timeout is not None and (time.time() - start) > timeout:
            raise LiMEError(f"Timeout waiting for {path} to stabilize")

        if not os.path.exists(path):
            time.sleep(poll_interval)
            continue

        size = os.path.getsize(path)
        if size == last_size:
            stable_for += poll_interval
        else:
            stable_for = 0
            last_size = size

        if stable_for >= idle_seconds:
            duration = time.time() - start
            return duration, size

        time.sleep(poll_interval)


def acquire_memory_lime(
    outdir,
    lime_path,
    lime_format="lime",
    idle_seconds=5,
    overall_timeout=3600,
    poll_interval=1,
    module_unload_timeout=30,
):
    if os.geteuid() != 0:
        raise LiMEError("Memory acquisition requires root privileges")

    os.makedirs(outdir, exist_ok=True)
    start_time = datetime.now(timezone.utc)

    timestamp = start_time.strftime("%Y%m%d_%H%M%S")
    host = os.uname().nodename
    outfile = os.path.join(outdir, f"{timestamp}_{host}.lime")

    if not os.path.isfile(lime_path):
        raise LiMEError(f"LiME kernel module not found at: {lime_path}")

    if shutil.which("insmod") is None or shutil.which("rmmod") is None:
        raise LiMEError("insmod/rmmod not found in PATH")

    module_name = 'lime'

    insmod_cmd = ["insmod", lime_path, f"path={outfile}", f"format={lime_format}"]
    logging.info("Loading LiME module with: %s", " ".join(insmod_cmd))

    try:
        result = subprocess.run(
            insmod_cmd,
            capture_output=True,
            text=True,
            shell=False,
            check=False,
        )
    except Exception as e:
        raise LiMEError(f"Failed to execute insmod: {e}")

    insmod_rc = result.returncode
    if insmod_rc != 0:
        stderr = (result.stderr or "").strip()
        raise LiMEError(f"insmod failed (rc={insmod_rc}): {stderr}")

    logging.info("insmod returned ok (rc=0). Memory extraction should be running in kernel.")
    notes = []
    rmmod_rc = None

    try:
        dur, final_size = _wait_for_file_stable(
            outfile, idle_seconds=idle_seconds, poll_interval=poll_interval, timeout=overall_timeout
        )
        logging.info("Memory file stable: %s (size=%d bytes) after %.1f s", outfile, final_size, dur)
    except KeyboardInterrupt:
        logging.warning("KeyboardInterrupt received; attempting to unload module and exit cleanly.")
        notes.append("KeyboardInterrupt during wait")
    except LiMEError as e:
        logging.warning("Error while waiting for file to stabilize: %s", e)
        notes.append(str(e))
    finally:
        logging.info("Attempting to unload LiME module '%s' via rmmod", module_name)
        try:
            r = subprocess.run(["rmmod", module_name], capture_output=True, text=True, check=False, timeout=module_unload_timeout)
            rmmod_rc = r.returncode
            if rmmod_rc != 0:
                logging.warning("rmmod returned rc=%s; stderr: %s", rmmod_rc, (r.stderr or "").strip())
                notes.append(f"rmmod returned rc={rmmod_rc}: {(r.stderr or '').strip()}")
            else:
                logging.info("rmmod succeeded (rc=0).")
        except subprocess.TimeoutExpired:
            notes.append("rmmod timed out")
            logging.error("rmmod timed out")
        except Exception as e:
            notes.append(f"rmmod exception: {e}")
            logging.exception("Exception when running rmmod")

    end_time = datetime.now(timezone.utc)
    metadata = {
        "outfile": outfile,
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "duration_seconds": (end_time - start_time).total_seconds(),
        "insmod_rc": insmod_rc,
        "rmmod_rc": rmmod_rc,
        "notes": notes,
    }

    if os.path.exists(outfile):
        try:
            size = os.path.getsize(outfile)
            metadata["size_bytes"] = size
            logging.info("Computing SHA-256 of %s...", outfile)
            sha256 = _sha256_of_file(outfile)
            metadata["sha256"] = sha256
            logging.info("SHA-256: %s", sha256)
        except Exception as e:
            metadata.setdefault("notes", []).append(f"hash_error: {e}")
            logging.exception("Failed to hash output file")
    else:
        metadata.setdefault("notes", []).append("outfile_missing")

    return metadata


# ------------------------
# Memory acquisition wrapper
# ------------------------
def memory(outdir, config):
    outdir = os.path.join(outdir, "capture")
    os.makedirs(outdir, exist_ok=True)

    if config.get('capture_method') == 'lime':
        lime_path = config['lime']['path']
        lime_format = config['lime']['format']
        if not os.path.isfile(lime_path):
            logging.error(f'Path "{lime_path}" to LiME LKM does not exist')
            sys.exit(1)
        return acquire_memory_lime(outdir, lime_path, lime_format)
    else:
        logging.error(f"Unsupported capture method: {config.get('capture_method')}")
        sys.exit(1)


# ------------------------
# disk acquisition wrapper
# ------------------------

def disk(outdir, config):
    # dd / e01
    method = config.get('capture_method', 'dd')
    if method == "dd":
        logging.info("[+] Using DD disk imaging")
        _disk_dd(outdir, config)
    elif method == "e01":
        logging.info("[+] Using E01 disk imaging")
        if config['host'] not in ("", "localhost", "127.0.0.1"):
            logging.error(f"[-] Only local capture supported with E01. Current host {config['host']} implies remote capture. Change capture method to \"dd\" in configuration")
            return
        _disk_e01(outdir, config)

def _disk_dd(outdir, config):
    """
    Capture a disk locally or remotely via sudo dd, compressed with gzip,
    with progress display and checksum verification.

    Args:
        outdir (str): Local output directory
        config (dict): Must include
            - 'disk': disk path, e.g., "/dev/sda"
            - 'host': "" / "localhost" for local capture, or "user@host" for remote

    Returns:
        Tuple[str, str]: (path_to_image_file, sha256_checksum)
    """
    import hashlib
    import logging
    import shutil
    import signal
    import subprocess
    from pathlib import Path

    # --- Verify dependencies ---
    for cmd in ["pv", "gzip", "dd"]:
        if shutil.which(cmd) is None:
            raise RuntimeError(f"The '{cmd}' command is required but not found.")

    outdir = Path(outdir) / "capture"
    outdir.mkdir(parents=True, exist_ok=True)

    device = config["disk"]
    host = config.get("host", "")
    filename = device.strip("/").replace("/", "_") + ".img.gz"
    outfile = outdir / filename
    checksum_file = outdir / (filename + ".sha256")

    bs = 64 * 1024

    dd_cmd = [
        "dd",
        f"if={device}",
        f"bs={bs}",
        "conv=noerror,sync"
    ]

    gzip_cmd = ["gzip", "-1", "-"]
    pv_cmd = ["pv", "-p", "-t", "-e", "-r"]

    processes = []

    # --- Local vs Remote ---
    if host in ("", "localhost", "127.0.0.1"):
        # Local: dd | gzip | pv > file
        dd_proc = subprocess.Popen(
            dd_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        processes.append(dd_proc)

        gzip_proc = subprocess.Popen(
            gzip_cmd,
            stdin=dd_proc.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        dd_proc.stdout.close()
        processes.append(gzip_proc)

        pv_stdin = gzip_proc.stdout

    else:
        # Remote: ssh "dd | gzip" | pv > file
        test = subprocess.run(
            ["ssh", host, "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if test.returncode != 0:
            raise RuntimeError(f"SSH authentication failed for {host}")

        remote_cmd = f"sudo {' '.join(dd_cmd)} | gzip -1 -"
        ssh_cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            host,
            remote_cmd
        ]

        logging.info(f"Running SSH: {' '.join(ssh_cmd)}")

        dd_proc = subprocess.Popen(
            ssh_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        processes.append(dd_proc)

        pv_stdin = dd_proc.stdout

    # --- Write to file with pv ---
    with open(outfile, "wb") as f:
        pv_proc = subprocess.Popen(
            pv_cmd,
            stdin=pv_stdin,
            stdout=f,
            stderr=None  # pv progress to terminal
        )
        processes.append(pv_proc)

        # Cancel-safe handling
        def signal_handler(sig, frame):
            logging.info("\nCancelling...")
            for p in processes:
                p.terminate()

        signal.signal(signal.SIGINT, signal_handler)

        pv_proc.wait()

    # Ensure all processes exit
    for p in processes:
        p.wait()

    # --- Compute checksum ---
    logging.info("Computing checksum...")
    sha256 = hashlib.sha256()
    with open(outfile, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha256.update(chunk)
    checksum = sha256.hexdigest()

    with open(checksum_file, "w") as f:
        f.write(checksum + "\n")

    logging.info(f"Capture complete: {outfile}")
    logging.info(f"SHA256: {checksum}")

    return str(outfile), checksum

def _disk_e01(outdir, config):
    """
    Capture a local disk to E01 using old ewfacquire (2014-era),
    interactively prompting for metadata.

    Args:
        outdir (str): Base output directory
        disk (str): Block device to capture (e.g., "/dev/sda")

    Returns:
        str: Path to first E01 segment (based on target filename entered in prompt)
    """
    if shutil.which("ewfacquire") is None:
        raise RuntimeError("ewfacquire not found")

    outdir = Path(outdir) / "capture"
    outdir.mkdir(parents=True, exist_ok=True)
    device = config['disk']
    filename = device.strip("/").replace("/", "_")
    outfile = outdir / filename
    logging.info(f"[*] Starting interactive E01 acquisition for device: {device}")
    logging.info(f"[*] Output directory: {outdir}")
    logging.info("[*] Ewfacquire will prompt for case number, examiner, description, etc.")

    # --- Run ewfacquire interactively ---
    cmd = ["ewfacquire", "-t" , outfile, device]
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=None,   # attach to terminal so user can input
            stdout=None,
            stderr=None
        )
        proc.wait()
    except KeyboardInterrupt:
        logging.warning("[!] Capture interrupted by user")
        proc.terminate()
        raise

    logging.info("[+] E01 acquisition complete. Check the capture directory for .E01/.E02 files.")
    return str(outdir)
