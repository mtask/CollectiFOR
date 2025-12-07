from scapy.all import sniff, PcapWriter
import os
import logging
import socket
import time
import sys
import subprocess
import hashlib
import shutil
from datetime import datetime, timezone


# ------------------------
# Network capture
# ------------------------
def network_interfaces(outdir, timeout, ifaces):
    outdir = os.path.join(outdir, "capture")
    os.makedirs(outdir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = socket.gethostname()
    outfile = os.path.join(outdir, f"{timestamp}_{hostname}.pcap")

    logging.info(f"[+] Starting packet capture → {outfile}")

    writer = PcapWriter(outfile, append=False, sync=True)
    end_time = time.time() + timeout

    def handle_packet(pkt):
        writer.write(pkt)

    try:
        while time.time() < end_time:
            sniff(iface=ifaces, timeout=1, prn=handle_packet, store=False)

    except KeyboardInterrupt:
        logging.info("[!] Ctrl+C detected — stopping capture early")

    finally:
        writer.flush()
        writer.close()
        logging.info("[+] Capture complete.")

    return outfile


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

    module_name = os.path.splitext(os.path.basename(lime_path))[0]

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
