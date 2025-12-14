# PyTriage | DFIR Triage Tool

A Python-based digital forensics and incident response (DFIR) triage tool to collect and analyze system and network artifacts from Linux based target machines.
Supports file collection, memory acquisition, network capture, checksum calculation, and analysis of indicators of compromise.

---

## Features

**Collect Mode (`collect/collect.py`):**
- File and directory collection
- File permission and checksum inventory
- Network capture (PCAP) using Scapy
- Memory acquisition via LiME (Linux Memory Extractor)
- Command output capture (system commands for triage)

**Analyze Mode (`analyze/analyze.py`):**
- Pattern matching against patterns/IoCs
- YARA rule scanning
- File permission risk analysis (SUID, SGID, world-writable)
- PCAP analysis for:
  - DNS anomalies (high-entropy domains)
  - Beaconing detection (periodic connections)
  - Unusual port usage
- Logs analysis (auth failures, sudo failures, desktop/tty logins)
- Filesystem integrity checks (checksums, SUID binaries, unexpected permissions)

---

## Requirements

- Collection: `collect/requirements.txt`
- Analysis/Scan: `analyze/requirements.txt`
- Optional (for memory acquisition):
  - LiME kernel module

---

## Usage

### Collect Mode

- See [collect/README.md](https://github.com/mtask/PyTriage/tree/main/collect/README.md)

- **Remote collection:** see [ansible-collect](https://github.com/mtask/PyTriage/tree/main/ansible_collect).

---

### Analyze Mode


- See [analyze/README.md](https://github.com/mtask/PyTriage/tree/main/analyze/README.md)

---
