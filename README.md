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

`collect.py` gathers system artifacts, memory, and network captures.

```bash
python collect.py --config config.yaml --collect --capture --interfaces eth0,wlan0
```

**Options:**
- `--config`: Path to YAML configuration file.
- `--capture`: Enable network and/or memory capture (can be configured in config file)
- `--interfaces`: Comma-separated list of interfaces for packet capture.

**YAML configuration:**

Check `collect/config.yaml`.

**Example Output Directory Structure:**

```
/tmp/out/<timestamp>/
├── capture/
│   ├── eth0.pcap
│   └── eth0.pcap.txt
├── checksums/
│   ├── md5.txt
│   ├── sha1.txt
│   └── sha256.txt
├── commands/
│   ├── stdout.ps.txt
│   └── stdout.ls.txt
├── file_permissions.txt
└── files_and_dirs/
```

---

### Analyze Mode

`analyze.py` analyzes collected data for anomalies and IoCs.

```bash
python analyze.py --config config.yaml --collection-path /tmp/out/<collection>.tar.gz --pattern --yara --analysis
```

**YAML configuration:**

Check `analyze/config.yaml`.

**Options:**
- `--collection-path`: Path to the collected data directory. (required)
- `--pattern`: Enable IoC pattern matching. (optional)
- `--yara`: Enable YARA scanning. (optional)
- `--analysis`: Enable other analysis modules against `files_and_dirs` content in the collection. (optional)

**Analysis Output:**
- HTML report with sections for:
  - YARA results
  - Pattern matches
  - PCAP analysis
  - File permissions issues
  - Logs anomalies

---
