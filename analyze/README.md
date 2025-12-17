## Usage

`analyze.py` analyses collected data for anomalies and IoCs.

```bash
python analyze.py --config config.yaml --collection-path /tmp/out/<collection>.tar.gz --pattern --yara --analysis
```

**Options:**
- `--collection-path`: Path to the collected tar.gz. (required)
- `--pattern`: Enable IoC pattern matching. (optional)
- `--yara`: Enable YARA scanning. (optional)
- `--analysis`: Enable other analysis modules against `files_and_dirs` content in the collection. (optional)

**YAML configuration:**

See `./config.yaml`.

**Analysis Output:**
- HTML report with sections for:
  - YARA results
  - Pattern matches
  - PCAP analysis
  - File permissions issues
  - Logs anomalies

Other than YARA and pattern matching, which rely on external data sources, other modules are more like a PoC features.
YARA and pattern modules basically are as good as your rule and pattern sources.

## Modules

### Patterns and YARA modules

* Load your patterns to text files containing things like IoCs under `patterns` directory. Files should have `.txt` extension.
* Load your YARA rules under `yara` directory. Files should have `.yar` extension.

Both directories can have sub-directories. Files (`.yar`/`.txt`) are searched recursively under those directories if related modules are enabled.

Directory paths for patterns and rules can be changed in `config.yaml`:

```
modules:
  pattern:
    # Pattern txt files are here. One pattern per line
    # Can contain sub directories
    # Expects .txt extension
    patterns_dir: ./patterns
  yara:
    # Yara yar files are here
    # Can contain sub directories
    # Expects .yar extension
    rules_dir: ./yara
```

Enable YARA module by giving `--yara` option and patterns module by giving `--pattern` option.

### Other analysis

Other analysis is enabled by giving `--analysis` option. As mentioned these are mainly sort of PoC modules.

You can use tools like plaso to do further analysis against the collection. Or Zeek to do further network analysis against the captured PCAP. The repository contains the following helper scripts:

* **plaso.sh**: run `log2timeline/plaso` docker image and mount collection inside. Spawns inside the container to run Plaso tools.

```
sudo ./plaso.sh <path to collection dir or tar.gz> <path to output dir>
```

The script specifies `--user 0` for docker run commands to ensure proper file access with the collection data. The collection data is mounted as read-only inside the container. The output directory is created if it does not exist. 
If the capture includes disk image, and you want create super timeline from it, then it needs to be extracted (gunzip) outside the contaider due to read-only mounting.

When the container's bash prompt opens you can run `log2timeline.py` etc.:

```
root@bb0a5da10423:/out# log2timeline.py /data/files_and_dirs
# Example to get some browser usage data if included in collection
root@bb0a5da10423:/out# psort.py --analysis unique_domains_visited -o null <database name>.plaso
root@bb0a5da10423:/out# psort.py --analysis browser_search -o null <database name>.plaso
```

* **zeek.sh**: Run zeek inside docker container. Requires zeek/zeek docker image.

```
sudo ./zeek.sh <path to collection dir or tar.gz> <path to output dir>
```

The script assumes that there is the usual one pcap under `<collection>/capture/`. This requires that the collection was executed with `--capture` and had network module enabled.

* **hindsight**:

Chrome/Chromium internet history forensics with [Hindsight](https://github.com/obsidianforensics/hindsight)

```
python3 venv/bin/hindsight.py -i /tmp/out/20251216_010107/files_and_dirs/home/user/snap/chromium/common/chromium/Default/ -o report/test
```

## TBD

### Top talkers

```sql
SELECT src, COUNT(*) FROM pcap_packets GROUP BY src ORDER BY COUNT(*) DESC;
```

### DNS queries

```sql
SELECT dns_qname, COUNT(*) FROM pcap_packets WHERE protocol='dns' GROUP BY dns_qname;
```

### Flows

```sql
SELECT src, dst, packet_count FROM network_flows ORDER BY packet_count DESC;
```

### ICMP activity

```sql
SELECT icmp_type, COUNT(*) FROM pcap_packets WHERE protocol='icmp' GROUP BY icmp_type;
```

## Reporting

TBD
