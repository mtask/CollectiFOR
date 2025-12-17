## Usage

```
usage: collectifor.py [-h] [-d DB] [-v] [-y RULE_DIR] [-p PATTERN_DIR] [-l] [-fp] [-pe] [-pc] [--init] [--analysis] [--viewer] collection

Parse forensic collection and store results in SQLite DB

positional arguments:
  collection            Path to collection directory or .tar.gz archive

options:
  -h, --help            show this help message and exit
  -d DB, --db DB        SQLite database file (default: collectifor.db)
  -v, --verbose         Enable verbose logging
  -y RULE_DIR, --yara RULE_DIR
                        Enable yara analysis module by providing path to your yara rules top-level directory.
  -p PATTERN_DIR, --pattern PATTERN_DIR
                        Enable pattern analysis module by providing path your pattern files top-level directory.
  -l, --logs            Enable logs analysis module
  -fp, --file-permissions
                        Enable file permissions analysis module
  -pe, --persistence    Enable persistence analysis module
  -pc, --pcap           Enable PCAP analysis module
  --init                Initialize collection (Run only once against same collection)
  --analysis            Enable and run all analysis modules. Yara module requires --yara RULE_DIR and pattern module --pattern PATTERN_DIR
  --viewer              Launch local analysis viewer
```

### Initialization, analysis and viewer

All the analysis and viewing related functionalities are launched with the `collectifor.py` script. Here's all-in-one example command to run everything with a frest collection tar.gz.

```bash
# Might require sudo/root depending on your collection's permissions
python3 collectifor.py --init --analysis --yara yara/ --pattern patterns/ --viewer /collections/host_20251217_141749.tar.gz 
```

**Arguments**:

* `--init`: -> Initialize collection SQLite database. Default path is `./collectifor.db`
* `--analysis` -> Run analysis modules
* `--yara yara/` -> YARA rules directory for the analysis
* `--pattern patterns/` -> Pattern files directory for the analysis
* `--viewer` -> Launch collectiFOR viewer after initialization and analysis (Listens -> 127.0.0.1:5000)
* `/collections/host_20251217_141749.tar.gz` -> Path to collection. Can be collection tar.gz or collection directory if already decompressed.



To initialize without:

* YARA rules -> remove `--yara DIR` from the command.
* Pattern match -> remove `--pattern DIR` from the command.
* any analysis -> remove `--yara DIR`, `--pattern DIR` and `--analysis` from the command.
* launching the viewer --> remove `--viewere`

## Collection-Parser-Database mapping

This shows which data is currently add to CollectiFOR database in initialization.


| Collection           | Parser             | DB table         |
|----------------------|--------------------|------------------|
| commands/            | CommandsParser     | command_output   |
| checksums/           | ChecksumParser     | checksums        |
| files_and_dirs/      | FilesAndDirsParser | files_and_dirs   |
| capture/*.pcap       | PcapParser         | pcap_packets     |
| capture/*.pcap       | PcapParser         | network_flows    |
| file_permissions.txt | PermissionsParser  | file_permissions |
| listeners.json       | N/A                | N/A              |


## Other analysis


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

## Database structure

Here is the current CollectiFOR database structure.

### Tables

```
sqlite> .tables
checksums         file_permissions  findings          pcap_packets    
command_output    files_and_dirs    network_flows
```

All analysis results goes to findings table. Other tables are used by initialization (`--init`) parsers.

### Tables' schemas

```
sqlite> .schema checksums
CREATE TABLE checksums (
	id INTEGER NOT NULL, 
	filepath TEXT NOT NULL, 
	checksum VARCHAR NOT NULL, 
	algorithm VARCHAR NOT NULL, 
	inserted_at DATETIME, 
	PRIMARY KEY (id)
);
sqlite> .schema file_permissions
CREATE TABLE file_permissions (
	id INTEGER NOT NULL, 
	filepath TEXT NOT NULL, 
	mode VARCHAR NOT NULL, 
	perm_string VARCHAR NOT NULL, 
	owner VARCHAR NOT NULL, 
	"group" VARCHAR NOT NULL, 
	size INTEGER NOT NULL, 
	timestamp DATETIME NOT NULL, 
	inserted_at DATETIME, 
	PRIMARY KEY (id)
);
sqlite> .schema findings
CREATE TABLE findings (
	id INTEGER NOT NULL, 
	type VARCHAR NOT NULL, 
	message VARCHAR NOT NULL, 
	rule VARCHAR, 
	source_file VARCHAR, 
	tags VARCHAR, 
	meta JSON, 
	namespace VARCHAR, 
	artifact VARCHAR, 
	indicator VARCHAR, 
	inserted_at DATETIME, 
	PRIMARY KEY (id)
);
sqlite> .schema pcap_packets
CREATE TABLE pcap_packets (
	id INTEGER NOT NULL, 
	interface VARCHAR NOT NULL, 
	packet_number INTEGER NOT NULL, 
	timestamp DATETIME NOT NULL, 
	protocol VARCHAR NOT NULL, 
	src VARCHAR, 
	src_port INTEGER, 
	dst VARCHAR, 
	dst_port INTEGER, 
	icmp_type INTEGER, 
	icmp_code INTEGER, 
	dns_qname VARCHAR, 
	dns_qtype VARCHAR, 
	raw_content TEXT, 
	inserted_at DATETIME, 
	PRIMARY KEY (id)
);
sqlite> .schema command_output
CREATE TABLE command_output (
	id INTEGER NOT NULL, 
	category VARCHAR NOT NULL, 
	commandline TEXT NOT NULL, 
	output TEXT NOT NULL, 
	inserted_at DATETIME, 
	PRIMARY KEY (id)
);
sqlite> .schema files_and_dirs
CREATE TABLE files_and_dirs (
	id INTEGER NOT NULL, 
	collection_path VARCHAR NOT NULL, 
	path VARCHAR NOT NULL, 
	type VARCHAR NOT NULL, 
	inserted_at DATETIME, 
	PRIMARY KEY (id)
);
sqlite> .schema network_flows
CREATE TABLE network_flows (
	id INTEGER NOT NULL, 
	protocol VARCHAR NOT NULL, 
	src VARCHAR NOT NULL, 
	src_port INTEGER, 
	dst VARCHAR NOT NULL, 
	dst_port INTEGER, 
	first_seen DATETIME NOT NULL, 
	last_seen DATETIME NOT NULL, 
	packet_count INTEGER, 
	inserted_at DATETIME, 
	PRIMARY KEY (id)
);
```

## Sample DB queries

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
