# Analysis modules

There are multiple automatica analysis modules which allow, for example, rule and pattern based analysis. Here's an example how to run all analysis modules:
  
```bash
python3 collectifor.py -c config.yaml.sample --init --analysis --collection /collections/host_20251217_141749/20251217_141749
```
  
> [!TIP]
> If you provide collection path to already extracted tar.gz file, the collectifor.py will automatically use the existing directory.
> Manually providing directory path (instead of tar.gz) needs to be pointed to `<path>/<hostname>_<ts>/<ts>/` -> collection files like `files_and_dirs` directory are in this path.
  
Before running the analysis modify config.yaml.sample to your needs. Module details are listed below, but here's a short overview of the configuration options:

* Database paths are defined at top-level. These should be the same as during the `--init` run.

```yaml
collection_database: './collectifor.db'
timeline_database: './timeline.duckdb'
```
* Enabled/disabled analysis modules are defined under `analysis` key.

```yaml
analysis:
  enable_yara: true
  enable_pattern: true
  enable_files: true
  enable_file_permissions: true
  enable_pcap: true
```

* Below the `enable_<module>` definitions are some source file paths for a few modules. These are explained later in this document.

```yaml
  yara: './source/yara'
  pattern: './source/pattern/'
  files: './source/files/'
``` 
    
Note that running same analysis module twice or more times against the same collection and database will mean duplicate findings.

In CollectiFOR database all analysis results are stored in "findings" table. Modules marked as `alpha / PoC` in the below listing are mostly in PoC concept state and have very simplistic analysis.
YARA and Pattern modules use existing source content (YARA rules, IoC listings, etc), so those do not have similar own analysis logic and should yield good results with good rule/pattern sources.

You can skipp all the PoC analysis modules like this if you still want to run YARA and/or PATTERN analysis.

# Modules

Do not use `--analysis` option if you want to run individual modules only.

<details>
 <summary># YARA</summary>

* Enable: `--yara RULES_DIR`

RULES_DIR contains YARA rule files with extension `.yar`. Can contain sub-directories, so you can hava structure like:

```
RULES_DIR
  myrules/*.yar
  rule_provider_Z/*.yar
```
</details>

<details>
<summary>Pattern</summary>

* Enable: `--pattern PATTERN_DIR`

Files in PATTERN_DIR are passed to `grep` as pattern file which means that there should be one "greppable" pattern per line in each file.
Can also contain sub-directories.
</details>

## Module | File permissions (alpha / PoC)

* Enable: `--file-permissions`

Does some simple analysis against the `file_permissions.txt` content if the collection has one.

## Module | Files (alpha / PoC)

* Enable: `--files`

Does some simple analysis against the `files_and_dirs` file contents if included in the collection.

## Module | PCAP (alpha / PoC)

* Enable: `--pcap`

Does some simple analysis against the PCAP content if the collection has one.

# Other analysis

There's no reason to user other tools with the collection for additional analysis. You can use tools like plaso to do further analysis against the collection. Or Zeek to do further network analysis against the captured PCAP. The repository contains the following helper scripts:
There are some helper scripts included in the repository and some sample commands and queries in this README.

## Grep patterns

CollectiFOR's pattern parser is basically just a wrapper for grep. You can do similar quick pattern matching just by running grep like this.

```bash
grep -r -f patterns/custom/test.txt /collections/host_20251217_141749/20251217_141749/
# OR with all pattern files
find patterns/ -name "*.txt" -exec grep -rf {} /collections/host_20251217_141749/20251217_141749/ \;
```

## Helper scripts

See `helpers/README.md`.

## Query CollectiFOR database

Here is some sample queries to query data directly from CollectiFOR database after initialization.

## Checksums

### Find filepaths matching checksum

```sql
SELECT filepath,checksum FROM checksums WHERE checksum = '99013dfc1af34a64a8ca13c29301ffe2';
```
### Find checksums matching part of the filepath

```sql
SELECT filepath,checksum FROM checksums WHERE filepath LIKE '%bin/%';
```

## Commands

### Get command output

```
SELECT output FROM command_output WHERE commandline = 'docker images';
```

## network

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

# Database structure

Here is the current CollectiFOR database structure.

## Tables

```
sqlite> .tables
checksums         file_permissions  findings          pcap_packets    
command_output    files_and_dirs    network_flows
```

All analysis results are inserted to findings table. Other tables are used by initialization (`--init`) parsers.

## Table schemas

```sql
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
