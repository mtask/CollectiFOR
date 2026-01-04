# CollectiFOR | analysis

There are multiple automatic analysis modules that do, for example, rule and pattern based analysis. Analysis modules add "findings" to collection database which was [initialized](../init/README.md) with `--init` option.
Move to [viewer](../viewer/README.md) after analysis.Note that analysis is not required to explore initialized collection database via viewer. Only thing missing before analysis are potential findings in its findings section.
  
Here's an example how to run all analysis modules:
```bash
python3 collectifor.py -c config.yaml.sample --init --analysis --collection /collections/host_20251217_141749/20251217_141749
```

> [!TIP]
> If you provide collection path to already extracted tar.gz file, the collectifor.py will automatically use the existing directory.
> Manually providing directory path (instead of tar.gz) needs to be pointed to `<path>/<hostname>_<ts>/<ts>/` -> collection files like `files_and_dirs` directory are in this path.

> [!TIP]
> collectifor.py does not directly support analysis of disk images, but you can use helper scripts to analyze disk image contents. More information [here](../workflows/disk_image_analysis.md).

Modify the config.yaml.sample file to match your needs before running the analysis. Module details are listed below, but here's a short overview of the configuration options:

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

* Below the `enable_<module>` definitions are some source file paths and other settings for analysis modules. These are explained later in this document.

```yaml
  yara: 
    rule_source: './source/yara'
    include_dirs: []
    exclude_dirs: []
  pattern: './source/pattern/'
  files: './source/files/'
``` 
    
Note that running the same analysis module twice or more times against the same collection and database will mean duplicate findings.
All analysis results are stored in "findings" table of the collection database. 

## Modules

<details>
 <summary>#YARA</summary>

YARA module enables YARA rule checks against the collection's content. 
Config file section `analysis.yara.rule_source` sets the path to YARA rules directory. Rule files should have extension `.yar`.
There are no existing rules provided currently. Configured directory can contain sub-directories, so you can hava structure like:

```
RULES_DIR
  myrules/*.yar
  rule_provider_Z/*.yar
```

You can also include or exclude paths in configuration:

```yaml
  yara: 
    rule_source: './source/yara'
    include_dirs: ['/opt']
    exclude_dirs: []
```

Note that exclude wins, so having include within path that is excluded upper level does not work.

</details>

<details>
<summary>#Pattern</summary>

Pattern module enables simple pattern rule checks against the collection's content. 
Config file section `analysis.pattern` sets the path to patternss directory. Pattern files should have extension `.txt`.
There are no existing patterns provided currently. Configured directory can contain sub-directories. Pattern files content can be anything that could be
provided to grep command as pattern file (`grep -F -f patterns.txt`). Patterns are treated as fixed strings (`grep -F`). See the next module for more complex query needs.

</details>

<details>
<summary>#Files</summary>

Files module runs analysis against the lines of specified collection's files. Module has its own YAML based rule syntax to create rules against file content.
Detection rules are written in regular expressions.
Here's an example rule to detect SSH failure in logs.

```yaml
events:
  - name: ssh_failure
    indicator: SSH authentication failure
    pattern: >
      Failed\s+(password|publickey)\s+for\s+(?P<user>\S+)
      \s+from\s+(?P<ip>\S+)
    message_template: "Failed SSH login for user {user} from {ip}"
    meta_fields: [user, ip]
    filenames:
      - /files_and_dirs/var/log/secure
      - /files_and_dirs/var/log/auth.log
      - /files_and_dirs/var/log/syslog
```

Module tries to match the regexp pattern against the lines in specified file(s) if the file path found in the collection. 
Paths in `filenames` should start with `/` from the collection's root directory. For example: `/files_and_dirs/` some file or `/file_permissions.txt`.
Module also handles log retention naming and supports wildcard patterns like this:

```yaml
events:
  ...
  - name: sudo_nopasswd_detected
    indicator: Sudoers NOPASSWD entry detected
    pattern: >
      ^(?!\#)(?P<value>\S+).*NOPASSWD
    message_template: "Sudoers file contains NOPASSWD entry for {value}"
    meta_fields: [value]
    filenames:
      - /files_and_dirs/etc/sudoers
      - /files_and_dirs/etc/sudoers.d/*
```

More samples can be found here: `analyze/source/files/`. Note that this module uses `re.VERBOSE` with its patterns, more information in [re library's docs](https://docs.python.org/3/library/re.html#re.VERBOSE).

</details>

<details>

<details>

<summary>#PCAP (PoC)</summary>

Does some simple analysis against the PCAP content if the collection has one.
Rule logic is in code and can't be extended currently without code modification.

</details>

## Helper scripts

See `helpers/README.md`.

## Query collection database

The intended way to view findings is the viewer component, but in some cases direct database queries can make sense.
You could also inject findings to it from other scripts and tools as long as you can match the `findings` table's schema.
The `meta` JSON field allows arbitrary content in JSON format.

```
CREATE TABLE findings (
	id INTEGER NOT NULL, 
	collection_name VARCHAR NOT NULL, 
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
```

Below is some sample queries to query data directly from CollectiFOR database after initialization. 
To check collection database schema:

```bash
sqlite3 collectifor.db # or the database path defined in config
> .tables
> .schema <tablename>
```

**Checksums: **

* Find filepaths matching checksum

```sql
SELECT filepath,checksum FROM checksums WHERE checksum = '99013dfc1af34a64a8ca13c29301ffe2';
```
* Find checksums matching part of the filepath

```sql
SELECT filepath,checksum FROM checksums WHERE filepath LIKE '%bin/%';
```

**Command outputs:**

* Get command output

```
SELECT output FROM command_output WHERE commandline = 'docker images';
```

**PCAP:**

* Top talkers

```sql
SELECT src, COUNT(*) FROM pcap_packets GROUP BY src ORDER BY COUNT(*) DESC;
```

* DNS queries

```sql
SELECT dns_qname, COUNT(*) FROM pcap_packets WHERE protocol='dns' GROUP BY dns_qname;
```

* Flows

```sql
SELECT src, dst, packet_count FROM network_flows ORDER BY packet_count DESC;
```

* ICMP activity

```sql
SELECT icmp_type, COUNT(*) FROM pcap_packets WHERE protocol='icmp' GROUP BY icmp_type;
```
