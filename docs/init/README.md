# CollectiFOR | init

After collection database initialization (data ingestion)  move to [analysis](../analysis/README.md) or to [viewer](../viewer/README.md) if you just want to explore the ingested data via UI.

> [!IMPORTANT]
> Do not remove your extracted collection if you want to run automatic analysis against it. Some viewer funcationalities (File Navigator) will also not fully work without access the original collection.
> If you do not need access to files via viewer's file navigator then it's safe to remove or move the original extracted path (after analysis if used).

## Collections

Collection ingestion is launched with the `--init` option. In addition you need to provide path to collection directory or tar.gz file with `--collection <path>` and path to configuration file with `-c <config>.yaml`.
Modify the provided `config.yaml.sample` if needed. The `analysis` section in the configuration file does not matter in this phase. Only the database location(s) matter.

```
sudo python3 collectifor.py -c config.yaml.sample --init --collection /collections/host_20251217_141749.tar.gz 
```

You can combine `--init` with other phases like seen [here](../README.md), but this page focuses on the initialization phase.
Initialization creates an SQLite3 database to path defined in config -> `collection_database`.

Below table shows which data is currently ingested to CollectiFOR database in initialization.


| Collection           | Parser             | DB table         |
|----------------------|--------------------|------------------|
| commands/            | CommandsParser     | command_output   |
| checksums/           | ChecksumParser     | checksums        |
| files_and_dirs/      | FilesAndDirsParser | files_and_dirs   |
| capture/*.pcap       | PcapParser         | pcap_packets     |
| capture/*.pcap       | PcapParser         | network_flows    |
| file_permissions.txt | PermissionsParser  | file_permissions |
| listeners.json       | ListenersParser    | listeners        |

All parsers skip ingestion gracefully if the related collection data is not found because not all collections include content from every collect module.
  
You can ingest multiple collections to sama database, but only one collection per run. In the [viewer](../viewer/README.md) component you can explore all the collections at once or select a single collection.
Which collections should be in the same database depends on needs. Note that `--init` does not do deduplication. If the same collection is ingested again it will create lots of duplicate rows which.
In accidental double ingestion it might be easiest to remove the database file and re-init. If only one collection needds to be removed from multi-collection database, that can't be removed, then some manual SQL work is needed.

```bash
sqlite3 collectifor.db 
# Check collection names
select collection_name from collections;
# Delete collection data from tables
DELETE FROM command_output WHERE collection_name = 'something';
DELETE FROM <tablename2> WHERE collection_name = '<ccllection>';
# etc.
```

## Timelines

CollectiFOR can also ingest super timelines created with Plaso tools. The [viewer](../viewer/README.md) component has some basic timeline explorer, query and chart tools.
CollectiFOR supports only JSON lines format (`psort.py -o json_line`).
  
```bash
python3 collectifor.py -c config.yaml.sample -tf /path/to/case.x.timeline.jsonl
```
  
This generates a DuckDB database to path defined in config -> `timeline_database`.
Option `-tf <timeline>.jsonl` can also be run at the same time with other `collectifor.py`'s options (`--init`, `--analysis`, etc.).
Here is some examples of how to generate timelines: [timelines.md](../workflows/timelines.md).
