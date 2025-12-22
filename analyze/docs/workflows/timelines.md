
# Super Timelines | PLASO

These examples use a script from [helpers dict](../../helpers/README.md).

## Plaso -> JSONL -> Explore

<details>
<summary> 1. Run collect and fetch the collection</summary>

```bash
./collect -c config.yaml --collect ...
```
</details>

<details>
<summary> 2. Use log2timeline to generate timeline</summary>

```bash
read -p "Case: " CASE
mkdir -p /cases/$CASE/plaso
helpers/plaso.sh ../ansible_collect/fetched_collections/rl_20251217_200032/20251217_200032/ /cases/$CASE/plaso
# drops you in docker container with Plaso tools
log2timeline.py /data/files_and_dirs/var/log/
```
Without specifying `--storage_file <output>.plaso` log2timeline will generate file with name pattern `<timestamp>-log.plaso`
</details>

<details>
<summary> 3. Create JSON lines output log</summary>

```bash
psort.py -o json_line -w x.timeline.jsonl <created-timeline>.plaso
# exit from the container
exit
```
</details>

<details>
<summary> 4. Load JSONL to CollectiFOR</summary>

```bash
python3 collectifor.py -c config.yaml.sample -tf x.timeline.jsonl
```
</details>

<details>
<summary> 5. Analyze data in CollectiFOR Viewer</summary>

```bash
python3 collectifor.py -c config.yaml.sample --viewer
```

* Open 127.0.0.1:5000 in browser.

</details>

## Plaso -> Timeline -> YARA check

<details>
<summary> 1. Run collect and fetch the collection</summary>

```bash
./collect -c config.yaml --collect ...
```

</details>

<details>
<summary> 2. Create timeline</summary>

```bash
CASE="x"
mkdir -p /cases/$CASE/plaso
helpers/plaso.sh ../ansible_collect/fetched_collections/rl_20251217_200032/20251217_200032/ /cases/$CASE/plaso
log2timeline.py /data/files_and_dirs/var/log/
psort.py -o json_line -w x.timeline.jsonl <created-timeline>.plaso
```

</details>


## Query timeline | DuckDB


<details>
<summary># Query by filehash and save results to CSV</summary>

* SHA256 hash only:

```sql
COPY (
    SELECT DISTINCT
        json_extract_string(extra, '$.sha256_hash') AS sha256_hash
    FROM timeline_events
    WHERE json_extract_string(extra, '$.sha256_hash') IS NOT NULL
) TO 'hashes.csv' (FORMAT CSV, HEADER, QUOTE '');
```

Results -\> `hashes.csv`

* Filename and SHA256 hash:

```sql
COPY (
    SELECT sha256_hash, filename
    FROM (
        SELECT
            TRIM(BOTH '"' FROM extra['sha256_hash']::VARCHAR) AS sha256_hash,
            TRIM(BOTH '"' FROM extra['filename']::VARCHAR) AS filename,
            ROW_NUMBER() OVER (PARTITION BY extra['sha256_hash'] ORDER BY extra['filename']) AS rn
        FROM timeline_events
        WHERE extra['sha256_hash'] IS NOT NULL
    ) t
    WHERE rn = 1
) TO 'hashes.csv' (FORMAT CSV, HEADER, QUOTE '');
```

Results -\> `hashes.csv`

</details>
