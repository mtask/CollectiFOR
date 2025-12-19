
# Super Timelines | PLASO

>[!TIP]
> Add --hashers md5,sha1,sha256 to log2timeline.py commands to generate file hashes

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
log2timeline.py /data/files_and_dirs/var/log/
```
Without specifying `--storage_file <output>.plaso` log2timeline will generate file with name pattern `<timestamp>-log.plaso`
</details>

<details>
<summary> 3. Create JSON lines output log</summary>

```bash
psort.py -o json_line -w x.timeline.jsonl <created-timeline>.plaso
```
</details>

<details>
<summary> 4. Load JSONL to your collection</summary>

```bash
TBD
```
</details>

## Plaso -> Timeline -> YARA check

<details>
<summary> 1. Run collect and fetch the collection</summary>

```bash
./collect -c config.yaml --collect ...
```

</details>

<summary> 2. Create timeline</summary>

```bash
CASE="x"
mkdir -p /cases/$CASE/plaso
helpers/plaso.sh ../ansible_collect/fetched_collections/rl_20251217_200032/20251217_200032/ /cases/$CASE/plaso
log2timeline.py /data/files_and_dirs/var/log/
psort.py -o json_line -w x.timeline.jsonl <created-timeline>.plaso
```

</details>
