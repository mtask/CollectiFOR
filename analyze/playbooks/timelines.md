
## Plaso - JSON

<details>
<summary> 1. Run collect and fetch the collection

```bash
./collect -c config.yaml --collect ...
```
</summary>
</details>

<details>
<summary> 2. Use log2timeline to generate timeline

```bash
CASE="x"
mkdir -p /cases/$CASE/plaso
helpers/plaso.sh ../ansible_collect/fetched_collections/rl_20251217_200032/20251217_200032/ /cases/$CASE/plaso
log2timeline.py /data/files_and_dirs/var/log/
```
Without specifying `--storage_file <output>.plaso` log2timeline will generate file with name pattern `<timestamp>-log.plaso`
</summary>
</details>

<details>
<summary> 3. Create JSON lines output log
```bash
psort.py -o json_line -w x.timeline.jsonl <created-timeline>.plaso
```
</summary>
</details>

## Plaso - YARA

<details>
<summary> 1. Run collect and fetch the collection

```bash
./collect -c config.yaml --collect ...
```
</summary>
</details>

<summary> 2. Create timeline

```bash
CASE="x"
mkdir -p /cases/$CASE/plaso
helpers/plaso.sh ../ansible_collect/fetched_collections/rl_20251217_200032/20251217_200032/ /cases/$CASE/plaso
log2timeline.py /data/files_and_dirs/var/log/
psort.py -o json_line -w x.timeline.jsonl <created-timeline>.plaso
```
</summary>
</details>
