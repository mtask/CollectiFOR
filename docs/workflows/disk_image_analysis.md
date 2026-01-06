## Run analysis modules against mounted disk image

This workflow uses provided [helper scripts](../../analyze/helpers/README.md).

<details>
<summary>1. Navigate to analyze directory</summary>

```bash
cd <path>/CollectiFOR/analyze/
```

</details>

<details>
<summary>2. Mount disk image</summary>

* E01

```bash
helpers/disk_e01.sh /tmp/sample/sample.E01 
```

* RAW (DD)

```bash
helpers/disk_e01.sh /tmp/sample/sample.img
```

If RAW disk image is gzip compressed the helper disk automatically extracts the image when the file extension is `.gz`.
If the disk was capture with CollectiFOR's `collect` tool then you can use `extract_collection.sh` to extract collection first.

```bash
helpers/extract_collection.sh /srv/rl_20251225_194124.tar.gz
helpers/disk_dd.sh /srv/rl_20251225_194124/20251225_194124/capture/<image>.gz
# OR
helpers/disk_dd.sh /srv/rl_20251225_194124/20251225_194124/capture/<image>.E01
```

</details>

<details>
<summary>4. Init collection from disk image and run analysis</summary>

```bash
python3 -m helpers.init_disk -c config.yaml -d /mnt/forensic/dev_vda.img-p1/  --all
```

In case you want to target only specific sub-directory inside the mounted image use `--subdir`:

```bash
python3 -m helpers.init_disk -c config.yaml -d /mnt/forensic/4Dell.E01-p1/ --all --subdir 'sub/path'
```
</details>

Prompts to create a new collection or select an existing one. Prompts optionally to select an existing case or create a new case to add findings to. If no case is selected then findings are not initially associated with any case.

<details>
<summary>5. Run viewer to see added findings and ingested data</summary>

The helper script outputs if there wer findings added. You can then view the findings with CollectionFOR's viewer:
  
```
python3 collectifor.py -c config.yaml.sample --viewer
```
  
Open browser -\> `127.0.0.1:5000`.
</details>
