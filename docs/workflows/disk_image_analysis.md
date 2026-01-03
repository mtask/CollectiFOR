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

```bash
helpers/disk_e01.sh /tmp/sample/sample.E01 
```

</details>

<details>
<summary>4. Init collection from disk image</summary>

```bash
python3 -m helpers.init_disk -c config.yaml -d /mnt/forensic/sample.E01-p1/ --checksums --files
```

In case you want to target only specific sub-directory inside the mounted image use `--subdir`:

```bash
python3 -m helpers.init_disk -c config.yaml -d /mnt/forensic/4Dell.E01-p1/ --checksums --files --subdir 'sub/path'
```

</details>

<details>
<summary>4. Run analyze_disk helper script</summary>

```bash
python3 -m helpers.analyze_disk -c config.yaml -d /mnt/forensic/sample.E01-p1/ --yara --files --pattern
```

In case you want to target only specific sub-directory inside the mounted image use `--subdir`:

```bash
python3 -m helpers.analyze_disk -c config.yaml -d /mnt/forensic/sample.E01-p1/ --yara --files --patterns --subdir 'sub/path'
```

</details>

<details>
<summary>5. Run viewer to see added findings and ingested data</summary>

The helper script outputs if there wer findings added. You can then view the findings with CollectionFOR's viewer:
  
```
python3 collectifor.py -c config.yaml.sample --viewer
```
  
Open browser -\> `127.0.0.1:5000`.
</details>
