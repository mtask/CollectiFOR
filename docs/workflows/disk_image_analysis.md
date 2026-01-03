## Run analysis modules against mounted disk image

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
<summary>3. Run analyze_disk helper script</summary>

```bash
python3 -m helpers.analyze_disk -c config.yaml -d /mnt/forensic/sample.E01-p1/
```

</details>
