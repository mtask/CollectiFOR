# Helper scripts

## Plaso | plaso.sh

Runs `log2timeline/plaso` docker image and mounts the collection inside. Spawns inside the container to run Plaso tools.

```
sudo ./plaso.sh <path to collection dir or tar.gz> <path to output dir>
```

The script specifies `--user 0` for docker run commands to ensure proper file access with the collection data. The collection data is mounted as read-only inside the container. The output directory is created if it does not exist.
If the capture includes disk image, and you want create super timeline from it, then it needs to be extracted (gunzip) outside the contaider due to read-only mounting.

When the container's bash prompt opens you can run `log2timeline.py` etc.:


```bash
# helpers/plaso.sh /tmp/out/host_20251218_092648.tar.gz /tmp/plaso
Extracting collection...
Collection extracted -> /tmp/out/host_20251218_092648
[+] Mounting /tmp/out/host_20251218_092648 -> /data
[+] Mounting /tmp/plaso -> /out
[+] Running log2timeline/plaso
root@ee4c81067f78:/out# ls /data/
20251218_092648
root@ee4c81067f78:/out# ls /data/20251218_092648/
capture  checksums  commands  file_permissions.txt  files_and_dirs  listeners.json
```

## Zeek | zeek.sh

Runs zeek/zeek docker container and runs analysis with the collecntion's PCAP file.

```
sudo ./zeek.sh <path to collection dir or tar.gz> <path to output dir>
```

The script assumes that there is the usual one pcap under `<collection>/capture/`. This requires that the collection was executed with `--capture -if <interfaces>` and had the network module enabled.


## Disk image mounting (RAW) | disk_dd.sh

```bash
# helpers/disk_dd.sh 
Usage:
  helpers/disk_dd.sh <disk_image>
  helpers/disk_dd.sh --cleanup

Features:
  - Extracts .gz images automatically
  - Detects partitions
  - Mounts selected partitions read-only
  - Cleanup option unmounts everything safely

Examples:
  sudo helpers/disk_dd.sh evidence.img
  sudo helpers/disk_dd.sh evidence.img.gz
  sudo helpers/disk_dd.sh --cleanup
```

## Disk image mounting (RAW) | disk_dd.sh

```
# helpers/disk_e01.sh 
Usage:
  disk_e01.sh <E01_image>
  disk_e01.sh --cleanup

Features:
  - Works with E01 images
  - Uses ewfmount to expose raw disk
  - Detects partitions using parted
  - Mounts selected partition(s) read-only
  - Tracks mounts for easy cleanup
```

# Other helpful commands and examples

## Browser data

### Chrome/Chromium | Hindsight

If the collection includes chrome/chromium internet history you can use [Hindsight](https://github.com/obsidianforensics/hindsight) to analyze the data.

```
python3 venv/bin/hindsight.py -i /tmp/out/20251216_010107/files_and_dirs/home/user/snap/chromium/common/chromium/Default/ -o report/test
```

