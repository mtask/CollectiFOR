# Helper scripts

Scripts assume that CWD is `analyze` directory.

## ingest_disk.py

Ingest checksums and file and directory paths from a mounted disk image.

```bash
python3 -m helpers.init_disk -c config.yaml -d /mnt/forensic/4Dell.E01-p1/ --checksums --files
```

Last two arguments (`--checksums --files`) define the initialization modules to enable. Data is added to a new collection that is named based on mount directory and prefixed with "DISK_". For example, `DISK_4Dell.E01-p1`.
  
You can also target only a sub-directory path within the mounted disk image with argument `--subdir / -s <path inside the disk mount>`. Provided path can be the absolute path to sub-directory or relative path from the mountpoint.
  
If the disk image was captured with CollectiFOR's `collect` tool then path to collection dir can be optionally given with `--collection <collection_dir>`. This only adds details from `info.json` to collection details.
  
## analyze_disk.py

Run analysis modules with a mounted disk image. (check disk helpers for mounting raw or E01 images)

```bash
python3 -m helpers.analyze_disk -c config.yaml -d /mnt/forensic/4Dell.E01-p1/ --pattern --yara --files
```

Last three arguments (`--pattern --yara --files`) define the analysis modules to enable. Findings are added to a new collection that is named based on mount directory and prefixed with "DISK_". For example, `DISK_4Dell.E01-p1`.

You can also target only a sub-directory path within the mounted disk image with argument `--subdir / -s <path inside the disk mount>`. Provided path can be the absolute path to sub-directory or relative path from the mountpoint.


## hasher.py 

TBD -> ingest collection findings ?

```bash
python3 -m helpers.hasher /tmp/out/20251220_000010/ /tmp/out/20251220_000040/
```

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

## Threatofx | threatfox_to_yara.py

Generate YARA rules from Threatfox's CSV exports.

Download CSV files from: https://threatfox.abuse.ch/export/
  
```
python3 -m helpers.threatfox_to_yara path/to/full.csv
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

You can also use this together with `plaso.sh` if you don't need/want to give the full disk image to plaso.

```shell
_dev_sda.E01  _dev_sda.E02  _dev_sda.E03  _dev_sda.E04  
# ./helpers/disk_e01.sh /tmp/out_disk/20251218_184907/capture/_dev_sda.E01 
Image information:
 ewfinfo 20140814

Acquiry information
[...SNIP..]
[1] Partition 1: start=2048s, sectors=fat32
[*] Enter partition numbers to mount (e.g., 1 2): 1
[+] Mounted partition 1 at /mnt/forensic/_dev_sda.E01-p1
[*] All selected partitions mounted
[*] Run './helpers/disk_e01.sh --cleanup' when finished

# helpers/plaso.sh /mnt/forensic/_dev_sda.E01-p1/ /tmp/plaso/
[+] Mounting /mnt/forensic/_dev_sda.E01-p1 -> /data
[+] Mounting /tmp/plaso -> /out
[+] Running log2timeline/plaso
root@d7396e2ea132:/out# ls -la /data/
total 2132
drwxr-x---  7 root root   16384 Jan  1  1970  .
drwxr-xr-x  1 root root    4096 Dec 18 17:20  ..
-rwxr-x---  1 root root     128 Apr  9  2021  autorun.inf
drwxr-x---  5 root root   16384 Sep 21  2021  boot
```

# Other helpful commands and examples

## Browser data

### Chrome/Chromium | Hindsight

If the collection includes chrome/chromium internet history you can use [Hindsight](https://github.com/obsidianforensics/hindsight) to analyze the data.

```
python3 venv/bin/hindsight.py -i /tmp/out/20251216_010107/files_and_dirs/home/user/snap/chromium/common/chromium/Default/ -o report/test
```

