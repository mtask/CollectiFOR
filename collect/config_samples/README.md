This folder contains some sample configurations for specific collection tasks.

# Disk cloning

## DD

**Configuration:** `config.disk_dd.yaml` -\> Only disk capture module using dd is enabled.

```
$ dist/collect -c config_samples/config.disk_dd.yaml --capture --disk-host "localhost" --disk /dev/sda
2025-12-18 09:57:56,216 [INFO] [+] Running capture modules
2025-12-18 09:57:56,622 [INFO] [+] Running module disk
0:16:43 [29.5MiB/s] [                                                                                                                                                                                              <=>                      ]
2025-12-18 10:14:40,626 [INFO] Computing checksum...
2025-12-18 10:16:28,988 [INFO] Capture complete: /tmp/out_disk/20251218_095756/capture/dev_sda.img.gz
2025-12-18 10:16:28,988 [INFO] SHA256: 8c8c66d202f60e2b8ce78f8440a4a66b53836dc18dbc433aec9f597501bb27ee
```

For remote disk cloning over SSH use `--disk-host <user>@<host>`. Requires passwordless key authentication with nopasswd sudo or direct root login.

## E01

**Configuration:** `config.disk_e01.yaml` -\> Only disk capture module using E01 is enabled.

Note that E01 capture method is interacive! From the below output see prompts after the output line `Acquiry parameters required, please provide the necessary input`.

```
# dist/collect -c config_samples/config.disk_e01.yaml --capture --disk-host "localhost" --disk /dev/sda
2025-12-18 11:56:12,950 [INFO] [+] Running capture modules
2025-12-18 11:56:13,352 [INFO] [+] Running module disk
2025-12-18 11:56:13,353 [INFO] [+] Using E01 disk imaging
2025-12-18 11:56:13,353 [INFO] [*] Starting interactive E01 acquisition for device: <function disk at 0x72f2f8025bc0>
2025-12-18 11:56:13,353 [INFO] [*] Output directory: /tmp/out_disk/20251218_115612/capture
2025-12-18 11:56:13,353 [INFO] [*] Ewfacquire will prompt for target, case number, examiner, description, etc.
ewfacquire 20140814

Device information:
Bus type:				USB
Vendor:					Random
Model:					Type 3.
Serial:					1123DC50555

Storage media information:
Type:					Device
Media type:				Removable
Media size:				31 GB (31029460992 bytes)
Bytes per sector:			512

Acquiry parameters required, please provide the necessary input
Case number: 1
Description: Description
Evidence number: 1
Examiner name: Example
Notes: Some notes
Media type (fixed, removable, optical, memory) [removable]: 
Media characteristics (logical, physical) [logical]: 
Use EWF file format (ewf, smart, ftk, encase1, encase2, encase3, encase4, encase5, encase6, linen5, linen6, ewfx) [encase6]: 
Compression method (deflate) [deflate]: 
Compression level (none, empty-block, fast, best) [none]: fast
Start to acquire at offset (0 <= value <= 31029460992) [0]: 
The number of bytes to acquire (0 <= value <= 31029460992) [31029460992]: 
Evidence segment file size in bytes (1.0 MiB <= value <= 7.9 EiB) [1.4 GiB]: 
The number of bytes per sector (1 <= value <= 4294967295) [512]: 
The number of sectors to read at once (16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768) [64]: 
The number of sectors to be used as error granularity (1 <= value <= 64) [64]: 
The number of retries when a read error occurs (0 <= value <= 255) [2]: 
Wipe sectors on read error (mimic EnCase like behavior) (yes, no) [no]: 
```

# Memory acquisition

**Configuration:** `config.memory.yaml` -> Only memory capture module is enabled.

```
dist/collect --capture -c config_samples/config.memory.yaml 
```

Result after capture:

```
<ollection path>/capture/<timestamp>_<host>.lime
```

Requires [LiME](https://github.com/504ensicsLabs/LiME) kernel module.
Configure path to the module in config:

```
    memory:
      capture_method: lime
      lime:
        path: memory/lime-6.14.0-36-generic.ko # <-- Set path to LiME module here
        # Format: lime/raw
        format: lime
```

Currently "lime" is the only supported capture method.
