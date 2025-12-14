## Building and using collect.py

```bash
pip3 install pyinstaller
pyinstaller --onefile --paths=. collect.py
```

After building ship `./dist/collect` and `config.yaml` to target machine and run collection.

```bash
sudo ./collect -c config.yaml --collect --capture -if eth0,eth1
```

**Options:**
- `--config`: Path to YAML configuration file.
- `--capture`: Enable network and/or memory capture (can be configured in config file)
- `--interfaces`: Comma-separated list of interfaces for packet capture.

Check the collection path from the last log message to stdout. For example:

```
2025-12-07 22:04:07,548 [INFO] Collection finished: /tmp/out/hostname_20251207_220252.tar.gz
```

If `compress_collection` is set to `false` in config.yaml then the collection's result path is directory instead of tar.gz file.

Copy collection to analysis machine and continue with [analysis](https://github.com/mtask/PyTriage/tree/main/analyze).

**Example Output Directory Structure:**

```
/tmp/out/<timestamp>/
├── capture/
│   ├── eth0.pcap
│   └── eth0.pcap.txt
├── checksums/
│   ├── md5.txt
│   ├── sha1.txt
│   └── sha256.txt
├── commands/
│   ├── stdout.ps.txt
│   └── stdout.ls.txt
├── file_permissions.txt
└── files_and_dirs/
```


## YAML configuration

Check `config.yaml.sample` for full example.

### Capture module | network

Capture network traffic for 60 seconds. Uses scapy module for the capture and capture interfaces are specified with command line argument `-if / --interfaces <if1,if2,if3>`.

```yaml
  capture:
    enable_network: true
    # seconds
    network:
      timeout: 60
  ...
```

Pcap and extracted text file version are stored under "capture" directory inside the collection.

### Capture module | memory

Example to enable memory capture and use lime module found in path `memory/lime-6.14.0-36-generic.ko`

```yaml
  capture:
  ...
    enable_memory: true
    memory:
      capture_method: lime
      lime:
        # Module not included
        path: memory/lime-6.14.0-36-generic.ko
        # Format: lime/raw
        format: lime
```

Memory capture is stored under "capture" directory inside the collection.


## Running modules in own threads

You can run any module in its own thread by specifying `own_thread` to `true` inside the module's config. Here's an example with the network module: 

```
modules:
  capture:
    # Capture network traffic
    enable_network: true
    # seconds
    network:
      own_thread: true
```

The `own_thread` parameter defaults to `false` with all modules if not specified.
