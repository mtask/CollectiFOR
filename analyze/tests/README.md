## run_files.py

Runs Files module and prints findings as JSON.

```
python3 -m tests.run_files -c config.yaml /tmp/sample/rl_20251225_194124/20251225_194124/
```

Sample `Files` module rules assume path `files_and_dirs`. Filenames in rules need to match when joined with the provided path for module to scan file contents.
For example:

```
filenames:
      - /files_and_dirs/var/log/syslog
```

--\> `/tmp/sample/rl_20251225_194124/20251225_194124/files_and_dirs/var/log/syslog`


## run_yara.py

Runs YARA module and prints findings as JSON.

```
python3 -m tests.run_yara -c config.yaml /mnt/forensic/4Dell.E01-p1/
```

## run_pattern.py

Runs Pattern module and prints findings as JSON.

```
python3 -m tests.run_pattern -c config.yaml /mnt/forensic/4Dell.E01-p1/
```
