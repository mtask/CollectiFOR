You may not always be able run the binary on a target machine or even the unbuilt `collect.py` script with its dependencies. 
The `gen-collect-sh.py` allows you to generate an alternative `collect.sh` type bash scripts based on the collect tool's YAML configurations.

**Usage:**

1. Run `python3 gen-collect-sh.py -c <path to config.yaml> <name for the output script e.g. collect.sh>`
2. Copy generated `<script name>.sh` to target host.
3. Run `./collect.sh` (usually as root).
4. Copy collection directory or tar.gz depending on your settings.

The script is generated with Jinja2 template under `templates` dirctory and it's very repetitive with the tasks as it's basically built with loops based on the config.yaml content.
The outcome should still work with CollectiFOR's analysis component.

You could use this to prepare different scripts for different needs. For example:

```bash
$ python3 gen-collect-sh.py -c ../config_samples/config.disk_dd.yaml collect_dd.sh 
$ python3 gen-collect-sh.py -c ../config_samples/config.disk_e01.yaml collect_e01.sh
$ python3 gen-collect-sh.py -c ../config.yaml collect_main.sh
$ ls *.sh
collect_dd.sh  collect_e01.sh  collect_main.sh
```

**Limitations / differences from the collect binary:**

* Network capture requires that tcpdump is installed on the host (`collect` tools uses Scapy)
* Tcpdump captures all interfaces unless you modify the script manually.
* Prompts for the disk and host in disk capture
* Does not allow skipping capture or collect modules based on cli switches. All modules enabled in config are included in the generated script.
* No multithreading support for different modules.
* Does not generate `listeners.json` (listeners module), but same information can always be collected with `commands` module.
