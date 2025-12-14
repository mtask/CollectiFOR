## Usage

`analyze.py` analyses collected data for anomalies and IoCs.

```bash
python analyze.py --config config.yaml --collection-path /tmp/out/<collection>.tar.gz --pattern --yara --analysis
```

**Options:**
- `--collection-path`: Path to the collected tar.gz. (required)
- `--pattern`: Enable IoC pattern matching. (optional)
- `--yara`: Enable YARA scanning. (optional)
- `--analysis`: Enable other analysis modules against `files_and_dirs` content in the collection. (optional)

**YAML configuration:**

See `./config.yaml`.

**Analysis Output:**
- HTML report with sections for:
  - YARA results
  - Pattern matches
  - PCAP analysis
  - File permissions issues
  - Logs anomalies


## Modules

### Patterns and YARA modules

* Load your patterns to text files containing things like IoCs under `patterns` directory. Files should have `.txt` extension.
* Load your YARA rules under `yara` directory. Files should have `.yar` extension.

Both directories can have sub-directories. Files (`.yar`/`.txt`) are searched recursively under those directories if related modules are enabled.

Directory paths for patterns and rules can be changed in `config.yaml`:

```
modules:
  pattern:
    # Pattern txt files are here. One pattern per line
    # Can contain sub directories
    # Expects .txt extension
    patterns_dir: ./patterns
  yara:
    # Yara yar files are here
    # Can contain sub directories
    # Expects .yar extension
    rules_dir: ./yara
```

Enable YARA module by giving `--yara` option and patterns module by giving `--pattern` option.

### Other analysis

Other analysis is enabled by giving `--analysis` option.

## Report

TBD
