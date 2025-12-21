import re
import os
import gzip
import yaml
import logging
from pathlib import Path
from lib.finding import new_finding


def _open_log(path):
    """Open normal or gzipped log file in text mode"""
    if Path(path).suffix == ".gz":
        return gzip.open(path, "rt", errors="ignore")
    return open(path, "r", errors="ignore")


def _load_rules(rule_dir):
    import re
    import yaml
    rules = []

    for i in os.listdir(rule_dir):
        rule_file = Path(rule_dir) / i
        logging.info(f"[+] Loading rules from {rule_file}")
        with open(rule_file, "r") as f:
            data = yaml.safe_load(f)

        for event in data.get("events", []):
            raw_pattern = event["pattern"]

            # Normalize YAML-folded whitespace:
            # remove all literal whitespace that VERBOSE would ignore anyway
            normalized = re.sub(r"[ \t\r\n]+", " ", raw_pattern).strip()

            try:
                regex = re.compile(normalized, re.VERBOSE)
            except re.error as e:
                raise ValueError(
                    f"Invalid regex in rule '{event['name']}': {e}"
                ) from e

            rules.append({
                "name": event["name"],
                "indicator": event["indicator"],
                "regex": regex,
                "message_template": event["message_template"],
                "meta_fields": event.get("meta_fields", []),
                "filenames": event.get("filenames", [])
            })

    return rules


def _find_files(log_dir, prefixes):
    """
    Find all log files matching rules' .filenames including rotated files
    """
    log_files = []
    for prefix in prefixes:
        p = Path(prefix)
        base_name = p.name
        pattern = f"{base_name}*"
        for f in log_dir.rglob("*"):  # get all files
            if f.is_file():
                # check if the file matches the prefix
                try:
                    relative_path = f.relative_to(log_dir)  # make path relative
                except ValueError:
                    continue  # f is outside log_dir, skip
                if str(relative_path).startswith(str(Path(prefix).relative_to("/"))):
                    log_files.append({"path": str(f), "prefix": prefix})
    return log_files

def analyze(rootdir, rules_dir="source/logs/"):
    results = []
    log_dir = Path(rootdir) / "files_and_dirs"

    rules = _load_rules(rules_dir)

    # Build a set of log file prefixes from rules
    prefixes = set()
    for d in rules:
        prefixes.update(d["filenames"])

    log_files = _find_files(log_dir, prefixes)

    for log_file in log_files:
        logging.info(f"Checking log file: {log_file['path']}")
        try:
            with _open_log(log_file['path']) as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if not line:
                        continue
                    for rule in rules:
                        # Check if current log file is in rule filenames
                        if f"{log_file['prefix']}" not in rule['filenames']:
                            continue
                        match = rule["regex"].search(line)
                        if not match:
                            continue
                        finding = new_finding()
                        finding["type"] = "logs"
                        finding["artifact"] = str(f"files_and_dirs{log_file['prefix']}")
                        finding["indicator"] = rule["indicator"]
                        finding['rule'] = rule['name']

                        # Message formatting (same content as original)
                        finding["message"] = rule["message_template"].format(
                            **match.groupdict()
                        )

                        # Meta (same structure as original)
                        meta = {"line": line}
                        for field in rule["meta_fields"]:
                            meta[field] = match.group(field)
                        finding["meta"] = meta

                        results.append(finding)
                        break  # only one rule per line
        except Exception as e:
            logging.error(repr(e))
    logging.info(f"[+] {len(results)} findings from logs")
    return results

