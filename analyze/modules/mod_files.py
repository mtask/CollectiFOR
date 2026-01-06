import re
import os
import glob
import gzip
import yaml
import logging
from pathlib import Path
from lib.finding import new_finding
from pygrok import Grok


def _open_file(path):
    """Open normal or gzipped file in text mode"""
    logging.info(f"[+] Read file {path}")
    if Path(path).suffix == ".gz":
        return gzip.open(path, "rt", errors="ignore")
    return open(path, "r", errors="ignore")


def _load_rules(rule_dir):
    rules = []

    for i in os.listdir(rule_dir):
        rule_file = Path(rule_dir) / i
        logging.info(f"[+] Loading rules from {rule_file}")
        with open(rule_file, "r") as f:
            data = yaml.safe_load(f)

        for event in data.get("events", []):
            type = event.get('type', 're')
            raw_pattern = event["pattern"]
            # Normalize YAML-folded whitespace:
            # remove all literal whitespace that VERBOSE would ignore anyway
            normalized = re.sub(r"[ \t\r\n]+", " ", raw_pattern).strip()
            if type == "re":
                try:
                    pattern = re.compile(normalized, re.VERBOSE)
                except re.error as e:
                    raise ValueError(
                        f"Invalid regex in rule '{event['name']}': {e}"
                    ) from e
            elif type == "grok":
                try:
                    pattern = Grok(normalized)
                except re.error as e:
                    raise ValueError(
                        f"Invalid grok in rule '{event['name']}': {e}"
                    ) from e
            else:
                logging.warning(f'[-] Unknown rule type "{type}" - {event["name"]}')
            rules.append({
                "name": event["name"],
                "indicator": event["indicator"],
                "pattern": pattern,
                "type": type,
                "message_template": event["message_template"],
                "meta_fields": event.get("meta_fields", []),
                "filenames": event.get("filenames", []),
                "source_file": str(rule_file)
            })
    logging.info(f"[+] Loaded {len(rules)} rules")
    return rules


def _find_files(file_dir, prefixes):
    """
    Find all files matching rules' .filenames including rotated files
    and glob patterns like /x/y/*.ext
    """
    files_lst = []
    for prefix in prefixes:
        # Check if the prefix contains a glob pattern (*)
        if "*" in str(prefix):
            for f_path in glob.glob(str(Path(file_dir) / prefix.lstrip('/'))):
                f = Path(f_path)
                if f.is_file():
                    files_lst.append({"path": str(f), "prefix": prefix})
        else:
            # Rotated files
            p = Path(prefix)
            base_name = p.name
            for f in glob.glob(str(Path(file_dir) / f"{prefix.lstrip('/')}*")):
                f = Path(f)
                if f.is_file():
                    try:
                        relative_path = f.relative_to(file_dir)
                    except ValueError:
                        continue
                    # check if the file matches the prefix
                    if str(relative_path).startswith(str(Path(prefix).relative_to("/"))):
                        files_lst.append({"path": str(f), "prefix": prefix})

    return files_lst

def analyze(rules_dir, rootdir):
    results = []
    file_dir = Path(rootdir)

    rules = _load_rules(rules_dir)

    # Build a set of log file prefixes from rules
    prefixes = set()
    for d in rules:
        prefixes.update(d["filenames"])
    logging.info("[+] Searching for relevant file paths")
    files_lst = _find_files(file_dir, prefixes)
    logging.info("[+] File list is ready")

    for current_file in files_lst:
        logging.info(f"Checking file: {current_file['path']}")
        try:
            with _open_file(current_file['path']) as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if not line:
                        continue
                    for rule in rules:
                        # Check if current file is in rule filenames
                        if f"{current_file['prefix']}" not in rule['filenames']:
                            continue
                        if rule['type'] == "re":
                            match_raw = rule["pattern"].search(line)
                        elif rule['type'] == "grok":
                            match_raw = rule["pattern"].match(line)
                        if not match_raw:
                            continue
                        elif match_raw and rule['type'] == "re":
                            match = match_raw.groupdict()
                        elif match_raw and rule['type'] == "grok":
                            match = match_raw
                        finding = new_finding()
                        finding["type"] = "files"
                        finding["artifact"] = current_file['path'].split(str(rootdir))[1]
                        finding["indicator"] = rule["indicator"]
                        finding['rule'] = rule['name']
                        finding['source_file'] = rule['source_file']

                        finding["message"] = rule["message_template"].format(
                            **match
                        )

                        meta = {"line": line}
                        for field in rule["meta_fields"]:
                            meta[field] = match[field]
                        finding["meta"] = meta

                        results.append(finding)
                        break  # only one rule per line
        except Exception as e:
            logging.error(repr(e))
    logging.info(f"[+] {len(results)} findings from files module")
    return results

