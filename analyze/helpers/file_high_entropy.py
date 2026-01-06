import os
import re
import glob
import logging
from pathlib import Path
from lib.finding import new_finding
from lib.utils import file_entropy
import argparse
import logging
import yaml
import sys
import json
from lib.db import DB
from lib.utils import collection_selector
from datetime import datetime

def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data

def _parse_size(size_str):
    """
    Convert human-readable file size string to bytes.
    Supports: B, KB, MB, GB, TB (case-insensitive).
    Example: "10MB" -> 10485760
    """
    if size_str is None:
        return None

    size_str = str(size_str).strip().upper()
    match = re.match(r'^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)?$', size_str)
    if not match:
        raise ValueError(f"Invalid size: {size_str}")

    number, unit = match.groups()
    number = float(number)
    unit_multipliers = {
        None: 1,
        "B": 1,
        "KB": 1024,
        "MB": 1024**2,
        "GB": 1024**3,
        "TB": 1024**4,
    }
    return int(number * unit_multipliers[unit])

def _entropy(f, max_size=None):
    """
    Calculate file entropy only if file is a regular file and below max_size.
    :param f: path to file
    :param threshold: entropy threshold
    :param max_size: maximum file size, can be int (bytes) or str like '10MB'
    """
    if not os.path.isfile(f):
        return  # skip non-regular files

    if max_size:
        if isinstance(max_size, str):
            max_size_bytes = _parse_size(max_size)
        else:
            max_size_bytes = max_size

        size = os.path.getsize(f)
        if size > max_size_bytes:
            print(f"[-] Skipping entropy calculation for {f}: file size {size} > {max_size_bytes}")
            return 0

    return file_entropy(f)

def analyze(rootdir, entropy_threshold=6.5, max_size="1GB"):
    results = []
    entries = []
    for root, dirs, files in os.walk(rootdir):
        for name in files + dirs:
            full_path = os.path.join(root, name)
            if os.path.isfile(full_path) and not os.path.islink(full_path):
                ent = _entropy(full_path, max_size=max_size)
                if ent >= float(entropy_threshold):
                    entries.append({"path": full_path, "entropy": str(ent)})
    for e in entries:
        finding = new_finding()
        finding["type"] = "file_anomaly"
        finding["artifact"] = os.path.basename(e["path"])
        finding["indicator"] = str(e["entropy"])
        finding['rule'] = "file_with_high_entropy"
        finding["message"] =  f'File {e["path"]} entropy is {e["entropy"]}'
        meta = {}
        results.append(finding)
    return results

if __name__=="__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    parser = argparse.ArgumentParser(
        description="Find files with high entropy"
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to collectifor.py's config.yaml",
        required=True
    )
    parser.add_argument(
        "-p", "--path",
        help="Path to target directory",
        required=True
    )
    parser.add_argument(
        "-t", "--threshold",
        help="Entropy threshold (default: 6.5)",
        default="6.5"
    )
    parser.add_argument(
        "-m", "--max-size",
        help='Max size to check a file (default: "1GB"',
        default="1GB"
    )
    args = parser.parse_args()
    config = load_config(args.config)
    findings = analyze(args.path, entropy_threshold=float(args.threshold), max_size=args.max_size)
    if not findings:
        logging.info(f"No findings")
    collection = collection_selector(config['collection_database'])
    if not collection:
         print(json.dumps(findings, indent=2))
         sys.exit(0)
    if collection['new']:
        db = DB(config['collection_database'], collection['name'], collection['path'], init=True)
        db.add_collection_info({"date": datetime.now(), "interfaces": {}, "os": {}, "hostname": ""})
    else:
        db = DB(config['collection_database'], collection['name'], collection['path'], init=False)
    logging.info(f"Adding {len(findings)} findings to database.")
    db.add_finding_entries(findings)
