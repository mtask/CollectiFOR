from datetime import datetime
import argparse
import logging
import yaml
import os
import sys
import json
from pathlib import Path
from lib.db import DB
import modules.mod_files as mf
from lib.utils import collection_selector

def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data

if __name__=="__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    parser = argparse.ArgumentParser(
        description="Analyze arbitrary directory path wih Files analysis module. Rules' \"filenames\" need to match with the given path"
    )

    parser.add_argument(
        "-c", "--config",
        help="Path to collectifor.py's config.yaml",
        required=True
    )
    parser.add_argument(
        "-p", "--path",
        help="Root path to analyze.",
        required=True
    )
    args = parser.parse_args()
    if not os.path.isdir(args.path):
        logging.erro("[-] Path {args.path} is not an existing directory path")
        sys.exit(1)
    config = load_config(args.config)
    logging.info("[+] Running Files analysis")
    findings = mf.analyze(config['analysis']['files'], args.path)
    collection = collection_selector(config['collection_database'])
    if not collection:
         print(json.dumps(findings, indent=2))
         sys.exit(0)
    if not findings:
        logging.info(f"No findings")
    if collection['new']:
        db = DB(config['collection_database'], collection['name'], collection['path'], init=True)
        db.add_collection_info({"date": datetime.now(), "interfaces": {}, "os": {}, "hostname": ""})
    else:
        db = DB(config['collection_database'], collection['name'], collection['path'], init=False)
    logging.info(f"Adding {len(findings)} findings to database.")
    db.add_finding_entries(findings)
