import argparse
import logging
import yaml
import pathlib
import os
import sys
from modules import mod_files as mf
from modules import mod_pattern as mp
from modules import mod_yara as my
from lib.db import DB
from datetime import datetime


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
        description="Analyze mounted disk image and ingest findings to CollectiFOR's database"
    )

    parser.add_argument(
        "-c", "--config",
        help="Path to collectifor.py's config.yaml",
        required=True
    )
    parser.add_argument(
        "-d", "--disk",
        help="Path to mounted disk image",
        required=True
    )
    parser.add_argument(
        "-s", "--subdir",
        help="Path to subdir inside the disk where to target the analysis. Can be full path or relative path from the disk mount path. Analysis is run against the full disk mount path if left empty.",
        required=False
    )
    parser.add_argument(
        "--yara",
        action="store_true",
        help="Run YARA module"
    )
    parser.add_argument(
        "--files",
        action="store_true",
        help="Run Files module"
    )
    parser.add_argument(
        "--pattern",
        action="store_true",
        help="Run Pattern module"
    )
    args = parser.parse_args()
    config = load_config(args.config)
    findings = []
    db = DB(config['collection_database'], f"DISK_{pathlib.Path(args.disk).name}", args.disk, init=False)
    if args.subdir:
        if args.subdir.startswith(args.disk):
            target_path = args.subdir
        else:
            target_path = os.path.join(args.disk, args.subdir.lstrip('/'))
    else:
        target_path = args.disk
    if not os.path.isdir(target_path):
        logging.error(f"[-] Provided path {target_path} is not a directory")
        sys.exit(1)
    else:
       logging.info(f'[+] Running analysis with target path: "{target_path}"')
    if args.yara:
        logging.info("[+] Running YARA module")
        findings = findings + my.search(config['analysis']['yara'], target_path)
    if args.files:
        logging.info("[+] Running Files module")
        findings = findings + mf.analyze(config['analysis']['files'], target_path)
    if args.pattern:
        logging.info("[+] Running Pattern module")
        findings = findings + mp.search(config['analysis']['pattern'], target_path)
    if findings:
        logging.info(f"Adding {len(findings)} findings to database.")
        db.add_finding_entries(findings)
