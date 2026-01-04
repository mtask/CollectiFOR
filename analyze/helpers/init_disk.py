from datetime import datetime
import argparse
import logging
import yaml
import os
import sys
from pathlib import Path
from lib.db import DB
from lib.parsers import FilesAndDirsParser, BasicInfoParser, FilesAndDirsChecksumParser
from modules import mod_files as mf
from modules import mod_pattern as mp
from modules import mod_yara as my


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
        description="Initialize data from mounted disk image to CollectiFOR's database"
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
        help="Path to subdir inside the disk where to target the initialization. Can be full path or relative path from the disk mount path. Init is run against the full disk mount path if left empty.",
        required=False
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all ingest and analysis modules. No need to provide specific module options."
    )
    parser.add_argument(
        "--checksums",
        action="store_true",
        help="Ingest checksums"
    )
    parser.add_argument(
        "--ifiles",
        action="store_true",
        help="Ingest file and directory paths"
    )
    parser.add_argument(
        "--yara",
        action="store_true",
        help="Run YARA analysis module"
    )
    parser.add_argument(
        "--files",
        action="store_true",
        help="Run Files analysis module"
    )
    parser.add_argument(
        "--pattern",
        action="store_true",
        help="Run Pattern module"
    )
    args = parser.parse_args()
    config = load_config(args.config)
    findings = []
    name_timestamp =  datetime.now().strftime("%Y%m%d_%H%M%S")
    db = DB(config['collection_database'], f"DISK_{Path(args.disk).name}_{name_timestamp}", args.disk, init=True)
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
       logging.info(f'[+] Running initialization with target path: "{target_path}"')
    db.add_collection_info({"date": datetime.now(), "interfaces": {}, "os": {}, "hostname": ""})
    if args.checksums or args.all:
        fpc = FilesAndDirsChecksumParser(db, subdir="")
        logging.info("[+] Running checksums")
        fpc.parse_dir(target_path)
    if args.files or args.all:
        logging.info("[+] Running files and dirs")
        fp = FilesAndDirsParser(db, subdir="")
        fp.parse_dir(target_path)
    ###
    # Analysis
    ###
    findings = []
    if args.yara or args.all:
        logging.info("[+] Running YARA module")
        findings = findings + my.search(config['analysis']['yara']['rule_source'], target_path, exclude_dirs=config['analysis']['yara'].get('exclude_dirs', None), include_dirs=config['analysis']['yara'].get('include_dirs', None))
    if args.files or args.all:
        logging.info("[+] Running Files module")
        findings = findings + mf.analyze(config['analysis']['files'], target_path)
    if args.pattern or args.all:
        logging.info("[+] Running Pattern module")
        findings = findings + mp.search(config['analysis']['pattern'], target_path)
    if findings:
        logging.info(f"Adding {len(findings)} findings to database.")
        db.add_finding_entries(findings)
