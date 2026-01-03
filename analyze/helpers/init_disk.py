from datetime import datetime
import argparse
import logging
import yaml
import os
import sys
from pathlib import Path
from lib.db import DB
from lib.hash import get_sha1, get_sha256, get_md5
from lib.parsers import FilesAndDirsParser

def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data


def generate_hashes(file_path):
    _sha1 = get_sha1(file_path)
    _sha256 = get_sha256(file_path)
    _md5 = get_md5(file_path)

def ingest_checksums(dir_path):
    checksums = []
    for f in Path(dir_path).rglob("*"):
        if not os.path.isfile(f):
            continue
        logging.info(f'[+] Generating checksums for file "{f}"')
        checksums.append({"filepath": str(f), "checksum": get_sha256(f), "algorithm": "sha256"})
        checksums.append({"filepath": str(f), "checksum": get_sha1(f), "algorithm": "sha1"})
        checksums.append({"filepath": str(f), "checksum": get_md5(f), "algorithm": "md5"})
    return checksums

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
        "--checksums",
        action="store_true",
        help="Ingest checksums"
    )
    parser.add_argument(
        "--files",
        action="store_true",
        help="Ingest file and directory paths"
    )
    args = parser.parse_args()
    config = load_config(args.config)
    findings = []
    db = DB(config['collection_database'], f"DISK_{Path(args.disk).name}", args.disk, init=True)
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
    if args.checksums:
        logging.info("[+] Running checksums")
        checksums = ingest_checksums(target_path)
        if checksums:
            db.add_checksums(checksums)
    if args.files:
        logging.info("[+] Running files and dirs")
        fp = FilesAndDirsParser(db, subdir="")
        fp.parse_dir(target_path)
