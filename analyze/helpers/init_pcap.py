from datetime import datetime
import argparse
import logging
import yaml
import os
import sys
import json
import modules.mod_pcap as mpcap
from pathlib import Path
from lib.db import DB
from lib.parsers import PcapParser
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
        description="Initialize PCAP files from a directory"
    )

    parser.add_argument(
        "-c", "--config",
        help="Path to collectifor.py's config.yaml",
        required=True
    )
    parser.add_argument(
        "-p", "--pcap-dir",
        help="Path to directory with PCAP files",
        required=True
    )
    args = parser.parse_args()
    config = load_config(args.config)
    name_timestamp =  datetime.now().strftime("%Y%m%d_%H%M%S")
    db = DB(config['collection_database'], f"PCAPS_{Path(args.pcap_dir).name}_{name_timestamp}", args.pcap_dir, init=True)
    pcp = PcapParser(db, subdir="")
    logging.info("[+] Running PCAP parser")
    pcp.parse_dir(args.pcap_dir)
    logging.info("[+] Running PCAP analysis module")
    findings = mpcap.analyze(args.pcap_dir, subdir="")
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
