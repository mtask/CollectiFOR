import argparse
import logging
import os
import sys
import json
import yaml

from lib.collection import decompress
from lib.db import DB
from lib.parsers import (
    CommandsParser,
    ChecksumParser,
    PermissionsParser,
    PcapParser,
    FilesAndDirsParser,
    ListenersParser,
    BasicInfoParser,
)
from lib.db_tl_duckdb import DB as DDB
from lib.timeline import PlasoTimelineParser
from viewer.app import run_viewer
from viewer.database import init_db
from pathlib import Path

def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data


# -----------------------------
# Parser registry
# -----------------------------
PARSERS = [
    BasicInfoParser,
    CommandsParser,
    ChecksumParser,
    PermissionsParser,
    PcapParser,
    FilesAndDirsParser,
    ListenersParser,
]

# -----------------------------
# Analysis
# -----------------------------

def analysis(config, collection_path):
    findings = []
    if config['enable_pattern']:
        logging.info("[RUN] Pattern module")
        import modules.mod_pattern as mp
        findings = findings + mp.search(config['pattern'], collection_path)
    if config['enable_yara']:
        logging.info("[RUN] YARA module")
        import modules.mod_yara as my
        findings = findings + my.search(config['yara']['rule_source'], collection_path, exclude_dirs=config['yara'].get('exclude_dirs', None), include_dirs=config['yara'].get('include_dirs', None))
    if config['enable_files']:
        import modules.mod_files as ml
        logging.info("[RUN] Files module")
        findings = findings + ml.analyze(config['files'], collection_path)
    if config['enable_pcap']:
        import modules.mod_pcap as mpcap
        logging.info("[RUN] PCAP module")
        findings = findings + mpcap.analyze(collection_path)
    return findings

#-----------------------------
# Timeline import
#----------------------------

def import_timeline(timeline, config):
    ddb = DDB(config['timeline_database'])
    parser = PlasoTimelineParser(ddb)
    parser.parse_file(timeline, batch_size=100_000, progress_interval=50_000)


# -----------------------------
# Main
# -----------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Parse forensic collection and store results in SQLite DB"
    )

    parser.add_argument(
        "-c", "--config", required=True,
        help="Path to CollectiFOR's config.yaml",
    )

    parser.add_argument(
        "--init",
        action='store_true',
        help="Initialize collection (Run only once against same collection)"
    )

    parser.add_argument(
        "--analysis",
        action='store_true',
        help="Enable and run all analysis modules. Yara module requires --yara RULE_DIR and pattern module --pattern PATTERN_DIR"
    )

    parser.add_argument(
        "--collection",
        help="Path to collection directory or .tar.gz archive",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    parser.add_argument(
        "-tf", "--timeline-file",
        metavar="TIMELINE_FILE",
        help="Import exported Plaso timeline in JSON lines format"
    )

    parser.add_argument(
        "--viewer",
        action="store_true",
        help="Launch local analysis viewer"
    )

    args = parser.parse_args()
    config = load_config(args.config)

    # -----------------------------
    # Logging
    # -----------------------------
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    # -----------------------------
    # Collection handling
    # -----------------------------
    collection_path = args.collection
    if args.collection:
        if not os.path.exists(collection_path):
            logging.error(f"Collection path does not exist: {collection_path}")
            sys.exit(1)

        if collection_path.endswith(".tar.gz"):
            try:
                collection_dir = decompress(collection_path)
            except Exception as e:
                logging.error(f"Failed to decompress archive: {e}")
                sys.exit(1)
        else:
            collection_dir = collection_path
            if not os.path.isfile(os.path.join(collection_dir, "info.json")):
                logging.error(f"Path does not look like a collection directory (info.json not found): {collection_dir}")
                sys.exit(1)

        # -----------------------------
        # Viewer
        # -----------------------------
        if not os.path.isdir(collection_dir):
            logging.error(f"Invalid collection directory: {collection_dir}")
            sys.exit(1)
    else:
        logging.info(f"No collection directory provided")

    # -----------------------------
    # Database
    # -----------------------------
    try:
        collection_id = os.path.join(Path(collection_dir).parts[-2])
    except UnboundLocalError:
        collection_dir = None
        collection_id = None
    db = DB(config['collection_database'], collection_id, collection_dir, init=args.init)

    # -----------------------------
    # Run parsers
    # -----------------------------
    if args.init and args.collection:
        logging.info("[+] Running initialize parsers")
        for ParserCls in PARSERS:
            logging.info(f"[RUN] {ParserCls.__name__}")
            try:
                parser = ParserCls(db)
                parser.parse_dir(collection_dir)
            except Exception:
                # Parsers should not crash the whole run
                logging.exception(f"[FAIL] {ParserCls.__name__}")
        logging.info("[+] All parsers completed")
    elif args.init and not args.collection:
        logging.error("[-] No collection provided with --collection <collection")
    if args.timeline_file:
        logging.info(f"[+] Importing timeline: {args.timeline_file}")
        import_timeline(args.timeline_file, config)
    if args.collection and args.analysis:
        logging.info("[+] Running enabled analysis modules")
        findings = analysis(config['analysis'], collection_dir)
        if findings:
            logging.info(f"Adding {len(findings)} findings to database.")
            db.add_finding_entries(findings)
        logging.info("[+] All modules completed")
    if args.viewer:
        logging.info("[+] Running viewer")
        try:
            collection_dir
        except NameError:
            collection_dir = None
        init_db(config['collection_database'])
        run_viewer(api_keys=config.get('api_keys', {}))
        return

if __name__ == "__main__":
    main()
