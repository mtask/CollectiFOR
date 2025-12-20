import argparse
import logging
import os
import sys
import json

from lib.collection import decompress
from lib.db import DB
from lib.parsers import (
    CommandsParser,
    ChecksumParser,
    PermissionsParser,
    PcapParser,
    FilesAndDirsParser,
    ListenersParser,
)
from lib.db_tl_duckdb import DB as DDB
from lib.timeline import PlasoTimelineParser
from viewer.app import run_viewer
from pathlib import Path

# -----------------------------
# Parser registry
# -----------------------------
PARSERS = [
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

def analysis(args, collection_path):
    findings = []
    if args.pattern:
        logging.info("[RUN] Pattern module")
        import modules.mod_pattern as mp
        findings = findings + mp.search(args.pattern, collection_path)
    if args.yara:
        logging.info("[RUN] YARA module")
        import modules.mod_yara as my
        findings = findings + my.search(args.yara, collection_path)
    if args.logs or args.analysis:
        import modules.mod_logs as ml
        logging.info("[RUN] Logs module")
        findings = findings + ml.analyze(collection_path)
    if args.file_permissions or args.analysis:
        import modules.mod_file_permissions as mf
        logging.info("[RUN] File permissions module")
        findings = findings + mf.analyze(collection_path)
    if args.persistence or args.analysis:
        import modules.mod_persistence as mp
        logging.info("[RUN] Persistence module")
        findings = findings + mp.analyze(collection_path)
    if args.pcap or args.analysis:
        import modules.mod_pcap as mpcap
        logging.info("[RUN] PCAP module")
        findings = findings + mpcap.analyze(collection_path)
    return findings

#-----------------------------
# Timeline import
#----------------------------

def import_timeline(timeline):
    ddb = DDB("timeline.duckdb")
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
        "-c", "--collection",
        help="Path to collection directory or .tar.gz archive",
    )

    parser.add_argument(
        "-d", "--db",
        default="collectifor.db",
        help="SQLite database file (default: collectifor.db)",
    )

    parser.add_argument(
        "-td", "--tdb",
        default="timeline.duckdb",
        help="DuckDB database file for imported timeline (default: timeline.duckdb)",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    parser.add_argument(
        "-y", "--yara",
        metavar="RULE_DIR",
        help="Enable yara analysis module by providing path to your yara rules top-level directory."
    )

    parser.add_argument(
        "-p", "--pattern",
        metavar="PATTERN_DIR",
        help="Enable pattern analysis module by providing path your pattern files top-level directory."
    )

    parser.add_argument(
        "-l", "--logs",
        action='store_true',
        help="Enable logs analysis module"
    )

    parser.add_argument(
        "-fp", "--file-permissions",
        action='store_true',
        help="Enable file permissions analysis module"
    )

    parser.add_argument(
        "-pe", "--persistence",
        action='store_true',
        help="Enable persistence analysis module"
    )

    parser.add_argument(
        "-pc", "--pcap",
        action='store_true',
        help="Enable PCAP analysis module"
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
    if args.init and os.path.isfile(args.db) and args.collection:
        ans = input(f"{args.db} already exists. Do you want to continue with initialization?[y/n] (default: n)")
        if ans.lower() != "y":
            logging.info("[-] Exiting without changes")
            sys.exit(0)
    try:
        collection_id = os.path.join(Path(collection_dir).parts[-2], Path(collection_dir).parts[-1])
    except UnboundLocalError:
        collection_id = None
    db = DB(args.db, collection_id)

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
        import_timeline(args.timeline_file)
    if args.collection:
        logging.info("[+] Running enabled analysis modules")
        findings = analysis(args, collection_dir)
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
        run_viewer(collection_dir, db_file=args.db)
        return

if __name__ == "__main__":
    main()
