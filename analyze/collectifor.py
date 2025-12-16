import argparse
import logging
import os
import sys

from lib.collection import decompress
from lib.db import DB
from lib.parsers import (
    CommandsParser,
    ChecksumParser,
    PermissionsParser,
    PcapParser,
    FilesAndDirsParser,
)

# -----------------------------
# Parser registry
# -----------------------------
PARSERS = [
    CommandsParser,
    ChecksumParser,
    PermissionsParser,
    PcapParser,
    FilesAndDirsParser,
]

# -----------------------------
# Main
# -----------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Parse forensic collection and store results in SQLite DB"
    )

    parser.add_argument(
        "collection",
        help="Path to collection directory or .tar.gz archive",
    )

    parser.add_argument(
        "-d", "--db",
        default="collectifor.db",
        help="SQLite database file (default: collectifor.db)",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
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

    if not os.path.isdir(collection_dir):
        logging.error(f"Invalid collection directory: {collection_dir}")
        sys.exit(1)

    logging.info(f"Using collection directory: {collection_dir}")

    # -----------------------------
    # Database
    # -----------------------------
    db = DB(args.db)

    # -----------------------------
    # Run parsers
    # -----------------------------
    for ParserCls in PARSERS:
        logging.info(f"[RUN ] {ParserCls.__name__}")
        try:
            parser = ParserCls(db)
            parser.parse_dir(collection_dir)
        except Exception:
            # Parsers should not crash the whole run
            logging.exception(f"[FAIL] {ParserCls.__name__}")

    logging.info("All parsers completed")


if __name__ == "__main__":
    main()
