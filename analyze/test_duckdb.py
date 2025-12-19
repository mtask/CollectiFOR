import sys
import logging
from lib.db_tl_duckdb import DB
from lib.timeline import PlasoTimelineParser

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <plaso.jsonl>")
        sys.exit(1)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    db = DB("timeline.duckdb")
    parser = PlasoTimelineParser(db)
    parser.parse_file(sys.argv[1], batch_size=100_000, progress_interval=50_000)

if __name__ == "__main__":
    main()
