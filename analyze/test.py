from lib.timeline import PlasoTimelineParser
from lib.db_tl import DB
import sys
import logging


if __name__=="__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    dbtl = DB("timeline.db")
    parser = PlasoTimelineParser(dbtl)
    parser.parse_file(sys.argv[1], batch_size=10_000)
