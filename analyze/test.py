from lib.plaso import PlasoTimelineParser
from lib.db import DB
import sys

db = DB("collectifor.db")

parser = PlasoTimelineParser(db)
parser.parse_file(sys.argv[1])
