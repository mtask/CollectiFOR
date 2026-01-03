from lib.db import DB
import yaml
import argparse
import logging

def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data

def get_findings():
    """
    Generate findings here
    """
    finding = {}
    finding["type"] = "custom"
    finding["artifact"] = "file.txt"
    finding["indicator"] = "some indicator"
    finding['rule'] = "XYZ"
    finding["message"] = "This is a sample finding"
    finding["meta"] = {"arbitrary": "dict data"}
    findings = [finding]
    return findings

if __name__=="__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    parser = argparse.ArgumentParser(
        description="3rd part findings integration"
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to collectifor.py's config.yaml",
        required=True
    )
    args = parser.parse_args()
    config = load_config(args.config)
    db = DB(config['collection_database'], "COLLECTION_NAME", "PATH_TO_COLLECTION", init=True)
    db.add_collection_info({})
    db.add_finding_entries(get_findings())

