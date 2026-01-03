import argparse
import logging
import yaml
import json
from modules import mod_files as mf


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
        description="Run files module"
    )
    parser.add_argument(
        "path",
        help="Path to analyze"
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to collectifor.py's config.yaml",
        required=True
    )
    args = parser.parse_args()
    config = load_config(args.config)
    logging.info("[+] Running Files module")
    findings = mf.analyze(config['analysis']['files'], args.path)
    print(json.dumps(findings, indent=2))
