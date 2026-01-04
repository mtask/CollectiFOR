import argparse
import logging
import yaml
import json
from modules import mod_yara as my


def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data

if __name__=="__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    parser = argparse.ArgumentParser(
        description="Run YARA module"
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
    logging.info("[+] Running YARA module")
    findings = my.search(config['analysis']['yara']['rule_source'], args.path, exclude_dirs=config['analysis']['yara'].get('exclude_dirs', None), include_dirs=config['analysis']['yara'].get('include_dirs', None))
    print(json.dumps(findings, indent=2))
