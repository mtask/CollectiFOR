import yaml
import argparse
import json
import os
import sys
import logging
import lib.collection as lc
from jinja2 import Environment, FileSystemLoader
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data

def report(reportdir, yara_data=[], pattern_data={}, persistence_data=[], pcap_data=[], log_data=[], file_permission_data=[]):
    env = Environment(loader=FileSystemLoader("./"))
    template = env.get_template("templates/report.html")
    html = template.render(
        pattern_result=pattern_data,
        yara_result=yara_data,
        persistence_result=persistence_data,
        pcap_result=pcap_data,
        log_result=log_data,
        file_permission_result=file_permission_data
    )

    with open(os.path.join(reportdir, "report.html"), "w") as f:
        f.write(html)

def validate_config(args, config):
    pass

def main(args):
    config = load_config(args.config)
    validate_config(args, config)
    target_path = lc.decompress(args.collection_path)
    pattern_result = []
    yara_result = []
    persistence_result = []
    pcap_result = []
    log_result = []
    file_permission_result = []
    if args.pattern:
        logging.info("Running pattern module")
        import modules.mod_pattern as mp
        mod_pattern = config['modules']['pattern']
        pattern_result = mp.search(mod_pattern['patterns_dir'], target_path)
        print(json.dumps(pattern_result, indent=2))
    if args.yara:
        logging.info("Running yara module")
        import modules.mod_yara as my
        mod_yara = config['modules']['yara']
        yara_result = my.search(mod_yara['rules_dir'], target_path)
        print(json.dumps(yara_result, indent=2))
    if args.analysis:
        import modules.mod_persistence as mp
        import modules.mod_pcap as mpcap
        import modules.mod_logs as ml
        import modules.mod_file_permissions as mf
        logging.info("Running persistence module")
        persistence_result = mp.analyze(target_path)
        print(json.dumps(persistence_result, indent=2))
        logging.info("Running pcap module")
        pcap_result = mpcap.analyze(target_path)
        print(json.dumps(pcap_result, indent=2))
        logging.info("Running logs module")
        log_result = ml.analyze(target_path)
        print(json.dumps(log_result, indent=2))
        logging.info("Running file permissions module")
        file_permission_result = mf.analyze(target_path)
        print(json.dumps(file_permission_result, indent=2))
    report(config['reportdir'], yara_data=yara_result, pattern_data=pattern_result, persistence_data=persistence_result, pcap_data=pcap_result, log_data=log_result, file_permission_data=file_permission_result)

def parse_args():
    parser = argparse.ArgumentParser(
        description="PyTriage"
    )
    parser.add_argument(
        "-c", "--config",
        required=True,
        help="Path to the YAML configuration file"
    )

    parser.add_argument(
        "-cp", "--collection-path",
        required=True,
        help="Path to collection tar.gz gathered by collect tool."
    )

    parser.add_argument(
        "--yara",
        action='store_true',
        help="Enable yara module"
    )

    parser.add_argument(
        "--pattern",
        action='store_true',
        help="Enable pattern module"
    )

    parser.add_argument(
        "--analysis",
        action='store_true',
        help="Run analysis modules"
    )

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = parse_args()
    main(args)
