import yaml
import argparse
import json
import os
import sys
import logging
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

def validate_config(args, config):
    if not args.capture and not args.collect:
        print("No --collect or --capture specified. Nothing to do.")
        sys.exit(0)
    if args.capture and not args.interfaces and config['modules']['capture']['enable_network']:
        print("-if / --interfaces is required when using --capture and network capturing is enabled in configuration")
        sys.exit(1)

def main(args):
    config = load_config(args.config)
    validate_config(args, config)
    dir_timestamp =  datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = os.path.join(config['outdir'], dir_timestamp)
    os.makedirs(outdir, exist_ok=True)
    if args.capture:
        logging.info("Running capture module")
        import modules.mod_capture as mcap
        mod_capture = config['modules']['capture']
        if mod_capture['enable_memory']:
            mcap.memory(outdir, mod_capture['memory'])
        if mod_capture['enable_network']:
            mcap.network_interfaces(outdir, int(mod_capture['network_timeout']), args.interfaces.strip().split(','))
    if args.collect:
        logging.info("Running collect module")
        import modules.mod_collect as mc
        mod_collect = config['modules']['collect']
        if mod_collect['enable_file_permissions']:
            mc.file_permissions(outdir, mod_collect['file_permissions'])
        if mod_collect['enable_commnds']:
            mc.commands(outdir, mod_collect['commands'])
        if mod_collect['enable_luks']:
            mc.find_luks_devices(outdir)
        if mod_collect['enable_checksums']:
            mc.checksums(outdir, mod_collect['checksums'])
        if mod_collect['enable_files_and_dirs']:
            mc.files_and_dirs(outdir, mod_collect['files_and_dirs'])
    if config['compress_collection']:
        import lib.collection as lc
        logging.info("Compressing collection")
        lc.compress(config['outdir'], dir_timestamp)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Triage collection"
    )
    parser.add_argument(
        "-c", "--config",
        required=True,
        help="Path to the YAML configuration file"
    )

    parser.add_argument(
        "--collect",
        action='store_true',
        help="Enable collect module"
    )

    parser.add_argument(
        "--capture",
        action='store_true',
        help="Enable capture module"
    )

    parser.add_argument(
        "-if", "--interfaces",
        required=False,
        help="Interfaces for capture module. Multiple interfaces can be seperated with comma"
    )

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = parse_args()
    main(args)
