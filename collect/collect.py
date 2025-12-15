import threading
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
        sys.exit(1)
    if args.capture and not args.interfaces and config['modules']['capture']['enable_network']:
        print("-if / --interfaces is required when using --capture and network capturing is enabled in configuration")
        sys.exit(1)
    if args.capture and (not args.disk or not args.disk_host) and config['modules']['capture']['enable_disk']:
        print("-d / --disk and -dh / --disk-host are required when using --capture and disk capturing is enabled in configuration")
        sys.exit(1)

def run_collect_modules(enabled_collect_modules, outdir, config, threads=[]):
    logging.info("[+] Running collect modules")
    import modules.mod_collect as mc
    for cm in enabled_collect_modules:
        logging.info(f"[+] Running module {cm}")
        current_module = cm.replace('enable_', '')
        logging.info(f"[+] Running module {current_module}")
        mod = getattr(mc, current_module)
        if not config[current_module]:
            config[current_module] = {}
        if config[current_module].get('own_thread', False):
            collect_thread = threading.Thread(
                target=mod,
                args=(
                    outdir,
                    config[current_module]
                )
            )
            collect_thread.start()
            threads.append(collect_thread)
        else:
            mod(outdir, config[current_module])
    return threads

def run_capture_modules(enabled_capture_modules, outdir, config, interfaces="", threads=[], disk="", host=""):
    logging.info("[+] Running capture modules")
    import modules.mod_capture as mcap
    for cm in enabled_capture_modules:
        current_module = cm.replace('enable_', '')
        logging.info(f"[+] Running module {current_module}")
        if not config[current_module]:
            config[current_module] = {}
        if interfaces:
            config[current_module]['interfaces'] = interfaces.strip().split(',')
        if disk:
            config[current_module]['disk'] = disk
        if host:
            config[current_module]['host'] = host
        mod = getattr(mcap, current_module)
        if config[current_module].get('own_thread', False):
            capture_thread = threading.Thread(
                target=mod,
                args=(
                    outdir,
                    config[current_module]
                )
            )
            capture_thread.start()
            threads.append(capture_thread)
        else:
            mod(outdir, config[current_module])
    return threads

def main(args):
    config = load_config(args.config)
    validate_config(args, config)
    dir_timestamp =  datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = os.path.join(config['outdir'], dir_timestamp)
    os.makedirs(outdir, exist_ok=True)
    threads = []
    if args.capture:
        config_mod_capture = config['modules']['capture']
        enabled_capture_modules = {
            k: v for k, v in config['modules']['capture'].items()
            if k.startswith("enable_") and v
        }
        threads = threads + run_capture_modules(enabled_capture_modules, outdir, config_mod_capture, interfaces=args.interfaces, disk=args.disk, host=args.disk_host)
    if args.collect:
        enabled_collect_modules = {
            k: v for k, v in config['modules']['collect'].items()
            if k.startswith("enable_") and v
        }
        config_mod_collect = config['modules']['collect']
        threads = threads + run_collect_modules(enabled_collect_modules, outdir, config_mod_collect)
    for thread in threads:
        logging.info("[+] Waiting jobs to finish")
        thread.join()
    if config['compress_collection']:
        import lib.collection as lc
        logging.info("[+] Compressing collection")
        lc.compress(config['outdir'], dir_timestamp)

def parse_args():
    parser = argparse.ArgumentParser(
        description="CollectiFOR | quick triage collection"
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

    parser.add_argument(
        "-dh", "--disk-host",
        required=False,
        help='Target host for disk capture. <str>@<str> assumes live capture over ssh. "localhost", "127.0.0.1", or "" assumes local disk.'
    )

    parser.add_argument(
        "-d", "--disk",
        required=False,
        help="Disk to capture. E.g. /dev/sda"
    )

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = parse_args()
    main(args)
