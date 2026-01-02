import os
import argparse
from lib.collection import decompress
from lib.hash import get_sha1, get_sha256, get_md5
from pathlib import Path

HASH_FUNC_MAP = {
    "sha256": get_sha256,
    "sha1": get_sha1,
    "md5": get_md5
}

def red(text):
    return f"\033[31m{text}\033[0m"

def check_print(check):
    print(f"""\033[32m
############################
[CHECK] {check}
############################
\033[0m""")

def get_dirs(c1, c2):
    if c1.endswith(".tar.gz"):
        try:
            c1_dir = decompress(c1)
        except Exception as e:
            logging.error(f"Failed to decompress archive: {e}")
            sys.exit(1)
    else:
        c1_dir = c1
    if c2.endswith(".tar.gz"):
        try:
            c2_dir = decompress(c2)
        except Exception as e:
            logging.error(f"Failed to decompress archive: {e}")
            sys.exit(1)
    else:
        c2_dir = c2

    return c1,c2

def files_and_dirs(c1, c2, seen, alg="sha256"):
    c1fd = os.path.join(c1, "files_and_dirs")
    c2fd = os.path.join(c2, "files_and_dirs")
    if not os.path.isdir(c1fd) and not os.path.isdir(c2fd):
        print("[-] No files_and_dirs for both collections found.")
        return
    root1 = Path(c1fd)
    root2 = Path(c2fd)
    for f in root1.rglob("*"):
        if not os.path.isfile(f):
            continue
        rel_to_c = f.relative_to(root1)
        if os.path.isfile(c2fd / rel_to_c):
            if rel_to_c in seen:
                continue
            seen.append(rel_to_c)
            c1_hash = HASH_FUNC_MAP[alg](c1fd / rel_to_c)
            c2_hash = HASH_FUNC_MAP[alg](c2fd / rel_to_c)
            if c1_hash != c2_hash:
                print(f'{red("[DIFF]")} "{rel_to_c}" - {c1_hash} ({Path(c1).name}) - {c2_hash} ({Path(c2).name})')
        else:
            print(f'{red("[DIFF]")} "{rel_to_c}" only in collection "{Path(c1).name}"')
    return seen

def checksums(c1, c2, alg="sha256"):
    def get_lines(path):
        d = {}
        with open(path) as f:
            for l in f:
                l = l.replace('\n', '')
                if l.strip() == "":
                    continue
                lc = l.split(' - ')
                d[lc[0]] = lc[1]
        return d
    c1c = os.path.join(c1, f"checksums/{alg}.txt")
    c2c = os.path.join(c2, f"checksums/{alg}.txt")
    if not os.path.isfile(f"{c1c}") and not os.path.isfile(f"{c2c}"):
        print(f"[-] No checksums/{alg}.txt for both collections found.")
        return
    c1_d = get_lines(c1c)
    c2_d = get_lines(c2c)
    # Keys in both
    for key in c1_d.keys() & c2_d.keys():  # intersection
        if c1_d[key] != c2_d[key]:
            print(f'{red("[DIFF]")} "{key}" - {c1_d[key]} ({Path(c1).name}) - {c2_d[key]} ({Path(c2).name})')

    # Keys only in c1_d
    for key in c1_d.keys() - c2_d.keys():  # difference
        print(f'{red("[DIFF]")} Path "{key}" only in "{Path(c1).name}"')

    # Keys only in c2_d
    for key in c2_d.keys() - c1_d.keys():
        print(f'{red("[DIFF]")} Path "{key}" only in "{Path(c2).name}"')

def run_checks(args):
    c1, c2 = get_dirs(args.collection1, args.collection2)
    ##################
    # files_and_dirs #
    #################
    check_print("files_and_dirs")
    seen = []
    seen = files_and_dirs(c1, c2, seen)
    files_and_dirs(c2, c1, seen, alg=args.alg)
    #######################
    # checksums/<alg>.txt #
    #######################
    check_print(f"checksums/{args.alg}.txt")
    checksums(c1,c2, alg=args.alg)

if __name__=="__main__":
    parser = argparse.ArgumentParser(
        description="Compare collections"
    )

    parser.add_argument(
        "-c",
        help="Path to collectifor.py's config.yaml",
    )
    parser.add_argument(
        "-alg",
        default="sha256",
        help="Algorithm (sha1, sha256, md5). Default sh256.",
    )
    parser.add_argument(
        "collection1",
        help="Path to first collection directory or .tar.gz archive",
    )
    parser.add_argument(
        "collection2",
        help="Path to second collection directory or .tar.gz archive",
    )
    args = parser.parse_args()
    run_checks(args)
