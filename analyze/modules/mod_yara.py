# modules/mod_yara.py
import os
import json
import re
import yara
import magic
import hashlib
import pwd
import logging
from lib.finding import new_finding
from pathlib import Path

# ===============================================================
# Helpers
# ===============================================================

def _get_file_owner(fp):
    try:
        st = os.stat(fp)
        return pwd.getpwuid(st.st_uid).pw_name
    except Exception:
        return ""


def _detect_file_signature(fp, num_bytes=16):
    try:
        with open(fp, "rb") as f:
            header = f.read(num_bytes)
        hex_sig = " ".join(f"{b:02X}" for b in header)

        filetype = magic.from_file(fp)

        return f"{hex_sig};{filetype}"
    except Exception:
        return ""


def _get_file_data(fp):
    d = {}
    d["filename"] = os.path.basename(fp)
    d["filepath"] = fp
    d["extension"] = os.path.splitext(fp)[1]
    d["filetype"] = _detect_file_signature(fp)

    try:
        with open(fp, "rb") as f:
            d["md5"] = hashlib.md5(f.read()).hexdigest()
    except Exception:
        d["md5"] = ""

    d["owner"] = _get_file_owner(fp)
    return d


# ===============================================================
# YARA Rule Processing
# ===============================================================

# Detect which externals a YARA rule references
EXT_PATTERN = re.compile(
    r'\b(filename|filepath|extension|filetype|md5|owner)\b'
)

def _detect_externals_in_string(rule_text):
    return set(m.group(1) for m in EXT_PATTERN.finditer(rule_text))


def _compile_rule_set(rule_files):
    """
    Auto-detect externals and compile all rules as a single YARA database.
    """
    filepaths_map = {}
    externals_needed = set()

    for i, rf in enumerate(rule_files):
        filepaths_map[f"rule_{i}"] = rf

        try:
            txt = Path(rf).read_text(errors="ignore")
        except Exception:
            txt = ""

        externals_needed.update(_detect_externals_in_string(txt))

    # Provide dummy externals that will be overridden per-file
    externals_dict = {ext: "" for ext in externals_needed}
    logging.info("[+] Compiling rules")
    rules = yara.compile(
        filepaths=filepaths_map,
        externals=externals_dict
    )

    logging.info("[+] Rule compiling ready")
    return rules, externals_needed


# ===============================================================
# Scan Execution
# ===============================================================

def _run_yara(rules, file_list, externals_needed):
    findings = []

    for filepath, externals in file_list:
        # Populate EXTERNAL variables dynamically
        active_externals = {
            key: externals.get(key, "")
            for key in externals_needed
        }

        try:
            matches = rules.match(filepath, externals=active_externals)
        except yara.Error:
            continue

        for m in matches:
            finding = new_finding()
            finding['type'] = 'yara'
            finding['message'] = f'Rule "{m.rule}" matched in file "{filepath}"'
            finding['rule'] = m.rule
            finding['namespace'] = m.namespace
            finding['tags'] = ', '.join(m.tags)
            finding['strings'] = str(m.strings)
            finding['meta'] = dict(m.meta)
            finding['artifact'] = filepath
            findings.append(finding)
            """
            all_matches.append({
                "rule":      m.rule,
                "namespace": m.namespace,
                "tags":      m.tags,
                "meta":      dict(m.meta),
                "strings":   str(m.strings),
                "filepath":  filepath
            })
            """

    return findings


# ===============================================================
# PUBLIC ENTRYPOINT
# ===============================================================

def search(rules_dir, target_path):
    """
    Main scanning interface.
    - Recursively collects files
    - Preloads metadata
    - Compiles YARA rule set
    - Runs match evaluation
    """

    # Collect files
    file_list = []

    if os.path.isfile(target_path):
        externals = _get_file_data(target_path)
        file_list.append([target_path, externals])

    elif os.path.isdir(target_path):
        for f in Path(target_path).rglob("*"):
            f = str(f)
            if os.path.isfile(f) and not os.path.islink(f):
                externals = _get_file_data(f)
                file_list.append([f, externals])

    # Gather YARA rule files
    rule_files = [str(r) for r in Path(rules_dir).rglob("*.yar")]

    if not rule_files:
        return []

    # Compile rule set with auto external detection
    rules, externals_needed = _compile_rule_set(rule_files)

    # Run scanning
    return _run_yara(rules, file_list, externals_needed)

