import os
import json
import re
import yara
import magic
import hashlib
import pwd
import logging
from pathlib import Path
from lib.finding import new_finding
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

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


def _get_file_data(fp, requested_fields=None):
    """
    Compute only the fields requested (optimization for huge datasets)
    """
    if requested_fields is None:
        requested_fields = {"filename", "filepath", "extension", "filetype", "md5", "owner"}

    d = {}
    if "filename" in requested_fields:
        d["filename"] = os.path.basename(fp)
    if "filepath" in requested_fields:
        d["filepath"] = fp
    if "extension" in requested_fields:
        d["extension"] = os.path.splitext(fp)[1]
    if "filetype" in requested_fields:
        d["filetype"] = _detect_file_signature(fp)
    if "md5" in requested_fields:
        try:
            h = hashlib.md5()
            with open(fp, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            d["md5"] = h.hexdigest()
        except Exception:
            d["md5"] = ""
    if "owner" in requested_fields:
        d["owner"] = _get_file_owner(fp)
    return d


# ===============================================================
# YARA Rule Processing
# ===============================================================

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
    logging.info(f"[+] Rule compiling ready, {len(list(rules))} loaded")
    return rules, externals_needed


# ===============================================================
# File traversal generator
# ===============================================================

def walk_files(target_path, exclude_dirs=None, include_dirs=None):
    """
    Lazily yield files under target_path.
    exclude_dirs/include_dirs are substrings to match anywhere in the path.
    """
    if exclude_dirs is None:
        exclude_dirs = []
    if include_dirs is None:
        include_dirs = []

    for f in Path(target_path).rglob("*"):
        fp = str(f.resolve())

        # Skip files in any excluded directory
        if exclude_dirs and any(excl in fp for excl in exclude_dirs):
            logging.debug(f"[-] Skipping path {fp}")
            continue

        # Skip files not in any included directory (if include_dirs specified)
        if include_dirs and not any(inc in fp for inc in include_dirs):
            logging.debug(f"[-] Skipping path {fp}")
            continue

        if f.is_file() and not f.is_symlink():
            yield fp


# ===============================================================
# Scan Execution (per file)
# ===============================================================

def _scan_file(fp, rules, externals_needed):
    """
    Scan a single file with YARA, return list of findings
    """
    externals = _get_file_data(fp, requested_fields=externals_needed)
    active_externals = {k: externals.get(k, "") for k in externals_needed}

    try:
        matches = rules.match(fp, externals=active_externals)
    except yara.Error:
        return []

    findings = []
    for m in matches:
        finding = new_finding()
        finding['type'] = 'yara'
        finding['message'] = f'Rule "{m.rule}" matched in file "{fp}"'
        finding['rule'] = m.rule
        finding['namespace'] = m.namespace
        finding['tags'] = ', '.join(m.tags)
        finding['strings'] = str(m.strings)
        finding['meta'] = dict(m.meta)
        finding['artifact'] = fp

        # store string instances in meta
        for s in m.strings:
            if "string_instances" not in finding['meta']:
                finding['meta']['string_instances'] = {}
            finding['meta']['string_instances'].setdefault(str(s.identifier), [])
            for i in s.instances:
                finding['meta']['string_instances'][str(s.identifier)].append(str(i))
        findings.append(finding)
    return findings


# ===============================================================
# PUBLIC ENTRYPOINT (threaded/lazy)
# ===============================================================

def search(rules_dir, target_path, max_workers=4, exclude_dirs=[], include_dirs=[]):
    """
    Scans a target path using YARA rules in rules_dir.
    Threaded + lazy traversal for large datasets.
    """
    # Gather YARA rule files
    rule_files = [str(r) for r in Path(rules_dir).rglob("*.yar")]
    if not rule_files:
        return []

    rules, externals_needed = _compile_rule_set(rule_files)
    findings = []

    # Use ThreadPoolExecutor to parallelize per-file scanning
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_scan_file, fp, rules, externals_needed): fp for fp in walk_files(target_path, exclude_dirs=exclude_dirs, include_dirs=include_dirs)}

        for future in as_completed(futures):
            try:
                file_findings = future.result()
                findings.extend(file_findings)
            except Exception as e:
                logging.warning(f"Skipping file {futures[future]} due to error: {e}")

    logging.info(f"[+] {len(findings)} findings from YARA check")
    return findings

