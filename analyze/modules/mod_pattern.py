import subprocess
import os
import json
import glob
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.finding import new_finding
from pathlib import Path

def search(patterns_dir, target, recursive=True, max_threads=4):
    pattern_files = [
        f
        for f in glob.glob(os.path.join(patterns_dir, "**/*.txt"), recursive=True)
        if os.path.isfile(f)
    ]

    def worker(pattern_file):
        results = match(pattern_file, target, recursive=recursive)
        return results

    merged = []   # final merged results

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(worker, pf): pf for pf in pattern_files}

        for future in as_completed(futures):
            results = future.result()
            merged = merged + results
    return merged



def match(pattern_source, target, recursive=True):
    """
    Use system grep (fgrep -F) to search patterns much faster than Python.
    Returns:
        list: [findings...]
    """

    # Ensure patterns file exists
    if not os.path.isfile(pattern_source):
        raise FileNotFoundError(f"Pattern file '{pattern_source}' not found")

    findings = []

    # ------------------------------------------------------------------
    # Build base grep command
    # ------------------------------------------------------------------

    # fgrep (-F) = literal fixed string matches (fastest)
    base_cmd = ["grep", "-F", "-o", "-f", pattern_source]

    if recursive and os.path.isdir(target):
        # -R recursive, -n include filename automatically
        cmd = base_cmd + ["-r", target]
    else:
        cmd = base_cmd + [target]

    # ------------------------------------------------------------------
    # Execute grep
    # ------------------------------------------------------------------
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="ignore"
        )
    except Exception as e:
        raise RuntimeError(f"Failed to execute grep: {e}")

    # grep exit code 1 = “no matches found” → return empty dict
    if proc.returncode == 1:
        return []

    if proc.returncode not in (0, 1):
        if "Permission denied" in str(proc.stderr):
            logging.warning(f"All files could not be accessed with the current privileges")
        else:
            logging.error(f"grep error: {repr(proc.stderr)}")

    # ------------------------------------------------------------------
    # Parse grep output:
    #   When recursive:      /path/to/file:match
    #   When single file:    match
    # ------------------------------------------------------------------

    for line in proc.stdout.splitlines():
        finding = new_finding()
        # Recursive grep prefix
        if ":" in line and recursive:
            filepath, match = line.split(":", 1)
        else:
            filepath = target
            match = line
        finding['type'] = 'pattern'
        finding['message'] = f'Pattern "{match}" matched in file {filepath}'
        finding['indicator'] = str(match)
        finding['source_file'] = str(pattern_source)
        finding['artifact'] = str(filepath)
        findings.append(finding)
    return findings

