import subprocess
import os
import glob
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

def search(patterns_dir, target, recursive=True, max_threads=4):
    pattern_files = [
        f
        for f in glob.glob(os.path.join(patterns_dir, "**/*.txt"), recursive=True)
        if os.path.isfile(f)
    ]

    def worker(pattern_file):
        results = match(pattern_file, target, recursive=recursive)
        return pattern_file, results  # return tuple

    merged = {}   # final merged results

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(worker, pf): pf for pf in pattern_files}

        for future in as_completed(futures):
            pattern_file, results = future.result()
            merged[pattern_file] = results
    return merged



def match(pattern_source, target, recursive=True):
    """
    Use system grep (fgrep -F) to search patterns much faster than Python.
    Returns:
        dict: { filepath: [matches...] }
    """

    # Ensure patterns file exists
    if not os.path.isfile(pattern_source):
        raise FileNotFoundError(f"Pattern file '{pattern_source}' not found")

    results = {}

    # ------------------------------------------------------------------
    # Build base grep command
    # ------------------------------------------------------------------

    # fgrep (-F) = literal fixed string matches (fastest)
    base_cmd = ["grep", "-F", "-o", "-f", pattern_source]

    if recursive and os.path.isdir(target):
        # -R recursive, -n include filename automatically
        cmd = base_cmd + ["-R", target]
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
        return {}

    if proc.returncode not in (0, 1):
        if "Permission denied" in str(proc.stderr):
            print(f"All files could not be accessed with the current privileges")
        else:
            raise RuntimeError(f"grep error: {proc.stderr}")

    # ------------------------------------------------------------------
    # Parse grep output:
    #   When recursive:      /path/to/file:match
    #   When single file:    match
    # ------------------------------------------------------------------

    for line in proc.stdout.splitlines():
        # Recursive grep prefix
        if ":" in line and recursive:
            filepath, match = line.split(":", 1)
        else:
            filepath = target
            match = line

        results.setdefault(filepath, []).append(match)

    return results

