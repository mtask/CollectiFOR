#!/usr/bin/env python3

import csv
import os
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# Output directory
OUTPUT_DIR = "source/yara/threatfox/"

# Supported hash algorithms
SUPPORTED_HASHES = {"md5", "sha1", "sha256"}

# Supported non-hash IOCs
SUPPORTED_IOCS = {"domain", "ip:port", "url"}

# Maximum number of IOCs per rule to avoid huge rules
MAX_IOCS_PER_RULE = 50


def yara_safe(value: str) -> str:
    value = value.lower().strip() or "unknown"
    value = re.sub(r"[^a-z0-9_]", "_", value)
    value = re.sub(r"_+", "_", value)
    return value.strip("_")


def normalize_family(fk_malware: str, printable: str) -> str:
    if fk_malware and fk_malware.lower() != "none":
        return fk_malware.split(".")[-1]
    if printable:
        return printable
    return "unknown"


def detect_ioc_type(ioc_type: str) -> str | None:
    ioc_type = ioc_type.lower()
    if ioc_type.endswith("_hash"):
        algo = ioc_type.replace("_hash", "")
        if algo in SUPPORTED_HASHES:
            return algo
    elif ioc_type in SUPPORTED_IOCS:
        return ioc_type
    return None


def parse_csv(csv_path: Path):
    """Parse ThreatFox CSV and yield IOC entries with metadata."""
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.reader(f, skipinitialspace=True)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            try:
                ioc_value = row[2].strip()
                ioc_type = row[3].strip().lower()
                fk_malware = row[5].strip()
                malware_printable = row[7].strip()
            except IndexError:
                continue

            kind = detect_ioc_type(ioc_type)
            if not kind:
                continue

            yield {
                "value": ioc_value,
                "type": kind,
                "family": normalize_family(fk_malware, malware_printable),
                "printable": malware_printable or fk_malware or "Unknown",
            }


def chunk_list(lst, size):
    for i in range(0, len(lst), size):
        yield lst[i:i + size]


def generate_family_rules(family: str, grouped_iocs: dict):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    rules = []

    # Separate hashes and non-hash IOCs
    hash_iocs = {k: grouped_iocs[k] for k in grouped_iocs if k in SUPPORTED_HASHES}
    non_hash_iocs = {k: grouped_iocs[k] for k in grouped_iocs if k in SUPPORTED_IOCS}

    all_non_hash = [e for v in non_hash_iocs.values() for e in v]
    all_hash = [e for v in hash_iocs.values() for e in v]

    # Skip family if empty
    if not all_non_hash and not all_hash:
        return ""

    # Add hash import if needed
    if all_hash:
        rules.append('import "hash"\n')

    # Split large lists into chunks
    hash_chunks = list(chunk_list(all_hash, MAX_IOCS_PER_RULE)) or [[]]
    non_hash_chunks = list(chunk_list(all_non_hash, MAX_IOCS_PER_RULE)) or [[]]
    max_chunks = max(len(hash_chunks), len(non_hash_chunks))

    for i in range(max_chunks):
        rule_hash_chunk = hash_chunks[i] if i < len(hash_chunks) else []
        rule_non_hash_chunk = non_hash_chunks[i] if i < len(non_hash_chunks) else []

        # Skip empty rules
        if not rule_hash_chunk and not rule_non_hash_chunk:
            continue

        suffix = f"_{i}" if max_chunks > 1 else ""
        rule_name = f"ThreatFox_{yara_safe(family)}{suffix}"

        rule_lines = [
            f"rule {rule_name}",
            "{",
            "    meta:",
            f'        family = "{family}"',
            '        source = "ThreatFox"',
            f'        generated = "{now}"'
        ]

        strings_lines = []
        condition_lines = []

        # Non-hash IOCs → strings
        for idx, e in enumerate(rule_non_hash_chunk):
            clean_value = e["value"].replace('"', '\\"')
            strings_lines.append(f'    $ioc{idx} = "{clean_value}" nocase')
        if strings_lines:
            rule_lines.append("\n    strings:")
            rule_lines.extend(strings_lines)
            condition_lines.append("any of ($ioc*)")

        # Hash IOCs → condition
        for e in rule_hash_chunk:
            condition_lines.append(f'hash.{e["type"]}(0, filesize) == "{e["value"].lower()}"')

        # Build condition
        rule_lines.append("\n    condition:")
        rule_lines.append("        " + " or\n        ".join(condition_lines))

        rule_lines.append("}")
        rules.append("\n".join(rule_lines))

    return "\n\n".join(rules)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <threatfox.csv>", file=sys.stderr)
        sys.exit(1)

    csv_path = Path(sys.argv[1])
    if not csv_path.is_file():
        print(f"File not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    families = defaultdict(lambda: defaultdict(list))
    for entry in parse_csv(csv_path):
        families[entry["family"]][entry["type"]].append(entry)

    for family, types in families.items():
        yara_text = generate_family_rules(family, types)
        if yara_text.strip():  # Only write non-empty rules
            output_file = Path(OUTPUT_DIR) / f"{yara_safe(family)}.yar"
            output_file.write_text(yara_text, encoding="utf-8")
            print(f"[+] Wrote {output_file}")


if __name__ == "__main__":
    main()

