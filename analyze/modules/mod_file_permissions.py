# modules/mod_file_permissions.py
from pathlib import Path
from lib.finding import new_finding

# -----------------------------
# Helper functions
# -----------------------------

def _is_world_writable(mode_str):
    """Check if a permission string is world-writable, e.g., -rw-rw-rw-"""
    return len(mode_str) == 9 and mode_str[8] in "wx"

def _is_suid(mode_str):
    """Check if a file has the SUID bit set (4xxx)"""
    return len(mode_str) == 9 and mode_str[0] != 'd' and 's' in mode_str[2:3]

def _is_sgid(mode_str):
    """Check if a file has the SGID bit set (2xxx)"""
    return len(mode_str) == 9 and mode_str[0] != 'd' and 's' in mode_str[5:6]

def _mode_to_int(mode_str):
    """Convert string mode like '755' or '640' to integer"""
    try:
        return int(mode_str, 8)
    except Exception:
        return None

# -----------------------------
# Main analysis function
# -----------------------------

def analyze(rootdir):
    """
    Analyze file_permissions.txt and return a list of entries with:
    - Path
    - Mode
    - Owner
    - Group
    - Reason (world-writable, suid, sgid, etc.)
    """
    findings = []
    fp_file = Path(rootdir) / "file_permissions.txt"
    if not fp_file.exists():
        return findings

    with open(fp_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Expected format: path mode perms owner:group size timestamp
            # Example: /etc/gshadow- 640 -rw-r----- root:shadow 1172 1764100568.0
            parts = line.split()
            if len(parts) < 6:
                continue
            path, mode_num, perms, owner_group, size, timestamp = parts[:6]
            if perms.startswith('l'):
                continue
            owner, group = owner_group.split(":") if ":" in owner_group else (owner_group, "")
            reasons = []

            # Check numeric permissions
            mode_int = _mode_to_int(mode_num)
            if mode_int is not None:
                # SUID/SGID bits
                if mode_int & 0o4000:
                    reasons.append("SUID")
                if mode_int & 0o2000:
                    reasons.append("SGID")
                # World writable
                if mode_int & 0o002:
                    reasons.append("World-writable")
                # Owner-writable but not root?
                if owner != "root" and mode_int & 0o020:
                    reasons.append("Group writable")
                if owner != "root" and mode_int & 0o002:
                    reasons.append("Other writable")

            # Optional: check symbolic string mode as well
            if 's' in perms:
                reasons.append("SUID/SGID (string)")

            if reasons:
                finding = new_finding()
                finding['type'] = 'file permissions'
                finding['artifact'] = path
                finding['message'] = ", ".join(reasons)
                finding['meta'] = {
                                      "mode": mode_num,
                                      "perms": perms,
                                      "owner": owner,
                                      "group": group,
                                      "size": size,
                                      "timestamp": timestamp,
                                  }
                findings.append(finding)

    return findings
