#!/bin/bash
set -euo pipefail

MOUNT_BASE="/mnt/forensic"
STATE_FILE="/tmp/forensic_mounts.state"

usage() {
    cat <<EOF
Usage:
  $0 <E01_image>
  $0 --cleanup

Features:
  - Works with E01 images
  - Uses ewfmount to expose raw disk
  - Detects partitions using parted
  - Mounts selected partition(s) read-only
  - Tracks mounts for easy cleanup
EOF
    exit 1
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "[!] Must be run as root"
        exit 1
    fi
}

cleanup() {
    echo "[*] Cleaning up mounted partitions..."
    if [[ ! -f "$STATE_FILE" ]]; then
        echo "[!] No mounts found"
        exit 0
    fi
    while read -r mountpoint loopdev ewf_mount; do
        if mountpoint -q "$mountpoint"; then
            echo "[-] Unmounting $mountpoint"
            umount "$mountpoint" && rm -rf "$mountpoint"
        fi
        if losetup "$loopdev" &>/dev/null; then
            echo "[-] Detaching $loopdev"
            losetup -d "$loopdev"
        fi
        if mountpoint -q "$ewf_mount"; then
            echo "[-] Unmounting EWF mount $ewf_mount"
            umount "$ewf_mount"
        fi
    done < "$STATE_FILE"
    rm -f "$STATE_FILE"
    echo "[+] Cleanup complete"
    exit 0
}

main() {
    require_root
    [[ $# -eq 0 ]] && usage
    [[ "$1" == "--cleanup" ]] && cleanup

    E01=$(realpath "$1")
    [[ ! -f "$E01" ]] && { echo "[!] E01 image not found"; exit 1; }
    echo -e "Image information:\n $(ewfinfo $E01)"
    mkdir -p "$MOUNT_BASE"
    : > "$STATE_FILE"

    # --- Mount E01 using ewfmount ---
    EWF_MNT=$(mktemp -d)
    ewfmount "$E01" "$EWF_MNT"
    echo "[*] E01 mounted at $EWF_MNT"

    # --- Detect partitions using parted ---
    echo "[*] Detecting partitions..."
    mapfile -t PARTS < <(
        parted -m "$EWF_MNT"/ewf1 unit s print | awk -F: '/^[0-9]+:/ {print $1":"$2":"$5}'
    )

    if [[ ${#PARTS[@]} -eq 0 ]]; then
        echo "[!] No partitions found in E01"
        exit 1
    fi

    echo "Available partitions:"
    for idx in "${!PARTS[@]}"; do
        IFS=":" read -r num start sectors <<<"${PARTS[$idx]}"
        echo "[$((idx+1))] Partition $num: start=$start, sectors=$sectors"
    done

    echo -n "[*] Enter partition numbers to mount (e.g., 1 2): "
    read -r -a SEL

    for sel in "${SEL[@]}"; do
        idx=$((sel-1))
        if [[ $idx -lt 0 || $idx -ge ${#PARTS[@]} ]]; then
            echo "[!] Invalid selection: $sel"
            continue
        fi

        IFS=":" read -r num start sectors <<<"${PARTS[$idx]}"
        start=${start%s}
        offset=$((start * 512))

        label="$(basename "$E01")-p$num"
        mnt="$MOUNT_BASE/$label"
        mkdir -p "$mnt"

        loopdev=$(losetup --find --read-only --show --offset "$offset" "$EWF_MNT/ewf1")
        mount -o ro "$loopdev" "$mnt"

        echo "$mnt $loopdev $EWF_MNT" >> "$STATE_FILE"
        echo "[+] Mounted partition $num at $mnt"
    done

    echo "[*] All selected partitions mounted"
    echo "[*] Run '$0 --cleanup' when finished"
}

main "$@"

