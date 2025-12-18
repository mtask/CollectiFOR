#!/bin/bash
set -euo pipefail

MOUNT_BASE="/mnt/forensic"
STATE_FILE="/tmp/forensic_mounts.state"

usage() {
    cat <<EOF
Usage:
  $0 <disk_image>
  $0 --cleanup

Features:
  - Works with raw disk images (with or without boot flags)
  - Detects partitions using parted (machine-readable)
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
    while read -r mountpoint loopdev; do
        if mountpoint -q "$mountpoint"; then
            echo "[-] Unmounting $mountpoint"
            umount "$mountpoint"
        fi
        if losetup "$loopdev" &>/dev/null; then
            echo "[-] Detaching $loopdev"
            losetup -d "$loopdev"
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

    IMAGE=$(realpath "$1")
    [[ ! -f "$IMAGE" ]] && { echo "[!] Image not found"; exit 1; }
    if [[ "$IMAGE" == *.gz ]]; then
    echo "[*] Extracting $IMAGE"
        EXTRACTED="${IMAGE%.gz}"
        gzip -dk "$IMAGE"   # -d = decompress, -k = keep original
        IMAGE="$EXTRACTED"
    fi
    mkdir -p "$MOUNT_BASE"
    : > "$STATE_FILE"

    # --- Parse partitions using parted ---
    echo "[*] Detecting partitions..."
    mapfile -t PARTS < <(
        parted -m "$IMAGE" unit s print | awk -F: '/^[0-9]+:/ {print $1":"$2":"$5}'
    )

    if [[ ${#PARTS[@]} -eq 0 ]]; then
        echo "[!] No partitions found in image"
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
        # Remove trailing 's' from parted units
        start=${start%s}
        offset=$((start * 512))

        label="$(basename "$IMAGE")-p$num"
        mnt="$MOUNT_BASE/$label"
        mkdir -p "$mnt"

        loopdev=$(losetup --find --read-only --show --offset "$offset" "$IMAGE")
        mount -o ro "$loopdev" "$mnt"

        echo "$mnt $loopdev" >> "$STATE_FILE"
        echo "[+] Mounted partition $num at $mnt"
    done

    echo "[*] All selected partitions mounted"
    echo "[*] Run '$0 --cleanup' when finished"
}

main "$@"

