#!/bin/bash

if [ $# -lt 2 ]; then
    echo "./zeek.sh PATH_TO_COLLECTION PATH_TO_OUTPUT_DIR"
    echo "Output directory is created if it does not exist"
    exit 0
fi

COLLECTION="$1"
OUTDIR=$(realpath "$2")

mkdir -p "$OUTDIR"

if file "$COLLECTION" | grep -q "gzip compressed data"; then
    parent_dir=$(dirname "$COLLECTION")
    filename=$(basename "$COLLECTION")
    top_dir=${filename#*_}
    top_dir=${top_dir%.tar.gz}
    extracted_dir="$parent_dir/$top_dir"
    tar -xzf "$COLLECTION" -C "$parent_dir"
    echo "Extracted directory: $extracted_dir"
    DATA=$(realpath "$extracted_dir")
else
    DATA=$(realpath "$COLLECTION")
fi

if ! [[ -d $DATA ]]
then
   echo "[-] Invalid collection path: $COLLECTION"
fi

PCAP=$(ls $DATA/capture/*.pcap | head -n 1)

echo "[+] Running zeek against pcap: $PCAP"
echo "[+] Storing results: $OUTDIR"

docker run --rm \
    -v "$DATA":/data:ro \
    -v "$OUTDIR":/out \
    -w /out \
    zeek/zeek \
    zeek -r /data/capture/$(basename "$PCAP")
