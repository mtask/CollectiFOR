#!/bin/bash

if [ $# -lt 2 ]; then
    echo "./plaso.sh PATH_TO_COLLECTION PATH_TO_OUTPUT_DIR"
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
    DATA=$(realpath "$COLLECTION")/files_and_dirs/
fi

if ! [[ -d $DATA ]]
then
   echo "[-] Invalid collection path: $COLLECTION"
fi

echo "[+] Running log2timeline against collection: $COLLECTION"
echo "[+] Storing log2timeline results: $OUTDIR"

docker run --rm --user 0 -v $DATA:/data:ro -v $OUTDIR:/out log2timeline/plaso log2timeline --storage-file /out/evidences.plaso /data/
#csv: docker run --rm --user 0 -v $OUTDIR:/data log2timeline/plaso psort.py -o l2tcsv -w /data/timeline.csv /data/evidences.plaso
docker run --rm --user 0 -v $OUTDIR:/data log2timeline/plaso psort.py -w /data/timeline.log /data/evidences.plaso
echo "[+] For further analysis with plaso run:"
echo "docker run -ti --rm --user 0 -v $OUTDIR:/data --entrypoint /bin/bash log2timeline/plaso"
