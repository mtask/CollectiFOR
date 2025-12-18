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
   echo "Extracting collection..."
   python3 -c "import lib.collection as lc;lc.decompress(\"$COLLECTION\")"
   DATA=$(realpath "$(echo $COLLECTION|sed 's/.tar.gz//g')")
   echo "Collection extracted -> $DATA"
else
    DATA=$(realpath "$COLLECTION")
fi

if ! [[ -d $DATA ]]
then
   echo "[-] Invalid collection path: $COLLECTION"
fi

echo "[+] Mounting $DATA -> /data"
echo "[+] Mounting $OUTDIR -> /out"
echo "[+] Running log2timeline/plaso"

docker run --rm -ti --user 0 -w /out -v $DATA:/data:ro -v $OUTDIR:/out --entrypoint /bin/bash log2timeline/plaso
