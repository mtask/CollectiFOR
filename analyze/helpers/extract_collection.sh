#!/bin/bash

if [ $# -lt 1 ]; then
    echo "./extract_collection.sh PATH_TO_COLLECTION"
    exit 0
fi

COLLECTION="$1"

if file "$COLLECTION" | grep -q "gzip compressed data"; then
   echo "Extracting collection..."
   python3 -c "import lib.collection as lc;lc.decompress(\"$COLLECTION\")"
   DATA=$(realpath "$(echo $COLLECTION|sed 's/.tar.gz//g')")
   echo "Collection extracted -> $DATA"
fi
