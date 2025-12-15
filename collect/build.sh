#!/usr/bin/env bash
set -euo pipefail

docker run --rm -t \
  -v "$PWD:/src" \
  -w /src \
  quay.io/pypa/manylinux_2_34_x86_64 \
  bash -c '
    set -e

    # Install Python 3.12 with development headers (provides libpython3.12.so)
    yum install -y python3.12 python3.12-devel gcc wget

    PYTHON=/usr/bin/python3.12

    # Bootstrap pip
    wget https://bootstrap.pypa.io/get-pip.py -O /tmp/get-pip.py
    $PYTHON /tmp/get-pip.py

    # Upgrade pip
    $PYTHON -m pip install --upgrade pip

    # Install dependencies
    $PYTHON -m pip install -r requirements.txt

    # Install PyInstaller
    $PYTHON -m pip install pyinstaller

    # Clean previous builds
    rm -rf build dist *.spec

    # Build one-file executable
    $PYTHON -m PyInstaller --onefile --paths=. collect.py
  '

