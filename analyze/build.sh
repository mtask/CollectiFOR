#!/bin/bash

pyinstaller \
  --onefile \
  --paths=. \
  --add-data "viewer/templates:viewer/templates" \
  --add-data "viewer/static:viewer/static" \
  collectifor.py

