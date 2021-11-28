#!/usr/bin/env bash

set -e
if command -v deactivate &> /dev/null; then
  deactivate
  rm -rf venv
fi
python3 -mvenv venv
source venv/bin/activate
pip3 install --upgrade pip
pip3 install wheel
pip3 install -r requirements.txt