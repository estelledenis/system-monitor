#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
python3 -m venv "$DIR/venv"
source "$DIR/venv/bin/activate"
pip install --upgrade pip
pip install -r "$DIR/requirements.txt"
python "$DIR/dashboard.py"
