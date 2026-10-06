#!/usr/bin/env bash
# Reproduces every number, table and figure in the paper.
set -euo pipefail
export PYTHONPATH="$(pwd)"
CFG=${1:-configs/default.yaml}
python experiments/prepare.py   "$CFG"
python experiments/label_counts.py "$CFG"
python experiments/detection.py "$CFG"
python experiments/collab.py    "$CFG"
python experiments/overhead.py  "$CFG"
python experiments/make_architecture.py
python experiments/make_figures.py
