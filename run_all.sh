#!/usr/bin/env bash
# run_all.sh — non-Make equivalent of the data + analysis flow (run from repo root).
# Assumes the isolated lab is already up (see testbed/ and `make testbed`).
#   ./run_all.sh [NAME] [N_SESSIONS]
set -uo pipefail
cd "$(dirname "$0")"
NAME="${1:-NSM-IDS-2026}"
N="${2:-12}"
PY="$([ -x ./.venv/bin/python ] && echo ./.venv/bin/python || echo python3)"

[ -f config.env ] || { echo "config.env yok — 'cp config.env.example config.env' ve düzenle."; exit 1; }

echo "### 1/5 CICFlowMeter image ###";      ./pipeline/setup_cicflowmeter.sh
echo "### 2/5 campaign ($N sessions) ###";  ./run_campaign.sh "$N"
echo "### 3/5 build dataset ###";           ./pipeline/build_cicids_dataset.sh "$NAME"
echo "### 4/5 verify labels ###";           $PY pipeline/verify_cicids_labels.py --full "dataset/${NAME}_full.csv" || true
echo "### 5/5 experiments ###";             bash experiments/run_all.sh
echo "### run_all DONE ###"
