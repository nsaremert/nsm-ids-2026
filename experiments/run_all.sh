#!/usr/bin/env bash
# run_all.sh — reproduce every technical-validation experiment (E1-E6) for the
# NSM-IDS-2026 Sensors Data Descriptor. Outputs: experiments/{results,figures,tables}/.
# Deterministic (fixed seeds in common.py / results/seeds.json). No data is modified.
#
#   bash experiments/run_all.sh
#
# E7 (CICIDS2017 compatibility/transfer) is optional and skipped unless the CICIDS2017
# MachineLearningCVE CSVs are present — see experiments/E7_cicids_compat/README.md.
set -uo pipefail
cd "$(dirname "$0")/.."
PY="./.venv/bin/python"
[ -x "$PY" ] || PY=python3

for e in E1_describe/e1.py \
         E2_cross_session/e2.py \
         E3_protocol/e3.py \
         E4_fix_validation/e4.py \
         E5_feature_analysis/e5.py \
         E6_host_modality/e6.py; do
  echo "######## RUN $e  $(date +%H:%M:%S) ########"
  $PY "experiments/$e" || { echo "  ! $e FAILED"; }
done

E7=experiments/E7_cicids_compat/e7.py
if [ -f "$E7" ]; then
  echo "######## RUN E7 (CICIDS2017) ########"; $PY "$E7" || echo "  ! E7 FAILED"
else
  echo "E7 (CICIDS2017) skipped — see experiments/E7_cicids_compat/README.md"
fi
echo "######## run_all DONE  $(date +%H:%M:%S) ########"
