#!/usr/bin/env bash
# 01 recon_scan — nmap SYN + servis sürüm taraması (attacker'da çalışır)
set -uo pipefail
VIC="${1:-10.10.10.30}"
echo "[recon] nmap -sS -sV -T4 --top-ports 1000 $VIC"
if sudo -n nmap -sS -sV -T4 --top-ports 1000 "$VIC"; then :; else
  echo "[recon] (sudo/-sS olmadı, -sT connect scan'e düşülüyor)"
  nmap -sT -sV -T4 --top-ports 1000 "$VIC" || true
fi
echo "[recon] done"
