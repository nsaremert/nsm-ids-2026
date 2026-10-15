#!/usr/bin/env bash
# =============================================================================
# stop_capture.sh — yakalamayı düzgünce durdurur, logları flush eder, çıktıları
# çağıran kullanıcıya chown eder (pipeline user olarak okuyabilsin).
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source ./config.env 2>/dev/null || true
export LC_ALL=C
IFACE="${CAPTURE_IFACE:-virbr-ids}"

STATE="data/.capture_state"
[ -f "$STATE" ] || { echo "Durum dosyası yok ($STATE) — yakalama çalışmıyor olabilir."; exit 0; }
# shellcheck disable=SC1091
source "$STATE"

if [ "$(id -u)" -ne 0 ]; then exec sudo -E "$0"; fi

echo "==> Yakalama durduruluyor (TS=$TS)"
# SIGINT → tcpdump/suricata/zeek logları flush edip kapanır
for pidvar in TCPDUMP_PID SURICATA_PID ZEEK_PID; do
  pid="${!pidvar:-}"
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    kill -INT "$pid" 2>/dev/null || true
    echo "   $pidvar=$pid → SIGINT"
  fi
done

# kapanmaları için bekle (en çok 15 sn)
for _ in $(seq 1 15); do
  still=0
  for pidvar in TCPDUMP_PID SURICATA_PID ZEEK_PID; do
    pid="${!pidvar:-}"; [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && still=1
  done
  [ "$still" -eq 0 ] && break
  sleep 1
done
# inatçı kalanları TERM/KILL
for pidvar in TCPDUMP_PID SURICATA_PID ZEEK_PID; do
  pid="${!pidvar:-}"; [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && { kill -TERM "$pid" 2>/dev/null; sleep 1; kill -KILL "$pid" 2>/dev/null || true; }
done

# SON ÇARE: PID tutmadıysa (yetim/systemd'ye devrolmuş, tcpdump kullanıcısına
# düşmüş vb.) yakalayıcıları ARAYÜZE GÖRE öldür. Yalnız bu lab arayüzünü hedefler.
for patt in "tcpdump -i $IFACE" "zeek -i $IFACE" "suricata -i $IFACE"; do
  pkill -INT -f "$patt" 2>/dev/null || true
done
sleep 2
for patt in "tcpdump -i $IFACE" "zeek -i $IFACE" "suricata -i $IFACE"; do
  pkill -KILL -f "$patt" 2>/dev/null || true
done
LEFT=$(pgrep -f "(tcpdump|zeek|suricata) -i $IFACE" 2>/dev/null | wc -l)
[ "$LEFT" -eq 0 ] && echo "   tüm yakalayıcılar durdu ✓" || echo "   UYARI: $LEFT yakalayıcı hâlâ çalışıyor ($IFACE)"

# çıktıları çağıran kullanıcıya ver
if [ -n "${OWNER:-}" ] && [ "$OWNER" != root ]; then
  chown -R "$OWNER":"$OWNER" "$PCAP" "$ZDIR" "$SDIR" 2>/dev/null || true
  chown "$OWNER":"$OWNER" data/pcap 2>/dev/null || true
fi

echo "   PCAP : $PCAP ($(du -h "$PCAP" 2>/dev/null | cut -f1))"
echo "   Zeek : $ZDIR ($(ls "$ZDIR"/*.log 2>/dev/null | wc -l) log)"
echo "   Suri : $SDIR"
rm -f "$STATE"
echo "==> Yakalama durduruldu."
