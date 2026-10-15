#!/usr/bin/env bash
# =============================================================================
# start_capture.sh — host'ta virbr-ids üzerinde yakalamayı başlatır (Bölüm 6).
#   tcpdump (ham PCAP) + Zeek (conn/http/dns/ssl... JSON) + Suricata (eve.json).
# Canlı yakalama root gerektirir → betik kendini sudo ile yeniden çalıştırır.
# Durum data/.capture_state'e yazılır; stop_capture.sh onu okur.
#   Kullanım: ./capture/start_capture.sh [TS]
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source ./config.env

TS="${1:-$(date +%Y%m%d_%H%M%S)}"

# root değilse kendini sudo ile yeniden çalıştır (env + TS korunur)
if [ "$(id -u)" -ne 0 ]; then exec sudo -E "$0" "$TS"; fi

ZEEK_BIN="/opt/zeek/bin/zeek"; command -v zeek >/dev/null 2>&1 && ZEEK_BIN="$(command -v zeek)"

# arayüz var mı?
if ! ip link show "$CAPTURE_IFACE" >/dev/null 2>&1; then
  echo "HATA: '$CAPTURE_IFACE' arayüzü yok. İzole ağ başlatıldı mı? (virsh net-start $NET_NAME)"; exit 1
fi

ZDIR="data/zeek_logs/$TS"; SDIR="data/suricata_logs/$TS"
mkdir -p data/pcap "$ZDIR" "$SDIR"
PCAP="data/pcap/session_${TS}.pcap"

echo "==> Yakalama başlıyor (iface=$CAPTURE_IFACE, TS=$TS)"

# tcpdump — ham PCAP (pipeline girişi)
# ÖNEMLİ: Ubuntu'nun 'tcpdump' AppArmor profili (enforce) prosese DIŞARIDAN
# sinyal gelmesini engeller → root 'kill' bile EPERM alır ve stop_capture
# tcpdump'ı durduramaz. Bu yüzden tcpdump'ı UNCONFINED başlatıyoruz.
AAE=""; command -v aa-exec >/dev/null 2>&1 && AAE="aa-exec -p unconfined --"
$AAE tcpdump -i "$CAPTURE_IFACE" -s 0 -U -w "$PCAP" >/dev/null 2>"data/pcap/tcpdump_${TS}.err" &
TCPDUMP_PID=$!
echo "   tcpdump PID=$TCPDUMP_PID → $PCAP  (unconfined: ${AAE:+evet})"

# Zeek — canlı; logları JSON olarak $ZDIR'e yazar
if [ -x "$ZEEK_BIN" ]; then
  ( cd "$ZDIR" && exec "$ZEEK_BIN" -i "$CAPTURE_IFACE" LogAscii::use_json=T local ) \
      >"$ZDIR/zeek.stdout" 2>"$ZDIR/zeek.stderr" &
  ZEEK_PID=$!
  echo "   zeek PID=$ZEEK_PID → $ZDIR/"
else
  ZEEK_PID=""; echo "   ! zeek bulunamadı, atlandı"
fi

# Suricata — eve.json
if command -v suricata >/dev/null 2>&1; then
  suricata -i "$CAPTURE_IFACE" -l "$SDIR" >"$SDIR/suricata.stdout" 2>"$SDIR/suricata.stderr" &
  SURICATA_PID=$!
  echo "   suricata PID=$SURICATA_PID → $SDIR/eve.json"
else
  SURICATA_PID=""; echo "   ! suricata bulunamadı, atlandı"
fi

cat > data/.capture_state <<EOF
TS=$TS
PCAP=$PCAP
ZDIR=$ZDIR
SDIR=$SDIR
TCPDUMP_PID=$TCPDUMP_PID
ZEEK_PID=$ZEEK_PID
SURICATA_PID=$SURICATA_PID
OWNER=${SUDO_USER:-root}
EOF

# yakalayıcıların ilk paketleri yakalamaya başlaması için kısa bekleme
sleep 3
echo "==> Yakalama aktif. Durdurmak için: ./capture/stop_capture.sh"
