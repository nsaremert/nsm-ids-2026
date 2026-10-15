#!/usr/bin/env bash
# =============================================================================
# extract_features_cic.sh — PCAP → CICFlowMeter V4 ham CSV (Docker: ids-cfm).
#   Kullanım: ./pipeline/extract_features_cic.sh <input.pcap> <output.csv>
# docker'a erişim: önce düz 'docker', sonra 'sg docker' (grup), sonra 'sudo docker'.
# Çıktı CICFlowMeter V4 formatında. Kanonik CICIDS2017 için: pipeline/cic_to_cicids.py
# =============================================================================
set -uo pipefail
PCAP="${1:?pcap gerekli}"; OUT="${2:?çıktı csv gerekli}"
IMG="ids-cfm"
[ -f "$PCAP" ] || { echo "PCAP yok: $PCAP"; exit 1; }

# docker çağrı yöntemi
if docker ps >/dev/null 2>&1; then DK(){ docker "$@"; }
elif sg docker -c "docker ps" >/dev/null 2>&1; then DK(){ sg docker -c "docker $(printf '%q ' "$@")"; }
else DK(){ sudo docker "$@"; }; fi

DK image inspect "$IMG" >/dev/null 2>&1 || { echo "'$IMG' imajı yok (önce ./pipeline/setup_cicflowmeter.sh)"; exit 1; }

PDIR=$(mktemp -d /tmp/cfm_in.XXXXXX); ODIR=$(mktemp -d /tmp/cfm_out.XXXXXX)
chmod 777 "$ODIR"
cp "$PCAP" "$PDIR/capture.pcap"; chmod 644 "$PDIR/capture.pcap"
echo "[cic] CICFlowMeter çalışıyor: $(basename "$PCAP")"
DK run --rm -v "$PDIR":/pcap -v "$ODIR":/flow "$IMG" /pcap /flow >/dev/null 2>&1 || true
CSV=$(find "$ODIR" -name '*.csv' 2>/dev/null | head -1)
if [ -z "$CSV" ]; then echo "[cic] CSV üretilmedi (docker run hatası? imaj/çıktı kontrol et)"; rm -rf "$PDIR" 2>/dev/null; exit 1; fi
mkdir -p "$(dirname "$OUT")"
cp "$CSV" "$OUT"             # root-sahipli olabilir; cp ile oku (644)
rm -rf "$PDIR" 2>/dev/null || true
echo "[cic] → $OUT ($(wc -l < "$OUT") satır, $(head -1 "$OUT" | tr ',' '\n' | wc -l) sütun)"
