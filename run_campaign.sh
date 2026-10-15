#!/usr/bin/env bash
# =============================================================================
# run_campaign.sh — N oturumu arka arkaya koşar (TEK sudo, kampanya boyunca
# keepalive). Her oturum parametreleri hafifçe değişir (çeşitlilik). Hacim için.
#
#   Kullanım: ./run_campaign.sh [N]     (varsayılan 8 oturum)
#
# Her oturum run_session.sh'i çağırır → per-session pcap/ground_truth/alerts +
# nfstream multi-modal dataset. Kampanya sonunda CICIDS CSV için:
#   ./pipeline/build_cicids_dataset.sh
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; cd "$HERE"
export LC_ALL=C PYTHONUNBUFFERED=1
N="${1:-8}"

c_b=$'\e[1m'; c_g=$'\e[32m'; c_0=$'\e[0m'
echo "${c_b}############ IDS KAMPANYA — $N oturum ############${c_0}"
echo "Tek sudo (kampanya boyunca canlı tutulur). Parola:"
sudo -v || { echo "sudo gerekli"; exit 1; }
( while true; do sudo -n true; sleep 50; done ) 2>/dev/null & KEEP=$!
trap 'kill $KEEP 2>/dev/null || true' EXIT

START=$(date +%s)
for i in $(seq 1 "$N"); do
  # çeşitlilik: gap 30-55, hping3 süre 6-12, slow-dos 20-30
  export GAP_SECONDS=$(( 30 + RANDOM % 26 ))
  export DOS_DURATION=$(( 6 + RANDOM % 7 ))
  export SLOW_DOS_DURATION=$(( 20 + RANDOM % 11 ))
  echo; echo "${c_b}======== OTURUM $i/$N  (gap=${GAP_SECONDS}s dos=${DOS_DURATION}s slow=${SLOW_DOS_DURATION}s) ========${c_0}"
  ./run_session.sh || echo "  ! oturum $i hata verdi, devam"
  echo "${c_g}  ✓ oturum $i bitti ($(date +%H:%M:%S))${c_0}"
  sleep 15   # oturumlar arası kısa boşluk
done

DUR=$(( ($(date +%s) - START) / 60 ))
echo; echo "${c_b}############ KAMPANYA BİTTİ — $N oturum, ${DUR} dk ############${c_0}"
echo "Oturum datasetleri: $(ls data/labeled/dataset_*.parquet 2>/dev/null | wc -l) adet"
echo "Sonraki: ./pipeline/build_cicids_dataset.sh   (CICFlowMeter → CICIDS CSV)"
echo "         ./.venv/bin/python pipeline/combine_sessions.py  (nfstream multi-modal birleştir)"
