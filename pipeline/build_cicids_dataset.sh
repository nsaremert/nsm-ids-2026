#!/usr/bin/env bash
# =============================================================================
# build_cicids_dataset.sh — tüm oturum pcap'lerinden CICIDS2017-uyumlu veri seti.
# Her pcap: CICFlowMeter (Docker) → kanonik CICIDS2017 şema → ground_truth ile
# etiketle. Hepsi birleştirilip dataset/ altına yazılır (full + ML-ready CSV).
#
#   Kullanım: ./pipeline/build_cicids_dataset.sh [DATASET_ADI]
#   (önce ./pipeline/setup_cicflowmeter.sh ile ids-cfm imajı derlenmiş olmalı)
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"; cd "$ROOT"
# shellcheck disable=SC1091
source ./config.env
PY="./.venv/bin/python"; [ -x "$PY" ] || PY=python3
NAME="${1:-NSM-IDS-2026}"
mkdir -p data/cicids dataset

c_g=$'\e[32m'; c_y=$'\e[33m'; c_b=$'\e[1m'; c_0=$'\e[0m'
echo "${c_b}==> CICIDS veri seti derleniyor: $NAME${c_0}"

shopt -s nullglob
PCAPS=(data/pcap/session_*.pcap)
[ ${#PCAPS[@]} -eq 0 ] && { echo "pcap yok (data/pcap/session_*.pcap). Önce oturum/kampanya koş."; exit 1; }
echo "   ${#PCAPS[@]} pcap bulundu"

n_ok=0
LABELS=()
for pcap in "${PCAPS[@]}"; do
  TS=$(basename "$pcap" | sed 's/^session_//; s/\.pcap$//')
  GT="data/scenarios/ground_truth_${TS}.csv"; [ -f "$GT" ] || GT="scenarios/ground_truth.csv"
  RAW="data/cicids/cic_raw_${TS}.csv"; LAB="data/cicids/cicids_${TS}.csv"
  echo; echo "${c_b}-- oturum $TS --${c_0}"
  if [ ! -f "$RAW" ]; then
    ./pipeline/extract_features_cic.sh "$pcap" "$RAW" || { echo "${c_y}  ! CICFlowMeter atladı${c_0}"; continue; }
  else echo "   (cic_raw mevcut, atlanıyor)"; fi
  $PY pipeline/label_cic.py --cic "$RAW" --ground-truth "$GT" --out "$LAB" || { echo "${c_y}  ! etiketleme hata${c_0}"; continue; }
  LABELS+=("$LAB")
  n_ok=$((n_ok+1))
done

echo; echo "${c_b}==> Birleştirme ($n_ok oturum)${c_0}"
# NOT: yalnız BU koşuda işlenen oturumlar birleştirilir (data/cicids'teki bayat/
# pretest dosyaları kör glob ile karışmasın diye liste açıkça geçirilir).
$PY - "$NAME" "${LABELS[@]}" <<'PYEOF'
import sys, pandas as pd
sys.path.insert(0, "pipeline"); import cic_to_cicids as cic
name = sys.argv[1]
files = sorted(sys.argv[2:])
if not files:
    print("Etiketli CIC CSV yok."); sys.exit(1)
frames = [pd.read_csv(f, skipinitialspace=True) for f in files]
full = pd.concat(frames, ignore_index=True)
full.columns = [c.strip() for c in full.columns]
full_path = f"dataset/{name}_full.csv"
ml_path   = f"dataset/{name}_ML.csv"
full.to_csv(full_path, index=False)
cic.ml_ready(full).to_csv(ml_path, index=False)
print(f"  full: {full_path}  ({len(full)} akış, {full.shape[1]} sütun)")
print(f"  ML  : {ml_path}  ({len(full)} akış, 79 sütun)")
print("  sınıf dağılımı:")
for k, v in full["Label"].value_counts().items():
    print(f"    {str(k):18s} {v:7d}  ({100*v/len(full):5.1f}%)")
PYEOF
echo; echo "${c_g}Bitti. dataset/${NAME}_full.csv ve _ML.csv hazır.${c_0}"
