#!/usr/bin/env bash
# =============================================================================
# run_session.sh — TEK KOMUT: bir veri toplama oturumu koştur (Doc Bölüm 11).
#   izolasyon → VM'ler → capture → benign → saldırılar → stop → pipeline → model
#
# Normal kullanıcı olarak çalıştır: ./run_session.sh
#   (sudo yalnızca izolasyon/capture/virsh için; aynı terminalde bir kez sorulur)
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
# shellcheck disable=SC1091
source ./config.env
export LC_ALL=C
export PYTHONUNBUFFERED=1   # pipeline/orchestrator çıktısı tee'ye anında aksın

PY="./.venv/bin/python"; [ -x "$PY" ] || PY="python3"
VIRSH="sudo LC_ALL=C virsh"
TS="$(date +%Y%m%d_%H%M%S)"

c_g=$'\e[32m'; c_y=$'\e[33m'; c_r=$'\e[31m'; c_b=$'\e[1m'; c_0=$'\e[0m'
step(){ echo; echo "${c_b}==> $*${c_0}"; }
ok(){ echo "${c_g}  ✓ $*${c_0}"; }
warn(){ echo "${c_y}  ! $*${c_0}"; }
die(){ echo "${c_r}  ✗ $*${c_0}"; exit 1; }

BENIGN_PID=""; SUDO_KEEP=""
cleanup(){
  [ -n "$BENIGN_PID" ] && kill "$BENIGN_PID" 2>/dev/null || true
  [ -n "$SUDO_KEEP" ] && kill "$SUDO_KEEP" 2>/dev/null || true
}
trap cleanup EXIT

# sudo'yu BİR KEZ al ve oturum boyunca canlı tut (uzun oturumda yeniden sormasın)
echo "Oturum sudo gerektirir (capture/virsh/docker). Parola bir kez sorulacak:"
sudo -v || die "sudo doğrulanamadı"
( while true; do sudo -n true; sleep 50; done ) 2>/dev/null & SUDO_KEEP=$!

vssh(){ ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=5 -o BatchMode=yes "$@"; }
wait_ssh(){ local u="$1" ip="$2" t=0; while [ $t -lt 120 ]; do
  vssh "${u}@${ip}" true 2>/dev/null && return 0; sleep 3; t=$((t+3)); done; return 1; }

echo "${c_b}############ IDS Lab Oturumu  TS=$TS ############${c_0}"

# --- 1. İZOLASYON (geçmezse DUR) --------------------------------------------
step "1/8 İzolasyon kill-check"
./testbed/isolation_check.sh || die "İzolasyon BAŞARISIZ — oturum durduruldu. (Doc Bölüm 10)"

# --- 2. VM'ler ayakta mı ----------------------------------------------------
step "2/8 VM'ler hazır mı"
for pair in "$VICTIM_NAME:$VICTIM_IP:$VICTIM_USER" "$ATTACKER_NAME:$ATTACKER_IP:$ATTACKER_USER"; do
  name="${pair%%:*}"; rest="${pair#*:}"; ip="${rest%%:*}"; user="${rest##*:}"
  $VIRSH domstate "$name" 2>/dev/null | grep -qi running || { $VIRSH start "$name" >/dev/null 2>&1 || true; }
  wait_ssh "$user" "$ip" && ok "$name ($ip) hazır" || die "$name ssh ile erişilemedi"
done

# --- 3. YAKALAMA ------------------------------------------------------------
step "3/8 Yakalama başlıyor (tcpdump + Zeek + Suricata)"
./capture/start_capture.sh "$TS" || die "Yakalama başlatılamadı"
# Wazuh varsa: bu oturum için alarm dosyasını sıfırla (temiz zaman penceresi)
if sudo docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "${WAZUH_MANAGER_NAME:-wazuh-manager}"; then
  sudo docker exec "${WAZUH_MANAGER_NAME}" sh -c 'truncate -s 0 /var/ossec/logs/alerts/alerts.json' 2>/dev/null \
    && echo "   Wazuh alerts.json sıfırlandı" || true
fi

# --- 4. BENIGN trafik (host → victim), arka plan ----------------------------
step "4/8 Benign trafik başlıyor (host .1 → victim)"
$PY traffic/benign_generator.py --duration 0 &
BENIGN_PID=$!
ok "benign_generator PID=$BENIGN_PID"
sleep 3

# --- 5. SALDIRILAR ----------------------------------------------------------
step "5/8 Saldırı senaryoları (orchestrator)"
$PY scenarios/orchestrator.py --out scenarios/ground_truth.csv \
    --gap "${GAP_SECONDS:-45}" --dos-duration "${DOS_DURATION:-8}" \
  || warn "orchestrator hata verdi (kısmi ground_truth olabilir)"
# oturum başına ground_truth sakla (CICFlowMeter toplu etiketleme için)
mkdir -p data/scenarios
cp scenarios/ground_truth.csv "data/scenarios/ground_truth_${TS}.csv" 2>/dev/null || true

# --- 6. DURDUR (benign + capture) -------------------------------------------
step "6/8 Benign ve yakalama durduruluyor"
kill "$BENIGN_PID" 2>/dev/null || true; BENIGN_PID=""
sleep 2
./capture/stop_capture.sh || warn "stop_capture sorunlu"

# --- 7. PIPELINE ------------------------------------------------------------
step "7/8 Pipeline: öznitelik → etiket → host-birleştir → dataset"
PCAP="data/pcap/session_${TS}.pcap"
FLOWS="data/features/flows_${TS}.parquet"
LABELED="data/labeled/flows_labeled_${TS}.parquet"
DATASET="data/labeled/dataset_${TS}.parquet"   # oturum başına ayrı (birleştirme için)
[ -f "$PCAP" ] || die "PCAP yok: $PCAP"

$PY pipeline/extract_features.py --pcap "$PCAP" --out "$FLOWS" || die "extract_features başarısız"
$PY pipeline/label.py --flows "$FLOWS" --ground-truth scenarios/ground_truth.csv \
    --out "$LABELED" --tolerance-ms 2000 --sample 50 || die "label başarısız"

# Wazuh alarmlarını manager container'dan çek (varsa)
mkdir -p data/wazuh_logs
if sudo docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "${WAZUH_MANAGER_NAME:-wazuh-manager}"; then
  sleep 8   # analysisd alerts.json'a yazsın
  sudo docker cp "${WAZUH_MANAGER_NAME}:/var/ossec/logs/alerts/alerts.json" data/wazuh_logs/alerts.json 2>/dev/null \
    && sudo chown "$(id -u):$(id -g)" data/wazuh_logs/alerts.json 2>/dev/null || true
  cp data/wazuh_logs/alerts.json "data/wazuh_logs/alerts_${TS}.json" 2>/dev/null || true  # oturum başına
  echo "   Wazuh alerts.json çekildi ($(wc -l < data/wazuh_logs/alerts.json 2>/dev/null || echo 0) satır)"
fi
WZ=""; [ -s data/wazuh_logs/alerts.json ] && WZ="data/wazuh_logs/alerts.json"
$PY pipeline/merge_hostlogs.py --flows-labeled "$LABELED" --hostlog "$WZ" \
    --victim-ip "$VICTIM_IP" --window-sec 30 --out "$DATASET" || die "merge başarısız"

# --- 8. MODEL + ÖZET --------------------------------------------------------
step "8/8 Baseline model + rapor"
$PY models/train_baseline.py --dataset "$DATASET" --report models/report.md || warn "train sorunlu"

# Etiket kalitesi — bağımsız çapraz doğrulama (Suricata imza motoru)
$PY pipeline/verify_labels.py --flows-labeled "$LABELED" \
    --suricata-eve "data/suricata_logs/${TS}/eve.json" \
    --attacker-ip "$ATTACKER_IP" --victim-ip "$VICTIM_IP" \
    --out models/label_quality.md || warn "verify_labels sorunlu"
cp "$DATASET" data/labeled/dataset.parquet 2>/dev/null || true   # 'en son' işaretçisi

step "ÖZET"
$PY - "$LABELED" "$DATASET" <<'PYEOF'
import sys, pandas as pd
lab = pd.read_parquet(sys.argv[1]); ds = pd.read_parquet(sys.argv[2])
print(f"  Toplam akış: {len(lab)}")
print("  Sınıf dağılımı:")
for k, v in lab["label"].value_counts().items():
    print(f"    {k:16s} {v:6d}  ({100*v/len(lab):5.1f}%)")
if "host_available" in ds and ds["host_available"].max() > 0:
    print(f"  Host alarmı olan akış: {(ds['host_alert_count']>0).sum()}")
else:
    print("  Host (Wazuh) verisi yok → yalnız-ağ dataseti (Wazuh kurulunca çok-modlu olur)")
PYEOF
echo
ok "Bitti. Çıktılar:"
echo "    PCAP     : $PCAP"
echo "    Dataset  : $DATASET"
echo "    Rapor    : models/report.md"
echo "    GT       : scenarios/ground_truth.csv"
grep -A20 "## Özet" models/report.md 2>/dev/null | head -12 || true
