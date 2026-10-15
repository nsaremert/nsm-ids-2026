#!/usr/bin/env bash
# =============================================================================
# setup_cicflowmeter.sh — Java CICFlowMeter V4 Docker imajını derler (ids-cfm).
# CICIDS2017/18 ile aynı yöntemle öznitelik hesaplar. ubuntu:18.04 tabanı eski
# jnetpcap/libpcap sorunlarını baypas eder.
#   Çalıştır: ./pipeline/setup_cicflowmeter.sh   (sudo: docker build)
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"
c_g=$'\e[32m'; c_r=$'\e[31m'; c_b=$'\e[1m'; c_0=$'\e[0m'
ok(){ echo "${c_g}  ✓ $*${c_0}"; }; die(){ echo "${c_r}  ✗ $*${c_0}"; exit 1; }
IMG="ids-cfm"
# docker erişimi: düz docker → sg docker (grup) → sudo docker
if docker ps >/dev/null 2>&1; then DK(){ docker "$@"; }
elif sg docker -c "docker ps" >/dev/null 2>&1; then DK(){ sg docker -c "docker $(printf '%q ' "$@")"; }
else sudo -v || die "sudo gerekli"; DK(){ sudo docker "$@"; }; fi

if DK image inspect "$IMG" >/dev/null 2>&1; then
  ok "İmaj '$IMG' zaten var (yeniden derlemek için önce: docker rmi $IMG)"
  exit 0
fi
echo "${c_b}==> CICFlowMeter Docker imajı derleniyor ($IMG) — ilk sefer ~10-15 dk${c_0}"
DK build -t "$IMG" pipeline/cicflowmeter/ || die "docker build başarısız"
ok "İmaj derlendi: $IMG"
echo "   Test: ./pipeline/extract_features_cic.sh <pcap> <out.csv>"
