#!/usr/bin/env bash
# =============================================================================
# isolation_check.sh — KILL-CHECK (doc Bölüm 3 & 10). Senaryolardan ÖNCE koşar.
#
# Doğrular:
#   (A) libvirt ağında <forward> YOK (XML seviyesinde izolasyon).
#   (B) Her VM'den DIŞARI erişim BAŞARISIZ:
#         - internet (8.8.8.8, 1.1.1.1) ping → başarısız olmalı
#         - host'un GERÇEK LAN geçidi ping → başarısız olmalı
#         - DNS çözümleme → başarısız olmalı
#   (C) Lab İÇİ erişim ÇALIŞIR: attacker → victim ping başarılı olmalı.
#
# Herhangi bir DIŞ erişim BAŞARILI olursa → çıkış kodu 1 (run_session DURUR).
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source ./config.env

c_g=$'\e[32m'; c_y=$'\e[33m'; c_r=$'\e[31m'; c_b=$'\e[1m'; c_0=$'\e[0m'
ok(){   echo "${c_g}  ✓ $*${c_0}"; }
bad(){  echo "${c_r}  ✗ $*${c_0}"; }
warn(){ echo "${c_y}  ! $*${c_0}"; }
FAIL=0

VIRSH="sudo LC_ALL=C virsh"   # İngilizce çıktı (Türkçe locale grep sorunları)
command -v sudo >/dev/null && sudo -v 2>/dev/null || true

vm_ssh(){ local ip="$1" user="$2"; shift 2;
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 -o BatchMode=yes "${user}@${ip}" "$@" 2>/dev/null; }

ensure_up(){ # $1=name $2=ip $3=user  → VM çalışsın ve ssh cevap versin
  local name="$1" ip="$2" user="$3" t=0
  domain_running(){ $VIRSH domstate "$name" 2>/dev/null | grep -qi running; }
  $VIRSH dominfo "$name" >/dev/null 2>&1 || { warn "$name tanımlı değil (atlanıyor)"; return 2; }
  domain_running || { echo "   $name başlatılıyor..."; $VIRSH start "$name" >/dev/null 2>&1 || true; }
  echo -n "   $name ssh bekleniyor: "
  while [ "$t" -lt 180 ]; do
    if vm_ssh "$ip" "$user" true; then echo " hazır"; return 0; fi
    echo -n "."; sleep 5; t=$((t+5))
  done
  echo " ERİŞİLEMEDİ"; warn "$name ssh ile erişilemedi"; return 1
}

# Host'un gerçek LAN geçidi (bu izole VM'lerden ERİŞİLEMEMELİ)
LAN_GW="${LAN_GW:-$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')}"
[ -z "$LAN_GW" ] && LAN_GW="192.168.1.1"

echo "${c_b}=== IDS Lab İzolasyon Kontrolü ===${c_0}"

# --- (A) XML forward yok -----------------------------------------------------
echo; echo "${c_b}(A) Ağ XML izolasyonu${c_0}"
if $VIRSH net-dumpxml "$NET_NAME" 2>/dev/null | grep -q '<forward'; then
  bad "'$NET_NAME' ağında <forward> VAR → İZOLE DEĞİL!"; FAIL=1
else
  ok "'$NET_NAME' <forward> içermiyor (izole)"
fi

# --- VM'lerden testler -------------------------------------------------------
# dış hedefe erişim: ping BAŞARILI olursa KÖTÜ (izolasyon ihlali)
check_outbound(){ # $1=name $2=ip $3=user
  local name="$1" ip="$2" user="$3"
  echo; echo "${c_b}(B) $name dışarı erişim testleri${c_0}"
  local broke=0
  for tgt in 8.8.8.8 1.1.1.1 "$LAN_GW"; do
    if vm_ssh "$ip" "$user" "ping -c1 -W2 $tgt >/dev/null 2>&1"; then
      bad "$name → $tgt PING BAŞARILI (İZOLASYON İHLALİ!)"; broke=1; FAIL=1
    else
      ok "$name → $tgt erişilemez (beklenen)"
    fi
  done
  # DNS
  if vm_ssh "$ip" "$user" "getent hosts google.com >/dev/null 2>&1 || nslookup google.com >/dev/null 2>&1"; then
    bad "$name → DNS çözümleme ÇALIŞIYOR (dış erişim olabilir!)"; FAIL=1
  else
    ok "$name → DNS çözümlenemiyor (beklenen)"
  fi
  [ "$broke" -eq 0 ] && ok "$name dış dünyadan yalıtık"
}

ATT_UP=1; VIC_UP=1
ensure_up "$VICTIM_NAME"   "$VICTIM_IP"   "$VICTIM_USER"   || VIC_UP=0
ensure_up "$ATTACKER_NAME" "$ATTACKER_IP" "$ATTACKER_USER" || ATT_UP=0

[ "$VIC_UP" -eq 1 ] && check_outbound "$VICTIM_NAME"   "$VICTIM_IP"   "$VICTIM_USER"
[ "$ATT_UP" -eq 1 ] && check_outbound "$ATTACKER_NAME" "$ATTACKER_IP" "$ATTACKER_USER"

# --- (C) lab içi bağlantı ----------------------------------------------------
echo; echo "${c_b}(C) Lab içi bağlantı${c_0}"
if [ "$ATT_UP" -eq 1 ] && [ "$VIC_UP" -eq 1 ]; then
  if vm_ssh "$ATTACKER_IP" "$ATTACKER_USER" "ping -c1 -W2 $VICTIM_IP >/dev/null 2>&1"; then
    ok "attacker → victim ($VICTIM_IP) erişilebilir (lab çalışıyor)"
  else
    bad "attacker → victim erişilemiyor → senaryolar çalışmaz!"; FAIL=1
  fi
else
  warn "Her iki VM up değil; lab içi bağlantı testi atlandı"
fi

# --- sonuç -------------------------------------------------------------------
echo
if [ "$FAIL" -eq 0 ]; then
  echo "${c_g}${c_b}>>> İZOLASYON OK — senaryolar güvenle çalıştırılabilir.${c_0}"
  exit 0
else
  echo "${c_r}${c_b}>>> İZOLASYON BAŞARISIZ — DUR. Senaryo ÇALIŞTIRMA.${c_0}"
  echo "${c_r}    Ağ XML'ini ve NAT NIC'in söküldüğünü kontrol et (provision_vms.sh).${c_0}"
  exit 1
fi
