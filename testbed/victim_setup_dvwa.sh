#!/usr/bin/env bash
# =============================================================================
# victim_setup_dvwa.sh — victim'e ÇALIŞAN DVWA kurar.
# ghcr.io/digininja/dvwa ayrı DB container ister (tek başına dvwaDatabaseConnect
# hatası verir). Burada KENDİ MySQL'ini içeren vulnerables/web-dvwa imajına geçeriz.
# Victim izole olduğundan: NAT'ı GEÇİCİ tak → imajı çek → container'ı değiştir →
# NAT'ı SÖK → izolasyonu doğrula. Idempotent.
#
# Çalıştır:  ./testbed/victim_setup_dvwa.sh   (sudo: NAT tak/sök)
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source ./config.env

c_g=$'\e[32m'; c_y=$'\e[33m'; c_r=$'\e[31m'; c_b=$'\e[1m'; c_0=$'\e[0m'
ok(){ echo "${c_g}  ✓ $*${c_0}"; }; warn(){ echo "${c_y}  ! $*${c_0}"; }; die(){ echo "${c_r}  ✗ $*${c_0}"; exit 1; }
step(){ echo; echo "${c_b}==> $*${c_0}"; }

VIRSH="sudo LC_ALL=C virsh"
NAT_MAC="52:54:00:12:34:30"   # victim nat mac (provision_vms.sh ile aynı)
IMG="vulnerables/web-dvwa:latest"
sudo -v || die "sudo gerekli"
( while true; do sudo -n true; sleep 50; done ) 2>/dev/null & KEEP=$!; trap 'kill $KEEP 2>/dev/null||true' EXIT

vssh(){ ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=8 -o BatchMode=yes "${VICTIM_USER}@${VICTIM_IP}" "$@"; }

$VIRSH domstate "$VICTIM_NAME" 2>/dev/null | grep -qi running || { $VIRSH start "$VICTIM_NAME"; sleep 8; }

step "1. NAT'ı geçici tak"
if $VIRSH domiflist "$VICTIM_NAME" | grep -qi "$NAT_MAC"; then ok "NAT zaten takılı"; else
  $VIRSH attach-interface "$VICTIM_NAME" network default --model virtio --mac "$NAT_MAC" --live && ok "NAT takıldı" || die "NAT takılamadı"
fi

step "2. Victim'de internet'i aç"
vssh 'bash -s' <<'EOS'
sudo netplan apply 2>/dev/null || true
sleep 4
if ! ping -c1 -W3 8.8.8.8 >/dev/null 2>&1; then
  for i in $(ls /sys/class/net | grep -v '^lo$'); do
    ip -4 addr show "$i" 2>/dev/null | grep -q '10\.10\.10\.' && continue
    sudo timeout 20 dhclient -v "$i" >/dev/null 2>&1 &
  done; sleep 8
fi
EOS
[ "$(vssh 'ping -c1 -W3 8.8.8.8 >/dev/null 2>&1 && echo OK || echo FAIL')" = OK ] \
  && ok "Victim internete çıkıyor (geçici)" || die "Victim internete çıkamadı"

step "3. Çalışan DVWA imajını çek ve container'ı değiştir"
vssh 'bash -s' <<EOS
set -e
docker pull $IMG
docker rm -f dvwa 2>/dev/null || true
docker run -d --name dvwa --restart unless-stopped -p 80:80 $IMG
sleep 8
docker ps --format '{{.Image}} {{.Status}}'
EOS
ok "DVWA container değiştirildi"

step "4. NAT'ı SÖK → tekrar izole"
$VIRSH detach-interface "$VICTIM_NAME" network --mac "$NAT_MAC" --live && ok "NAT söküldü" \
  || warn "NAT sökülemedi; elle: sudo virsh detach-interface $VICTIM_NAME network --mac $NAT_MAC --live"
vssh 'sudo ip route del default 2>/dev/null; sudo netplan apply 2>/dev/null; true' || true

step "5. İzolasyon + DVWA sağlık"
vssh 'ping -c1 -W3 8.8.8.8 >/dev/null 2>&1' && die "İHLAL: victim hâlâ internette!" || ok "Victim tekrar izole"
sleep 3
code=$(vssh "curl -s -o /dev/null -w '%{http_code}' http://localhost/login.php" 2>/dev/null)
echo "   DVWA login.php → HTTP ${code:-?}"
[ "$code" = "200" ] && ok "DVWA çalışıyor (login formu geliyor)" || warn "DVWA henüz hazır olmayabilir; birkaç sn sonra tekrar bak"
echo; ok "Bitti."
