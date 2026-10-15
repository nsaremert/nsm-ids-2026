#!/usr/bin/env bash
# =============================================================================
# attacker_install_tools.sh — Kali genericcloud minimal geldiği için saldırı
# araçlarını kurar. Attacker izole olduğundan: NAT'ı GEÇİCİ tak → kur → NAT'ı
# SÖK → izolasyonu doğrula. Idempotent.
#
# Araçlar: nmap, hydra, sqlmap, hping3, curl, (metasploit-framework: opsiyonel/büyük)
# Çalıştır:  ./testbed/attacker_install_tools.sh   (sudo gerekir: NAT tak/sök)
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
NAT_MAC="52:54:00:12:34:20"   # provision_vms.sh ile aynı olmalı
sudo -v || die "sudo gerekli"
( while true; do sudo -n true; sleep 50; done ) 2>/dev/null & KEEP=$!; trap 'kill $KEEP 2>/dev/null||true' EXIT

vssh(){ ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=8 -o BatchMode=yes "${ATTACKER_USER}@${ATTACKER_IP}" "$@"; }

$VIRSH domstate ids-attacker 2>/dev/null | grep -qi running || { $VIRSH start ids-attacker; sleep 8; }

step "1. NAT'ı geçici tak (internet için)"
if $VIRSH domiflist ids-attacker | grep -qi "$NAT_MAC"; then
  ok "NAT arayüzü zaten takılı"
else
  $VIRSH attach-interface ids-attacker network default --model virtio --mac "$NAT_MAC" --live \
    && ok "NAT arayüzü takıldı" || die "NAT takılamadı"
fi

step "2. Attacker'da internet'i aç (netplan/dhcp)"
vssh 'bash -s' <<'EOS'
sudo netplan apply 2>/dev/null || true
sleep 4
if ! ping -c1 -W3 8.8.8.8 >/dev/null 2>&1; then
  for i in $(ls /sys/class/net | grep -v '^lo$'); do
    ip -4 addr show "$i" 2>/dev/null | grep -q '10\.10\.10\.' && continue
    sudo timeout 20 dhclient -v "$i" >/dev/null 2>&1 &
  done
  sleep 8
fi
ping -c1 -W3 8.8.8.8 >/dev/null 2>&1 && echo "NET_OK" || echo "NET_FAIL"
EOS
NETSTATE=$(vssh 'ping -c1 -W3 8.8.8.8 >/dev/null 2>&1 && echo OK || echo FAIL')
[ "$NETSTATE" = OK ] && ok "Attacker internete çıkıyor (geçici)" || die "Attacker internete çıkamadı; NAT/netplan kontrol et"

step "3. Araçları kur (apt)"
vssh 'bash -s' <<'EOS'
set -e
sudo DEBIAN_FRONTEND=noninteractive apt-get update -y
echo ">>> çekirdek araçlar"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y nmap hydra sqlmap hping3 curl netcat-traditional
echo ">>> çeşitlilik araçları (DoS alt-tipleri, web, brute)"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y slowhttptest nikto patator git || echo "VARIETY_PARTIAL"
echo ">>> GoldenEye (DoS GoldenEye) + HULK (opsiyonel) /opt altına"
sudo git clone --depth 1 https://github.com/jseidl/GoldenEye.git /opt/GoldenEye 2>/dev/null || echo "GoldenEye var/atlandı"
sudo git clone --depth 1 https://github.com/Hyperclaw79/HULK-v3.git /opt/hulk 2>/dev/null || echo "HULK atlandı (opsiyonel)"
echo ">>> metasploit-framework (büyük; başarısız olursa devam)"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y metasploit-framework || echo "MSF_FAIL"
EOS

step "4. Araçları doğrula"
vssh 'for t in nmap hydra sqlmap hping3 curl msfconsole slowhttptest nikto patator; do printf "   %-14s " $t; command -v $t >/dev/null && echo OK || echo EKSİK; done; printf "   %-14s " GoldenEye; [ -f /opt/GoldenEye/goldeneye.py ] && echo OK || echo EKSİK; printf "   %-14s " HULK; [ -f /opt/hulk/hulk.py ] && echo OK || echo "yok(ops)"'

step "5. NAT'ı SÖK → tekrar tam izole"
$VIRSH detach-interface ids-attacker network --mac "$NAT_MAC" --live \
  && ok "NAT söküldü" || warn "NAT sökülemedi; elle: sudo virsh detach-interface ids-attacker network --mac $NAT_MAC --live"
# guest'te olası default rotayı temizle
vssh 'sudo ip route del default 2>/dev/null; sudo netplan apply 2>/dev/null; true' || true

step "6. İzolasyonu doğrula"
if vssh 'ping -c1 -W3 8.8.8.8 >/dev/null 2>&1'; then
  die "İHLAL: attacker hâlâ internete çıkıyor! NAT sökülmemiş olabilir."
else
  ok "Attacker tekrar izole (8.8.8.8 erişilemez)"
fi
echo; ok "Bitti. Artık ./testbed/isolation_check.sh ile tam doğrulama yapabilirsin."
