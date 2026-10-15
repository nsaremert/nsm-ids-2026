#!/usr/bin/env bash
# =============================================================================
# provision_vms.sh — VM'leri cloud-init ile kurar (Faz 1).
#
# STRATEJİ (doc Bölüm 4 & 10): "indir, sonra ağı kes".
#   1. Her VM İKİ NIC ile açılır:
#        - natnic  (libvirt 'default' NAT) → SADECE kurulumda internet
#        - isonic  (ids-isolated, statik IP) → kalıcı, dışarı çıkış YOK
#   2. cloud-init paketleri/DVWA'yı NAT üzerinden kurar, PROVISION_DONE yazar.
#   3. Betik NAT NIC'i SÖKER → VM artık tamamen izole (yalnız 10.10.10.0/24).
#
# KULLANIM:
#   ./testbed/provision_vms.sh                # victim + attacker kur
#   ./testbed/provision_vms.sh --only victim  # yalnız biri
#   ./testbed/provision_vms.sh --force        # varsa sil ve yeniden kur (YIKICI: onay sorar)
#   ./testbed/provision_vms.sh --no-isolate   # NAT NIC'i sökme (hata ayıklama)
#
# Idempotent: VM zaten varsa atlar (--force olmadıkça).
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source ./config.env

c_g=$'\e[32m'; c_y=$'\e[33m'; c_r=$'\e[31m'; c_b=$'\e[1m'; c_0=$'\e[0m'
step(){ echo; echo "${c_b}==> $*${c_0}"; }
ok(){   echo "${c_g}  ✓ $*${c_0}"; }
warn(){ echo "${c_y}  ! $*${c_0}"; }
die(){  echo "${c_r}  ✗ $*${c_0}"; exit 1; }

ONLY=""; FORCE=0; ISOLATE=1
while [ $# -gt 0 ]; do case "$1" in
  --only) ONLY="$2"; shift 2;;
  --force) FORCE=1; shift;;
  --no-isolate) ISOLATE=0; shift;;
  *) die "Bilinmeyen argüman: $1";;
esac; done

# --- sudo (virsh/virt-install qemu:///system gerektirir) ---------------------
command -v sudo >/dev/null || die "sudo yok"
sudo -v || die "sudo doğrulanamadı"
( while true; do sudo -n true; sleep 50; done ) 2>/dev/null & KEEP=$!; trap 'kill $KEEP 2>/dev/null||true' EXIT
# LC_ALL=C → virsh çıktısı İngilizce (Türkçe locale'de grep'ler tutsun)
VIRSH="sudo LC_ALL=C virsh"
VINSTALL="sudo LC_ALL=C virt-install"

# --- ön kontrol --------------------------------------------------------------
step "Ön kontrol"
for t in virt-install cloud-localds qemu-img; do command -v "$t" >/dev/null || die "$t yok (önce ./setup_host.sh)"; done
[ -f "${SSH_KEY}.pub" ] || { ssh-keygen -t ed25519 -N '' -f "$SSH_KEY" -C ids-lab >/dev/null; ok "SSH anahtarı üretildi"; }
PUBKEY="$(cat "${SSH_KEY}.pub")"
# ağlar
$VIRSH net-info "$NET_NAME" >/dev/null 2>&1 || die "'$NET_NAME' ağı yok (önce ./setup_host.sh)"
$VIRSH net-info "$NET_NAME" 2>/dev/null | grep -qi 'Active:.*yes' || $VIRSH net-start "$NET_NAME" >/dev/null
# 'default' NAT ağı (kurulumda internet için)
if ! $VIRSH net-info default >/dev/null 2>&1; then
  warn "'default' NAT ağı yok; oluşturuluyor"
  $VIRSH net-define /usr/share/libvirt/networks/default.xml 2>/dev/null || true
fi
$VIRSH net-info default 2>/dev/null | grep -qi 'Active:.*yes' || $VIRSH net-start default >/dev/null 2>&1 || true
$VIRSH net-autostart default >/dev/null 2>&1 || true
ok "Ağlar hazır (izole: $NET_NAME, NAT: default)"
mkdir -p images

# --- yardımcılar -------------------------------------------------------------
# Çalışan VM diskleri + seed ISO'lar libvirt havuzunda (/home izin/AppArmor
# sorunlarından kaçınmak için). Taban imajlar ./images'te kalır.
POOL="/var/lib/libvirt/images"
esc(){ printf '%s' "$1" | sed -e 's/[&|\\]/\\&/g'; }

# ssh ile VM'e komut (izole statik IP üzerinden; host 10.10.10.1 erişir)
vm_ssh(){ local ip="$1"; shift; local user="$1"; shift;
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 -o BatchMode=yes "${user}@${ip}" "$@" 2>/dev/null; }

wait_provision(){ # $1=ip $2=user $3=timeout_sn
  local ip="$1" user="$2" tmo="${3:-900}" t=0
  echo -n "   cloud-init bekleniyor (${ip}, en çok ${tmo}s): "
  while [ "$t" -lt "$tmo" ]; do
    if vm_ssh "$ip" "$user" "test -f /var/lib/cloud/instance/PROVISION_DONE" ; then
      echo " hazır"; return 0
    fi
    echo -n "."; sleep 10; t=$((t+10))
  done
  echo " ZAMAN AŞIMI"; return 1
}

domain_exists(){ $VIRSH dominfo "$1" >/dev/null 2>&1; }

destroy_vm(){ local name="$1"
  $VIRSH destroy "$name" >/dev/null 2>&1 || true
  $VIRSH undefine "$name" --nvram --remove-all-storage >/dev/null 2>&1 \
    || $VIRSH undefine "$name" >/dev/null 2>&1 || true
  sudo rm -f "$POOL/${name}.qcow2" "$POOL/${name}-seed.iso"
}

# build_vm <name> <ip> <nat_mac> <iso_mac> <base_qcow2> <user_data_tmpl> <net_tmpl> <user> <osv> <vcpus> <ram_mb> <disk_gb> <timeout>
build_vm(){
  local name="$1" ip="$2" nat_mac="$3" iso_mac="$4" base="$5" ud_tmpl="$6" net_tmpl="$7" \
        user="$8" osv="$9" vcpus="${10}" ram="${11}" disk="${12}" tmo="${13}"

  step "VM: $name  ($ip)"
  if domain_exists "$name"; then
    if [ "$FORCE" -eq 1 ]; then
      read -r -p "   ${c_y}--force: '$name' silinecek (disk dahil). Onaylıyor musun? [e/H] ${c_0}" a
      [[ "$a" =~ ^[eE]$ ]] || die "İptal edildi"
      destroy_vm "$name"; ok "Eski '$name' silindi"
    else
      ok "'$name' zaten var — atlanıyor (--force ile yeniden kur)"; return 0
    fi
  fi
  [ -f "$base" ] || die "Taban imaj yok: $base"

  # disk (libvirt havuzunda)
  sudo cp --reflink=auto "$base" "$POOL/${name}.qcow2"
  sudo qemu-img resize "$POOL/${name}.qcow2" "${disk}G" >/dev/null
  ok "Disk hazır: $POOL/${name}.qcow2 (${disk}G)"

  # cloud-init seed
  local tmp; tmp="$(mktemp -d)"
  sed -e "s|__SSH_PUBKEY__|$(esc "$PUBKEY")|g" \
      -e "s|__HOSTNAME__|$(esc "$name")|g" \
      -e "s|__VICTIM_USER__|$(esc "$VICTIM_USER")|g" \
      -e "s|__ATTACKER_USER__|$(esc "$ATTACKER_USER")|g" \
      -e "s|__BRUTE_USER__|$(esc "$BRUTE_USER")|g" \
      -e "s|__BRUTE_PASSWORD__|$(esc "$BRUTE_PASSWORD")|g" \
      -e "s|__HOST_IP__|$(esc "$HOST_IP")|g" \
      "$ud_tmpl" > "$tmp/user-data"
  sed -e "s|__NAT_MAC__|$(esc "$nat_mac")|g" \
      -e "s|__ISO_MAC__|$(esc "$iso_mac")|g" \
      -e "s|__VICTIM_IP__|$(esc "$ip")|g" \
      -e "s|__ATTACKER_IP__|$(esc "$ip")|g" \
      -e "s|__HOST_IP__|$(esc "$HOST_IP")|g" \
      "$net_tmpl" > "$tmp/network-config"
  sed -e "s|__INSTANCE_ID__|$(esc "iid-$name")|g" -e "s|__HOSTNAME__|$(esc "$name")|g" \
      testbed/cloud-init/meta-data > "$tmp/meta-data"
  cloud-localds --network-config="$tmp/network-config" "$tmp/${name}-seed.iso" "$tmp/user-data" "$tmp/meta-data"
  sudo cp "$tmp/${name}-seed.iso" "$POOL/${name}-seed.iso"
  rm -rf "$tmp"
  ok "cloud-init seed hazır"

  # virt-install: NAT + izole NIC
  echo "   virt-install çalışıyor..."
  $VINSTALL --name "$name" --memory "$ram" --vcpus "$vcpus" \
    --cpu host-passthrough --virt-type kvm \
    --disk "path=$POOL/${name}.qcow2,format=qcow2,bus=virtio" \
    --disk "path=$POOL/${name}-seed.iso,device=cdrom" \
    --os-variant "$osv" \
    --network "network=default,model=virtio,mac=${nat_mac}" \
    --network "network=${NET_NAME},model=virtio,mac=${iso_mac}" \
    --graphics vnc,listen=127.0.0.1 --noautoconsole --import \
    || die "virt-install başarısız ($name)"
  ok "VM tanımlandı ve başlatıldı"

  # provizyon bitişini bekle
  if wait_provision "$ip" "$user" "$tmo"; then
    ok "cloud-init tamamlandı ($name)"
  else
    warn "cloud-init zaman aşımı — VM'e VNC/konsoldan bak: sudo virsh console $name"
    warn "NAT NIC sökülmeyecek (hata ayıklama için açık bırakıldı)"
    return 0
  fi

  # İZOLE ET: NAT NIC'i sök
  if [ "$ISOLATE" -eq 1 ]; then
    $VIRSH detach-interface "$name" network --mac "$nat_mac" --live --config \
      && ok "NAT NIC söküldü → '$name' artık TAMAMEN İZOLE" \
      || warn "NAT NIC sökülemedi; elle: sudo virsh detach-interface $name network --mac $nat_mac --live --config"
    # temiz baseline: kapat (run_session başlatır)
    $VIRSH shutdown "$name" >/dev/null 2>&1 || true
  else
    warn "--no-isolate: NAT NIC açık bırakıldı"
  fi
}

# --- VM tanımları ------------------------------------------------------------
# MAC kuralı: izole NIC son okteti IP ile eşleşir (okunurluk için).
provision_victim(){
  build_vm "$VICTIM_NAME" "$VICTIM_IP" \
    "52:54:00:12:34:30" "52:54:00:10:10:30" \
    "images/noble-base.img" \
    "testbed/cloud-init/victim-user-data.tmpl" \
    "testbed/cloud-init/victim-network-config.tmpl" \
    "$VICTIM_USER" "ubuntu24.04" \
    "$VICTIM_VCPUS" "$VICTIM_RAM_MB" "$VICTIM_DISK_GB" 1200
}

provision_attacker(){
  if [ "$ATTACKER_DISTRO" = "kali" ]; then
    build_vm "$ATTACKER_NAME" "$ATTACKER_IP" \
      "52:54:00:12:34:20" "52:54:00:10:10:20" \
      "images/kali-base.qcow2" \
      "testbed/cloud-init/attacker-kali-user-data.tmpl" \
      "testbed/cloud-init/attacker-network-config.tmpl" \
      "$ATTACKER_USER" "generic" \
      "$ATTACKER_VCPUS" "$ATTACKER_RAM_MB" "$ATTACKER_DISK_GB" 1200
  else
    build_vm "$ATTACKER_NAME" "$ATTACKER_IP" \
      "52:54:00:12:34:20" "52:54:00:10:10:20" \
      "images/noble-base.img" \
      "testbed/cloud-init/attacker-ubuntu-user-data.tmpl" \
      "testbed/cloud-init/attacker-network-config.tmpl" \
      "$ATTACKER_USER" "ubuntu24.04" \
      "$ATTACKER_VCPUS" "$ATTACKER_RAM_MB" "$ATTACKER_DISK_GB" 1800
  fi
}

# --- imaj indirme ------------------------------------------------------------
download_images(){
  step "Taban imajlar"
  if [ "$ONLY" != "attacker" ] || [ "$ATTACKER_DISTRO" = "ubuntu" ]; then
    if [ ! -f images/noble-base.img ]; then
      echo "   Ubuntu 24.04 cloud image indiriliyor..."
      curl -fL --progress-bar "$UBUNTU_IMG_URL" -o images/noble-base.img || die "Ubuntu imajı indirilemedi"
    fi
    ok "Ubuntu taban imajı hazır"
  fi
  if [ "$ONLY" != "victim" ] && [ "$ATTACKER_DISTRO" = "kali" ]; then
    if [ ! -f images/kali-base.qcow2 ]; then
      # 1) indir (arşiv ve ham disk ikisi de yoksa)
      if [ ! -f images/kali.tar.xz ] && [ ! -f images/disk.raw ]; then
        local kurl="$KALI_IMG_URL"
        if ! curl -sfIL --max-time 20 "$kurl" >/dev/null 2>&1; then
          warn "KALI_IMG_URL erişilemedi; ${KALI_IMG_DIR_URL} listesinden keşfediliyor"
          local fn
          fn="$(curl -sL --max-time 20 "$KALI_IMG_DIR_URL" | grep -oE 'kali-linux-[0-9.]+-cloud-genericcloud-amd64\.tar\.xz' | head -1)"
          [ -n "$fn" ] && kurl="${KALI_IMG_DIR_URL}${fn}" && ok "Bulundu: $kurl" || die "Kali imaj dosyası keşfedilemedi"
        fi
        echo "   Kali cloud image indiriliyor: $kurl"
        curl -fL --progress-bar "$kurl" -o images/kali.tar.xz || die "Kali imajı indirilemedi"
      fi
      # 2) çıkart (ham disk henüz yoksa)
      if [ ! -f images/disk.raw ] && [ -f images/kali.tar.xz ]; then
        echo "   çıkartılıyor..."
        tar -xJf images/kali.tar.xz -C images/
      fi
      # 3) disk imajını qcow2'ye çevir (genericcloud 'disk.raw' RAW olarak gelir)
      local raw qc
      raw="$(find images -maxdepth 2 \( -name 'disk.raw' -o -name '*.raw' \) 2>/dev/null | head -1)"
      if [ -n "$raw" ]; then
        echo "   qcow2'ye çevriliyor ($raw → kali-base.qcow2)..."
        qemu-img convert -O qcow2 "$raw" images/kali-base.qcow2 || die "Kali qcow2 dönüşümü başarısız"
        rm -f "$raw"
      else
        qc="$(find images -maxdepth 2 -name '*.qcow2' ! -name 'kali-base.qcow2' 2>/dev/null | head -1)"
        [ -n "$qc" ] && mv "$qc" images/kali-base.qcow2 || die "Kali disk imajı bulunamadı (arşiv içeriği?)"
      fi
      rm -f images/kali.tar.xz
    fi
    ok "Kali taban imajı hazır"
  fi
}

# --- main --------------------------------------------------------------------
download_images
case "$ONLY" in
  victim)   provision_victim ;;
  attacker) provision_attacker ;;
  "")       provision_victim; provision_attacker ;;
  *) die "--only sadece victim|attacker olabilir" ;;
esac

step "ÖZET"
$VIRSH list --all | sed 's/^/   /'
echo
ok "Provizyon bitti. İzolasyonu doğrulamak için: ${c_b}./testbed/isolation_check.sh${c_0}"
