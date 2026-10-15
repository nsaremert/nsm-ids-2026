#!/usr/bin/env bash
# =============================================================================
# setup_host.sh — host tarafı tek seferlik kurulum (Faz 0 + altyapı ön koşulları)
#
#   Kurar: libvirt/KVM, virt-install, cloud-image-utils, Zeek, Suricata, Docker,
#          chrony (izole ağ için NTP referansı), tcpdump, Python venv + bağımlılıklar.
#   Yapar: 'ids-isolated' izole ağını tanımlar+başlatır, lab SSH anahtarını üretir,
#          kullanıcıyı kvm/libvirt/docker gruplarına ekler.
#
#   ÇALIŞTIRMA:  ./setup_host.sh        (normal kullanıcı olarak; içeride sudo çağırır)
#   Idempotenttir: tekrar çalıştırmak güvenlidir.
#
#   NOT: Grup değişiklikleri için oturumu kapatıp açman (veya `newgrp libvirt`)
#        gerekebilir. Betik sonunda hatırlatır.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
# shellcheck disable=SC1091
source ./config.env

# ---- çıktı yardımcıları -----------------------------------------------------
c_g=$'\e[32m'; c_y=$'\e[33m'; c_r=$'\e[31m'; c_b=$'\e[1m'; c_0=$'\e[0m'
step(){ echo; echo "${c_b}==> $*${c_0}"; }
ok(){   echo "${c_g}  ✓ $*${c_0}"; }
warn(){ echo "${c_y}  ! $*${c_0}"; WARNS+=("$*"); }
die(){  echo "${c_r}  ✗ $*${c_0}"; exit 1; }
WARNS=()

# apt install: DEBIAN_FRONTEND'i sudo İÇİNDEN geçir (sudo env'i süzer) → dialog çıkmaz.
# conffile çakışmalarında mevcut ayarı koru.
apt_install(){ sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@"; }

# ---- 0. ön kontrol ----------------------------------------------------------
step "0. Ön kontrol"
[ "$(id -u)" -eq 0 ] && die "Bunu root olarak DEĞİL, normal kullanıcı olarak çalıştır (içeride sudo kullanılır)."
command -v sudo >/dev/null || die "sudo bulunamadı."
echo "   sudo erişimi doğrulanıyor (parola isteyebilir)..."
sudo -v || die "sudo doğrulanamadı."
# sudo zaman aşımını canlı tut
( while true; do sudo -n true; sleep 50; done ) 2>/dev/null & SUDO_KEEPALIVE=$!
trap 'kill "$SUDO_KEEPALIVE" 2>/dev/null || true' EXIT
[ -e /dev/kvm ] && ok "/dev/kvm mevcut" || warn "/dev/kvm yok — BIOS'ta sanallaştırma (VT-x) kapalı olabilir."
export DEBIAN_FRONTEND=noninteractive

# ---- 1. temel paketler ------------------------------------------------------
step "1. Temel sanallaştırma + yakalama paketleri"
# postfix vb. için debconf ön-cevapları (interaktif dialog ÇIKMASIN)
echo "postfix postfix/main_mailer_type select Local only" | sudo debconf-set-selections 2>/dev/null || true
echo "postfix postfix/mailname string $(hostname)"        | sudo debconf-set-selections 2>/dev/null || true
# önceki yarım kalan/iptal edilmiş kurulumu onar
sudo DEBIAN_FRONTEND=noninteractive dpkg --configure -a 2>/dev/null || true
sudo apt-get update -qq || warn "apt update sorunlu"
BASE_PKGS=(
  qemu-kvm libvirt-daemon-system libvirt-clients virtinst bridge-utils
  cloud-image-utils genisoimage ovmf
  tcpdump chrony curl gnupg ca-certificates software-properties-common
  python3-venv python3-pip python3-dev build-essential libpcap-dev xz-utils
)
if apt_install "${BASE_PKGS[@]}"; then ok "Temel paketler kuruldu"; else warn "Bazı temel paketler kurulamadı"; fi

# ---- 2. Zeek (OpenSUSE Build Service deposu) ---------------------------------
step "2. Zeek"
if command -v zeek >/dev/null 2>&1 || [ -x /opt/zeek/bin/zeek ]; then
  ok "Zeek zaten kurulu"
else
  ZREPO="/etc/apt/sources.list.d/security:zeek.list"
  ZKEY="/etc/apt/trusted.gpg.d/security_zeek.gpg"
  if [ ! -f "$ZREPO" ]; then
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' \
      | sudo tee "$ZREPO" >/dev/null
  fi
  if [ ! -f "$ZKEY" ]; then
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key \
      | gpg --dearmor | sudo tee "$ZKEY" >/dev/null || warn "Zeek anahtarı indirilemedi"
  fi
  sudo apt-get update -qq || warn "Zeek deposu apt update sorunlu"
  if apt_install zeek; then ok "Zeek kuruldu (/opt/zeek)"; else warn "Zeek kurulamadı"; fi
fi
# /opt/zeek/bin PATH'e (etkileşimli kabuklar için)
if [ -d /opt/zeek/bin ] && [ ! -f /etc/profile.d/zeek-path.sh ]; then
  echo 'export PATH="/opt/zeek/bin:$PATH"' | sudo tee /etc/profile.d/zeek-path.sh >/dev/null
fi

# ---- 3. Suricata (OISF PPA) --------------------------------------------------
step "3. Suricata"
if command -v suricata >/dev/null 2>&1; then
  ok "Suricata zaten kurulu ($(suricata -V 2>/dev/null | head -1))"
else
  sudo add-apt-repository -y ppa:oisf/suricata-stable || warn "Suricata PPA eklenemedi (universe'e düşülecek)"
  sudo apt-get update -qq || true
  if apt_install suricata; then ok "Suricata kuruldu"; else warn "Suricata kurulamadı"; fi
fi
# Suricata kuralları (opsiyonel; yoksa sorun değil)
command -v suricata-update >/dev/null 2>&1 && (sudo suricata-update --no-test >/dev/null 2>&1 && ok "Suricata kuralları güncellendi" || warn "suricata-update atlandı")

# ---- 4. Docker --------------------------------------------------------------
step "4. Docker (Wazuh manager için)"
if command -v docker >/dev/null 2>&1; then
  ok "Docker zaten kurulu"
else
  if apt_install docker.io docker-compose-v2; then
    ok "Docker + compose kuruldu"
  else
    warn "docker.io/docker-compose-v2 kurulamadı — Wazuh için 'light' moda geçebilirsin."
  fi
fi
sudo systemctl enable --now docker 2>/dev/null && ok "docker servisi etkin" || warn "docker servisi başlatılamadı"

# ---- 5. Python venv + bağımlılıklar -----------------------------------------
step "5. Python ortamı (.venv) + pipeline bağımlılıkları"
# Anaconda'yı baypas et: sistem python'u kullan
SYS_PY=/usr/bin/python3
if [ ! -d .venv ]; then "$SYS_PY" -m venv .venv || warn ".venv oluşturulamadı"; fi
if [ -x .venv/bin/pip ]; then
  ./.venv/bin/pip install --upgrade pip -q || true
  if ./.venv/bin/pip install -q -r requirements.txt; then ok "Python bağımlılıkları kuruldu (.venv)"; else warn "pip install sorunlu — logu incele"; fi
  ./.venv/bin/python -c "import nfstream, sklearn, pandas, pyarrow" 2>/dev/null && ok "nfstream/sklearn/pandas/pyarrow doğrulandı" || warn "Bazı Python paketleri import edilemedi"
else
  warn ".venv/bin/pip yok; Python kurulumunu atla"
fi

# ---- 6. Kullanıcı grupları --------------------------------------------------
step "6. Kullanıcı grupları (kvm, libvirt, docker)"
CHANGED_GROUPS=0
for g in kvm libvirt docker; do
  if getent group "$g" >/dev/null 2>&1; then
    if id -nG "$USER" | tr ' ' '\n' | grep -qx "$g"; then
      ok "$USER zaten '$g' grubunda"
    else
      sudo usermod -aG "$g" "$USER" && { ok "$USER → '$g' grubuna eklendi"; CHANGED_GROUPS=1; }
    fi
  fi
done

# ---- 7. chrony: host'u izole ağ için NTP referansı yap ----------------------
step "7. chrony (host = izole ağın saat referansı)"
CHRONY_DROPIN="/etc/chrony/conf.d/ids-lab.conf"
if [ -d /etc/chrony/conf.d ]; then
  printf 'allow %s\nlocal stratum 10\n' "$NET_SUBNET" | sudo tee "$CHRONY_DROPIN" >/dev/null
  sudo systemctl restart chrony 2>/dev/null || sudo systemctl restart chronyd 2>/dev/null || warn "chrony yeniden başlatılamadı"
  ok "chrony $NET_SUBNET ağına NTP sunuyor (host saati referans)"
else
  warn "/etc/chrony/conf.d yok — chrony kurulumunu kontrol et"
fi

# ---- 8. izole ağı tanımla + başlat ------------------------------------------
step "8. İzole libvirt ağı: $NET_NAME"
if sudo virsh net-info "$NET_NAME" >/dev/null 2>&1; then
  ok "Ağ '$NET_NAME' zaten tanımlı"
else
  sudo virsh net-define testbed/net-isolated.xml && ok "Ağ tanımlandı" || warn "Ağ tanımlanamadı"
fi
sudo virsh net-autostart "$NET_NAME" >/dev/null 2>&1 || true
if ! sudo virsh net-info "$NET_NAME" 2>/dev/null | grep -qi 'Active:.*yes'; then
  sudo virsh net-start "$NET_NAME" && ok "Ağ başlatıldı" || warn "Ağ başlatılamadı"
else
  ok "Ağ zaten aktif"
fi
# İZOLASYON DOĞRULAMA: forward olmamalı
if sudo virsh net-dumpxml "$NET_NAME" 2>/dev/null | grep -q '<forward'; then
  die "GÜVENLİK: '$NET_NAME' ağında <forward> VAR — bu izole değil! net-isolated.xml'i düzelt."
else
  ok "İzolasyon doğrulandı: <forward> yok"
fi

# ---- 9. lab SSH anahtarı ----------------------------------------------------
step "9. İzole-lab SSH anahtarı"
if [ ! -f "$SSH_KEY" ]; then
  ssh-keygen -t ed25519 -N '' -f "$SSH_KEY" -C "ids-lab" >/dev/null && ok "Anahtar üretildi: $SSH_KEY" || warn "Anahtar üretilemedi"
else
  ok "Anahtar zaten var: $SSH_KEY"
fi
chmod 600 "$SSH_KEY" 2>/dev/null || true

# ---- özet -------------------------------------------------------------------
step "ÖZET"
echo "   Kurulu araçlar:"
for t in virsh virt-install cloud-localds zeek suricata tcpdump docker chronyc; do
  if command -v "$t" >/dev/null 2>&1 || { [ "$t" = zeek ] && [ -x /opt/zeek/bin/zeek ]; }; then
    printf "     ${c_g}✓${c_0} %s\n" "$t"
  else
    printf "     ${c_r}✗${c_0} %s\n" "$t"
  fi
done
if [ "${#WARNS[@]}" -gt 0 ]; then
  echo; echo "   ${c_y}Uyarılar (${#WARNS[@]}):${c_0}"
  for w in "${WARNS[@]}"; do echo "     - $w"; done
fi
if [ "$CHANGED_GROUPS" -eq 1 ]; then
  echo; echo "   ${c_y}ÖNEMLİ:${c_0} Grup değişiklikleri için ${c_b}oturumu kapatıp aç${c_0} (veya 'newgrp libvirt')."
fi
echo; echo "   Sonraki adım: ${c_b}./testbed/provision_vms.sh${c_0} (VM imajlarını indirir ve kurar)."
