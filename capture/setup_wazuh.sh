#!/usr/bin/env bash
# =============================================================================
# setup_wazuh.sh — host modu (çok-modlu kısım). Doc Bölüm 6.
#   A) HOST: wazuh-manager container (Docker). Sadece manager — indexer/dashboard
#      YOK (merge_hostlogs yalnız alerts.json okur → hafif). Portlar: 1514 (olay),
#      1515 (kayıt/authd).
#   B) VICTIM: wazuh-agent (offline kurulum: NAT geçici tak→kur→sök). Manager
#      adresi = host'un izole IP'si (10.10.10.1). Agent izole ağ üzerinden enroll
#      olur ve olay gönderir.
#
# Çalıştır:  ./capture/setup_wazuh.sh   (sudo: docker + NAT tak/sök)
# Idempotent.
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
DOCKER="sudo docker"
NAT_MAC="52:54:00:12:34:30"   # victim nat mac
VER="$WAZUH_VERSION"
MGR="$WAZUH_MANAGER_NAME"
sudo -v || die "sudo gerekli"
( while true; do sudo -n true; sleep 50; done ) 2>/dev/null & KEEP=$!; trap 'kill $KEEP 2>/dev/null||true' EXIT

vssh(){ ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=8 -o BatchMode=yes "${VICTIM_USER}@${VICTIM_IP}" "$@"; }

# ============ A) HOST: wazuh-manager container ============
step "A. Wazuh manager (host, Docker) — sürüm $VER"
if $DOCKER ps -a --format '{{.Names}}' | grep -qx "$MGR"; then
  $DOCKER start "$MGR" >/dev/null 2>&1 || true
  ok "Manager container zaten var (başlatıldı)"
else
  echo "   imaj çekiliyor: wazuh/wazuh-manager:$VER"
  $DOCKER pull "wazuh/wazuh-manager:$VER" || die "manager imajı çekilemedi"
  $DOCKER run -d --name "$MGR" --restart unless-stopped \
    -p 1514:1514 -p 1515:1515 -p 514:514/udp \
    "wazuh/wazuh-manager:$VER" || die "manager başlatılamadı"
  ok "Manager container başlatıldı"
fi

echo "   manager hazır olması bekleniyor (authd/analysisd)..."
t=0; ready=0
while [ $t -lt 180 ]; do
  if $DOCKER exec "$MGR" /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q 'wazuh-authd is running'; then ready=1; break; fi
  sleep 5; t=$((t+5)); echo -n "."
done
echo
[ $ready -eq 1 ] && ok "Manager çalışıyor (authd ayakta)" || warn "authd durumu doğrulanamadı; yine de devam"

# ============ B) VICTIM: wazuh-agent (offline, NAT ile) ============
step "B. Wazuh agent (victim) — offline kurulum"
# zaten kurulu + bağlı mı?
if vssh 'test -f /var/ossec/bin/wazuh-control' 2>/dev/null; then
  ok "Agent zaten kurulu (victim)"
else
  $VIRSH domstate "$VICTIM_NAME" 2>/dev/null | grep -qi running || { $VIRSH start "$VICTIM_NAME"; sleep 8; }
  # NAT tak
  if $VIRSH domiflist "$VICTIM_NAME" | grep -qi "$NAT_MAC"; then ok "NAT zaten takılı"; else
    $VIRSH attach-interface "$VICTIM_NAME" network default --model virtio --mac "$NAT_MAC" --live && ok "NAT takıldı" || die "NAT takılamadı"
  fi
  # internet aç
  vssh 'bash -s' <<'EOS'
sudo netplan apply 2>/dev/null || true; sleep 4
if ! ping -c1 -W3 8.8.8.8 >/dev/null 2>&1; then
  for i in $(ls /sys/class/net | grep -v '^lo$'); do
    ip -4 addr show "$i" 2>/dev/null | grep -q '10\.10\.10\.' && continue
    sudo timeout 20 dhclient -v "$i" >/dev/null 2>&1 &
  done; sleep 8
fi
EOS
  [ "$(vssh 'ping -c1 -W3 8.8.8.8 >/dev/null 2>&1 && echo OK || echo FAIL')" = OK ] \
    && ok "Victim internete çıkıyor (geçici)" || die "Victim internete çıkamadı"

  # repo + agent kur (manager adresi env ile gömülür)
  echo "   agent kuruluyor (manager=$WAZUH_MANAGER_ADDR)..."
  vssh "bash -s" <<EOS
set -e
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --yes --dearmor -o /usr/share/keyrings/wazuh.gpg
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update -y
sudo WAZUH_MANAGER="$WAZUH_MANAGER_ADDR" DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-agent=${VER}-1 || \
sudo WAZUH_MANAGER="$WAZUH_MANAGER_ADDR" DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-agent
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
EOS
  ok "Agent kuruldu"

  # NAT sök → izole
  $VIRSH detach-interface "$VICTIM_NAME" network --mac "$NAT_MAC" --live && ok "NAT söküldü" || warn "NAT sökülemedi (elle sök)"
  vssh 'sudo ip route del default 2>/dev/null; sudo netplan apply 2>/dev/null; true' || true
  vssh 'ping -c1 -W3 8.8.8.8 >/dev/null 2>&1' && die "İHLAL: victim internette!" || ok "Victim tekrar izole"
fi

# agent'ı başlat (izole ağ üzerinden manager'a enroll olur)
step "C. Agent'ı başlat + bağlantıyı doğrula"
vssh 'sudo systemctl restart wazuh-agent' || warn "agent başlatılamadı"
echo "   enroll + bağlantı bekleniyor..."
sleep 20
echo "   --- manager tarafı ajan listesi ---"
$DOCKER exec "$MGR" /var/ossec/bin/agent_control -l 2>/dev/null | sed 's/^/   /' || \
  $DOCKER exec "$MGR" /var/ossec/bin/manage_agents -l 2>/dev/null | sed 's/^/   /' || warn "ajan listesi alınamadı"
echo "   --- victim agent durumu ---"
vssh 'sudo systemctl is-active wazuh-agent; sudo tail -3 /var/ossec/logs/ossec.log 2>/dev/null' | sed 's/^/   /' || true

echo
ok "Wazuh kurulumu bitti. Oturumda alerts.json otomatik çekilecek (run_session)."
echo "   Elle test: $DOCKER exec $MGR cat /var/ossec/logs/alerts/alerts.json | tail"
