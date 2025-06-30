#!/bin/bash
# Vollständiges VPS-Setup-Skript mit VPN-Option (WireGuard/NetBird)
# Autor: ChatGPT | Stand: Juni 2025

set -euo pipefail
IFS=$'\n\t'

### === KONFIGURATION === ###
read -rp "Neuer Benutzername: " NEW_USERNAME
read -rp "Öffentlicher SSH-Key: " PUBLIC_SSH_KEY
read -rp "WireGuard-Port [51820]: " WIREGUARD_PORT
WIREGUARD_PORT=${WIREGUARD_PORT:-51820}
read -rp "WireGuard VPS-IP [10.0.0.1]: " WG_SERVER_IP
WG_SERVER_IP=${WG_SERVER_IP:-10.0.0.1}
read -rp "WireGuard Client-IP [10.0.0.10]: " WG_CLIENT_IP
WG_CLIENT_IP=${WG_CLIENT_IP:-10.0.0.10}
read -rp "Discord Webhook URL (für Login-Alerts): " DISCORD_WEBHOOK_URL
### ======================= ###

log() { echo -e "\e[32m[INFO]\e[0m $*"; }
err() { echo -e "\e[31m[ERROR]\e[0m $*" >&2; exit 1; }
[[ $EUID -ne 0 ]] && err "Dieses Skript muss als Root ausgeführt werden."

### === System vorbereiten === ###
log "System wird aktualisiert..."
apt update && apt -y upgrade
apt install -y sudo curl gnupg ufw software-properties-common neofetch lsb-release

### === Benutzer + SSH === ###
read -rp "Alternative SSH-Portnummer (Standard 22): " SSH_PORT
SSH_PORT=${SSH_PORT:-22}
if ! id "$NEW_USERNAME" &>/dev/null; then
  log "Benutzer '$NEW_USERNAME' wird erstellt..."
  adduser --disabled-password --gecos "" "$NEW_USERNAME"
  usermod -aG sudo "$NEW_USERNAME"
fi
mkdir -p /home/$NEW_USERNAME/.ssh
echo "$PUBLIC_SSH_KEY" > /home/$NEW_USERNAME/.ssh/authorized_keys
chmod 700 /home/$NEW_USERNAME/.ssh
chmod 600 /home/$NEW_USERNAME/.ssh/authorized_keys
chown -R $NEW_USERNAME:$NEW_USERNAME /home/$NEW_USERNAME/.ssh

sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i "s/^#Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config || echo "Port $SSH_PORT" >> /etc/ssh/sshd_config
sed -i "s/^Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config || echo "Port $SSH_PORT" >> /etc/ssh/sshd_config
systemctl reload sshd

ufw allow $SSH_PORT/tcp
ufw --force enable

apt install -y unattended-upgrades
systemctl enable --now unattended-upgrades
dpkg-reconfigure -f noninteractive unattended-upgrades
mkdir -p /etc/apt/apt.conf.d
cat > /etc/apt/apt.conf.d/51-auto-reboot <<EOF
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
EOF

### === CrowdSec === ###
if ! command -v crowdsec &>/dev/null; then
  log "CrowdSec wird installiert..."
  curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
  apt install -y crowdsec
fi
read -rp "CrowdSec Console Enrollment Key (leer lassen zum Überspringen): " CROWDSEC_KEY
if [[ -n "$CROWDSEC_KEY" ]]; then
  cscli console enroll "$CROWDSEC_KEY" || log "CrowdSec Anmeldung fehlgeschlagen (optional)."
fi

### === VPS Metadaten === ###
log "VPS-Metadaten erfassen..."
read -rp "VPS-Name (hostname): " VPS_NAME
read -rp "Umgebung (z. B. PROD / DEV): " VPS_ENV
read -rp "Rolle (z. B. Webserver): " VPS_ROLE
read -rp "Standort (z. B. Hetzner FSN1): " VPS_LOCATION

cat > /etc/vps-meta.conf <<EOF
Name=$VPS_NAME
Umgebung=$VPS_ENV
Rolle=$VPS_ROLE
Standort=$VPS_LOCATION
EOF

### === MOTD + Root-Warnung === ###
log "MOTD wird eingerichtet..."
echo -e "\n\e[33m⚠️  Warnung: Du bist als root eingeloggt.\e[0m\n" > /etc/motd

cat > /etc/update-motd.d/10-premium-motd <<'EOF'
#!/bin/bash
[ -f /etc/vps-meta.conf ] && source /etc/vps-meta.conf
ascii=$(neofetch --ascii --colors 4 6 1 8 9 5 --ascii_distro "$(lsb_release -is)" --stdout | head -n 10)
HOSTNAME=${Name:-$(hostname)}
DISTRO=$(lsb_release -ds)
KERNEL=$(uname -r)
UPTIME=$(uptime -p)
LOAD=$(cut -d ' ' -f1-3 /proc/loadavg)
CPU=$(lscpu | grep '^CPU(s):' | awk '{print $2}')
CPUMODEL=$(lscpu | grep 'Model name' | awk -F: '{print $2}' | xargs)
MEM=$(free -h | awk '/^Mem:/ {print $3 " / " $2}')
DISK=$(df -h / | awk 'NR==2 {print $5}')
USERS=$(who | wc -l)
echo "$ascii"
printf " %-18s: %s | %s | %s\n" "$HOSTNAME" "${Umgebung:-N/A}" "${Rolle:-N/A}"
printf " Standort         : %s\n" "${Standort:-Unbekannt}"
printf " System           : %s (%s)\n" "$DISTRO" "$(uname -m)"
printf " Kernel           : %s\n" "$KERNEL"
printf " Uptime/Load      : %s | %s\n" "$UPTIME" "$LOAD"
printf " CPU              : %s × %s\n" "$CPU" "$CPUMODEL"
printf " RAM              : %s\n" "$MEM"
printf " Disk /           : %s voll\n" "$DISK"
printf " Benutzer aktiv   : %s\n" "$USERS"
DISK_INT=$(echo "$DISK" | tr -d '%')
[ "$DISK_INT" -ge 85 ] && echo -e "\e[31m⚠️  Achtung: Root-Partition ist zu $DISK voll!\e[0m"
UPDATES=$(apt list --upgradable 2>/dev/null | grep -c '^')
[ "$UPDATES" -gt 0 ] && echo -e "\e[33m📦  $UPDATES Updates verfügbar\e[0m"
EOF
chmod +x /etc/update-motd.d/10-premium-motd
find /etc/update-motd.d -type f ! -name '10-premium-motd' -exec chmod -x {} +

### === Bash Hardening === ###
log "Shell-Hardening wird eingerichtet..."
for user in root $NEW_USERNAME; do
  user_home=$(eval echo "~$user")
  echo "export HISTTIMEFORMAT='%F %T '" >> $user_home/.bashrc
  echo "alias ll='ls -alF'" >> $user_home/.bashrc
  echo "alias la='ls -A'" >> $user_home/.bashrc
  echo "alias l='ls -CF'" >> $user_home/.bashrc
  chown $user:$user $user_home/.bashrc || true
  chmod 644 $user_home/.bashrc || true
done

### === SSH Login Benachrichtigung (Discord) === ###
log "SSH Login-Benachrichtigung via Discord aktivieren..."
cat > /etc/profile.d/ssh-discord-alert.sh <<EOF
#!/bin/bash
if [[ -n "\$SSH_CONNECTION" ]]; then
  HOSTNAME=\$(hostname)
  IP=\$(echo \$SSH_CONNECTION | awk '{print \$1}')
  USER=\$(whoami)
  curl -H "Content-Type: application/json" -X POST -d "{\"content\": \"🔐 SSH Login auf \\$HOSTNAME durch Benutzer \\$USER von IP \\$IP\"}" "$DISCORD_WEBHOOK_URL" >/dev/null 2>&1 || true
fi
EOF
chmod +x /etc/profile.d/ssh-discord-alert.sh

### === VPN Auswahl === ###
echo "VPN-Setup wählen:
1) Klassisches WireGuard
2) NetBird Agent (Overlay VPN)
3) Überspringen"
read -rp "Auswahl (1/2/3): " VPN_CHOICE

if [[ "$VPN_CHOICE" == "1" ]]; then
  log "WireGuard wird installiert..."
  apt install -y wireguard qrencode
  mkdir -p /etc/wireguard
  umask 077
  wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
  PRIVKEY=$(< /etc/wireguard/privatekey)
  PUBKEY=$(< /etc/wireguard/publickey)
  cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = $WG_SERVER_IP/24
SaveConfig = true
PrivateKey = $PRIVKEY
ListenPort = $WIREGUARD_PORT
EOF
  systemctl enable wg-quick@wg0 && systemctl start wg-quick@wg0

  log "WireGuard Peer für Windows-Client erzeugen:"
  read -rp "Dein Client Public Key: " CLIENT_PUB
  cat <<CONF > /tmp/wg-peer-client.conf
[Peer]
PublicKey = $CLIENT_PUB
AllowedIPs = $WG_CLIENT_IP/32
CONF
  cat /tmp/wg-peer-client.conf >> /etc/wireguard/wg0.conf

  echo "\n--- Füge das Folgende in deine WireGuard-App ein: ---"
  cat <<CONF
[Interface]
PrivateKey = <DEIN_CLIENT_PRIVATE_KEY>
Address = $WG_CLIENT_IP/24

[Peer]
PublicKey = $PUBKEY
Endpoint = $(hostname -I | awk '{print $1}'):$WIREGUARD_PORT
AllowedIPs = $WG_SERVER_IP/32
PersistentKeepalive = 25
CONF
  echo "--- Ende ---\n"

elif [[ "$VPN_CHOICE" == "2" ]]; then
  log "NetBird wird installiert..."
  curl -fsSL https://pkgs.netbird.io/install.sh | bash
  read -rp "NetBird Setup Key: " NETBIRD_SETUP_KEY
  read -rp "NetBird Control Plane Domain [app.netbird.io]: " NETBIRD_CONTROL_PLANE
  NETBIRD_CONTROL_PLANE=${NETBIRD_CONTROL_PLANE:-app.netbird.io}
  netbird up --setup-key "$NETBIRD_SETUP_KEY" --management-url "https://$NETBIRD_CONTROL_PLANE"
  netbird status
fi

log "Setup abgeschlossen ✅. Du kannst dich nun mit $NEW_USERNAME einloggen."
