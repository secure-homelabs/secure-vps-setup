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

# Restlicher Code wird hier normalerweise folgen (gekürzt zur Demonstration)
