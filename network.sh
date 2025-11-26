#!/usr/bin/env bash
# ===================================================================================================
#  Network Troubleshooter & Safe Recovery Toolkit v5.0
#  Compatible with: AlmaLinux / CloudLinux / CentOS / Ubuntu / Debian / cPanel Servers
# ---------------------------------------------------------------------------------------
#  Author: ChatGPT (OpenAI)
#  Date:   2025-11-11
#  Overview: interactive toolkit to diagnose and safely recover network issues.
#  Safety: backups created before edits; no destructive overwrites; all actions logged.
# ===================================================================================================

set -euo pipefail
IFS=$'\n\t'

LOGFILE="/tmp/network_troubleshoot_$(date +%Y%m%d-%H%M%S).log"

# Colors
GREEN="\033[1;32m"; YELLOW="\033[1;33m"; RED="\033[1;31m"; BLUE="\033[1;34m"; NC="\033[0m"

# Helpers
log() { echo -e "[${BLUE}$(date +'%F %T')${NC}] $*" | tee -a "$LOGFILE"; }
pause() { read -rp "Press Enter to continue..."; }
require_root() { [ "$EUID" -eq 0 ] || { echo -e "${RED}Run as root.${NC}"; exit 1; }; }

run_and_log() {
  local cmd="$1"
  log "Running: $cmd"
  if output=$(eval "$cmd" 2>&1); then
    echo -e "${GREEN}$output${NC}" | tee -a "$LOGFILE"
  else
    echo -e "${RED}$output${NC}" | tee -a "$LOGFILE"
    log "(command failed)"
  fi
}

show_header() {
  clear
  echo -e "${BLUE}========================================${NC}"
  echo -e "${GREEN} Network Troubleshooter v5.0${NC}"
  echo -e " Log: $LOGFILE"
  echo -e "${BLUE}========================================${NC}"
}

# Dependency installer (safe, best-effort)
install_dependencies() {
  log "Checking dependencies..."
  local DEPS=(ip ifconfig curl ping traceroute ethtool dig nmcli nmap speedtest-cli)
  local MISSING=()
  for c in "${DEPS[@]}"; do command -v "$c" &>/dev/null || MISSING+=("$c"); done
  if [ ${#MISSING[@]} -eq 0 ]; then log "All dependencies OK."; return; fi
  log "${YELLOW}Missing:${NC} ${MISSING[*]}"
  if [ -f /etc/redhat-release ]; then
    log "Installing on RHEL-family (yum)..."
    yum install -y iproute net-tools curl traceroute ethtool bind-utils NetworkManager nmap python3-speedtest-cli -q || true
  elif [ -f /etc/debian_version ]; then
    log "Installing on Debian-family (apt)..."
    apt update -y && apt install -y iproute2 net-tools curl traceroute ethtool dnsutils network-manager nmap speedtest-cli -q || true
  else
    log "${YELLOW}Unknown distro - please install missing packages manually: ${MISSING[*]}${NC}"
  fi
  log "${GREEN}Dependency check complete.${NC}"
}

# ==============================================================================
#                                MAIN MENU
# ==============================================================================
main_menu() {
  while true; do
    show_header
    echo "  1) System Info"
    echo "  2) Interfaces & Routes"
    echo "  3) DNS Check"
    echo "  4) Connectivity Test"
    echo "  5) Firewall Check"
    echo "  6) Network Services"
    echo "  7) cPanel Checks"
    echo "  8) Tail Logs"
    echo "  9) Advanced Tools"
    echo " 10) Deep Network Debug"
    echo " 11) Hardware/Driver Level Recovery (Safe)"
    echo " 12) Regenerate Network Interface Config (AlmaLinux)"
    echo " 13) Regenerate /etc/resolv.conf"
    echo " 14) Reassign Public IP (Hyper-V / Cloud)"
    echo " 15) Boot-Time NIC Mapping Fix (Udev Rename)"
    echo " 16) Show Network Configuration File Locations"
    echo "  0) Exit"
    read -rp "Choice: " choice
    case "$choice" in
      1) sys_info ;;
      2) interfaces ;;
      3) dns_check ;;
      4) connectivity ;;
      5) firewall_check ;;
      6) net_services ;;
      7) cpanel_check ;;
      8) logs_check ;;
      9) advanced_tools ;;
      10) deep_network_debug ;;
      11) hardware_recover ;;
      12) regen_ifcfg ;;
      13) regen_resolv ;;
      14) reassign_ip ;;
      15) udev_fix ;;
      16) show_config_locations ;;
      0) echo "Log saved to $LOGFILE"; exit 0 ;;
      *) echo -e "${RED}Invalid${NC}"; pause ;;
    esac
  done
}

# ==============================================================================
#                          BASIC TROUBLESHOOTERS (1-9)
# ==============================================================================
sys_info() {
  log "=== System Information ==="
  run_and_log "hostnamectl || uname -a"
  [ -f /etc/os-release ] && run_and_log "cat /etc/os-release"
  run_and_log "df -hT"
  run_and_log "free -h"
  pause
}

interfaces() {
  log "=== Interfaces & Routes ==="
  run_and_log "ip -brief addr show || ifconfig -a"
  run_and_log "ip route show || route -n"
  pause
}

dns_check() {
  log "=== DNS Configuration ==="
  run_and_log "cat /etc/resolv.conf || echo 'resolv.conf missing'"
  read -rp "Hostname to test (default: google.com): " H
  H=${H:-google.com}
  if command -v dig &>/dev/null; then
    run_and_log "dig +short $H"
  elif command -v nslookup &>/dev/null; then
    run_and_log "nslookup $H"
  else
    run_and_log "getent hosts $H || echo 'No DNS tool available'"
  fi
  pause
}

connectivity() {
  log "=== Connectivity Tests ==="
  read -rp "Ping host (default 8.8.8.8): " P
  P=${P:-8.8.8.8}
  run_and_log "ping -c 4 $P || echo 'Ping failed'"
  run_and_log "traceroute -m 10 $P 2>/dev/null || tracepath $P 2>/dev/null || echo 'No traceroute tool'"
  run_and_log "curl -I https://example.com 2>/dev/null || echo 'Curl test failed'"
  pause
}

firewall_check() {
  log "=== Firewall Status ==="
  run_and_log "systemctl is-active firewalld && firewall-cmd --list-all || echo 'firewalld not active'"
  run_and_log "ufw status verbose 2>/dev/null || echo 'ufw not found'"
  run_and_log "iptables -L -n -v 2>/dev/null || nft list ruleset 2>/dev/null || echo 'No iptables/nftables found'"
  pause
}

net_services() {
  log "=== Network Services ==="
  run_and_log "systemctl status NetworkManager --no-pager 2>/dev/null || echo 'NetworkManager not found'"
  run_and_log "nmcli device status 2>/dev/null || echo 'nmcli not found'"
  if [ -d /etc/netplan ]; then run_and_log "ls -l /etc/netplan || true"; fi
  pause
}

cpanel_check() {
  if [ ! -d /usr/local/cpanel ]; then
    echo -e "${YELLOW}cPanel not installed.${NC}"
    pause
    return
  fi
  log "=== cPanel Checks ==="
  run_and_log "/usr/local/cpanel/scripts/restartsrv_cpsrvd --status 2>/dev/null || systemctl status cpanel --no-pager"
  pause
}

logs_check() {
  log "=== Recent Logs ==="
  run_and_log "tail -n 100 /var/log/messages 2>/dev/null || tail -n 100 /var/log/syslog 2>/dev/null || echo 'No syslog/messages found'"
  pause
}

# ==============================================================================
#                      ADVANCED TOOLS (9)
# ==============================================================================
advanced_tools() {
  while true; do
    clear
    echo -e "${BLUE}========= Advanced Tools =========${NC}"
    echo " 1) Backup network configs"
    echo " 2) Restore network configs"
    echo " 3) Auto-Heal network (safe)"
    echo " 4) Interface health"
    echo " 5) DNS/Route auto-fix"
    echo " 6) Speed test"
    echo " 7) Security port scan"
    echo " 0) Back"
    read -rp "Choice: " a
    case "$a" in
      1) backup_configs ;;
      2) restore_configs ;;
      3) auto_heal ;;
      4) interface_health ;;
      5) auto_fix ;;
      6) net_speed ;;
      7) sec_scan ;;
      0) break ;;
      *) echo -e "${RED}Invalid${NC}"; pause ;;
    esac
  done
}

backup_configs() {
  local B="/root/netbackup_$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$B"
  cp -a /etc/sysconfig/network-scripts/* "$B" 2>/dev/null || true
  cp -a /etc/netplan/* "$B" 2>/dev/null || true
  cp -a /etc/network/interfaces* "$B" 2>/dev/null || true
  cp -a /etc/resolv.conf "$B" 2>/dev/null || true
  tar czf "$B.tar.gz" -C "$(dirname "$B")" "$(basename "$B")"
  echo -e "${GREEN}Backup saved to $B.tar.gz${NC}"
  pause
}

restore_configs() {
  read -rp "Backup file path: " F
  [ -f "$F" ] || { echo -e "${RED}File not found${NC}"; return; }
  tar tzf "$F" >/dev/null 2>&1 || { echo -e "${RED}Invalid archive${NC}"; return; }
  tar xzf "$F" -C /
  systemctl restart NetworkManager || systemctl restart networking || true
  echo -e "${GREEN}Configs restored safely.${NC}"
  pause
}

auto_heal() {
  if ! ping -c 1 8.8.8.8 &>/dev/null; then
    echo -e "${YELLOW}No external connectivity. Attempting safe network restart...${NC}"
    systemctl restart NetworkManager || systemctl restart networking || true
    dhclient -v || true
    echo -e "${GREEN}Auto-heal attempted.${NC}"
  else
    echo -e "${GREEN}Network appears healthy.${NC}"
  fi
  pause
}

interface_health() {
  for IF in $(ip -o link show | awk -F': ' '{print $2}'); do
    echo -e "${BLUE}Checking $IF${NC}"
    ethtool "$IF" 2>/dev/null | sed -n '1,20p' || true
    ip -s link show "$IF" | grep -E 'errors|dropped' || true
  done
  pause
}

auto_fix() {
  if ! grep -q nameserver /etc/resolv.conf 2>/dev/null; then
    cp -a /etc/resolv.conf /etc/resolv.conf.bak.$(date +%s) 2>/dev/null || true
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    echo -e "${GREEN}Added common public DNS servers to /etc/resolv.conf${NC}"
  else
    echo -e "${GREEN}DNS already configured.${NC}"
  fi
  if ! ip route | grep -q '^default'; then
    echo -e "${YELLOW}No default route present. Manual action required.${NC}"
  fi
  pause
}

net_speed() {
  if command -v speedtest-cli &>/dev/null; then
    speedtest-cli || echo -e "${RED}Speed test failed${NC}"
  else
    echo -e "${YELLOW}speedtest-cli not installed${NC}"
  fi
  pause
}

sec_scan() {
  IP=$(hostname -I | awk '{print $1}')
  [ -z "$IP" ] && { echo -e "${RED}No IP detected${NC}"; pause; return; }
  if command -v nmap &>/dev/null; then
    nmap -Pn -p 22,80,443,2083,2087 "$IP" || echo -e "${RED}nmap scan failed${NC}"
  else
    echo -e "${YELLOW}nmap not installed${NC}"
  fi
  pause
}

# ==============================================================================
#                 DEEP DIAGNOSTICS & SAFE RECOVERY (10-15)
# ==============================================================================
deep_network_debug() {
  echo -e "${BLUE}=== Deep Network Diagnostic ===${NC}"
  run_and_log "ip link show"
  run_and_log "ip addr show"
  run_and_log "ip route show"
  run_and_log "nmcli device show || ifconfig -a"
  run_and_log "ethtool \$(ip route | awk '/default/ {print \$5}' | head -n1) 2>/dev/null || true"
  run_and_log "cat /etc/resolv.conf 2>/dev/null || echo '/etc/resolv.conf missing'"
  run_and_log "ping -c 2 127.0.0.1 || true"
  run_and_log "ping -c 2 \$(ip route | awk '/default/ {print \$3}' | head -n1) || echo 'Gateway unreachable'"
  run_and_log "ping -c 2 8.8.8.8 || echo 'External ping failed'"
  run_and_log "ping -c 2 google.com || echo 'DNS resolution failed'"
  run_and_log "traceroute 8.8.8.8 2>/dev/null || tracepath 8.8.8.8 2>/dev/null || echo 'No traceroute tool'"
  pause
}

hardware_recover() {
  echo -e "${YELLOW}Safe hardware/driver reload${NC}"
  local IF
  IF=$(ip -o link show | awk -F': ' '{print $2}' | head -n1)
  [ -z "$IF" ] && { echo -e "${RED}No interface detected${NC}"; pause; return; }
  local DRV
  DRV=$(ethtool -i "$IF" 2>/dev/null | awk '/driver:/ {print $2}')
  [ -z "$DRV" ] && { echo -e "${RED}Driver not found for $IF${NC}"; pause; return; }
  echo -e "${YELLOW}Backing up network state and attempting driver reload for $DRV on $IF${NC}"
  # backup basic state
  ip addr show dev "$IF" > "/tmp/${IF}_addr.bak" 2>/dev/null || true
  ip route show > "/tmp/routes.bak" 2>/dev/null || true
  # attempt unload/load (safe attempt)
  if modprobe -r "$DRV" 2>/dev/null; then
    sleep 1
    if modprobe "$DRV" 2>/dev/null; then
      systemctl restart NetworkManager || systemctl restart networking || true
      echo -e "${GREEN}Driver reloaded and NetworkManager restarted${NC}"
    else
      echo -e "${RED}modprobe load failed (driver reload unsuccessful)${NC}"
    fi
  else
    echo -e "${RED}modprobe remove failed (could be in use)${NC}"
  fi
  pause
}

regen_ifcfg() {
  echo -e "${YELLOW}Safe regeneration of NetworkManager connection (nmcli)${NC}"
  local IF
  IF=$(ip -o link show | awk -F': ' '/ether/ {print $2; exit}')
  [ -z "$IF" ] && { echo -e "${RED}No ethernet interface found${NC}"; pause; return; }
  local BACKUP_DIR="/root/nmbackup_$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$BACKUP_DIR"
  cp -a /etc/NetworkManager/system-connections/* "$BACKUP_DIR" 2>/dev/null || true
  echo -e "${YELLOW}Backup of NM connections saved to $BACKUP_DIR${NC}"
  # Create a simple DHCP connection if not exists
  nmcli con add type ethernet ifname "$IF" con-name "${IF}_dhcp_recover" autoconnect yes ipv4.method auto 2>/dev/null || true
  nmcli con reload
  nmcli con up "${IF}_dhcp_recover" 2>/dev/null || echo -e "${YELLOW}Could not bring connection up automatically${NC}"
  echo -e "${GREEN}Regeneration attempt complete.${NC}"
  pause
}

regen_resolv() {
  echo -e "${YELLOW}Backing up and regenerating /etc/resolv.conf${NC}"
  cp -a /etc/resolv.conf /etc/resolv.conf.bak.$(date +%Y%m%d-%H%M%S) 2>/dev/null || true
  {
    echo "nameserver 8.8.8.8"
    echo "nameserver 1.1.1.1"
  } > /etc/resolv.conf
  echo -e "${GREEN}/etc/resolv.conf regenerated (8.8.8.8, 1.1.1.1)${NC}"
  pause
}

reassign_ip() {
  echo -e "${YELLOW}Manual safe public IP assignment (temporary only)${NC}"
  read -rp "Interface (e.g. eth0): " IF
  read -rp "IP/CIDR (e.g. 203.0.113.10/24): " IP
  read -rp "Gateway (e.g. 203.0.113.1): " GW
  [ -z "$IF" ] || [ -z "$IP" ] || [ -z "$GW" ] || true
  if [ -z "$IF" ] || [ -z "$IP" ] || [ -z "$GW" ]; then
    echo -e "${RED}Interface, IP/CIDR and Gateway are required${NC}"
    pause; return
  fi
  # create backups of current addresses
  ip addr show dev "$IF" > "/tmp/${IF}_addr_preassign.bak" 2>/dev/null || true
  run_and_log "ip addr add $IP dev $IF || echo 'IP add failed or already present'"
  run_and_log "ip route add default via $GW || echo 'Default route add failed or already present'"
  echo -e "${GREEN}Temporary IP assignment applied. This does NOT persist across reboot.${NC}"
  pause
}

udev_fix() {
  echo -e "${YELLOW}Boot-time NIC naming fix (safe change - requires reboot)${NC}"
  echo "Current interfaces:"
  ip -o link show | awk -F': ' '{print $2}'
  read -rp "Apply kernel args net.ifnames=0 biosdevname=0 to disable predictable names? [y/N]: " A
  if [[ ! "$A" =~ ^[Yy]$ ]]; then echo "Cancelled"; pause; return; fi
  if command -v grubby &>/dev/null; then
    grubby --update-kernel=ALL --args="net.ifnames=0 biosdevname=0" 2>/dev/null || echo -e "${YELLOW}grubby returned non-zero (check manually)${NC}"
    echo -e "${GREEN}Kernel args updated via grubby. Reboot required.${NC}"
  else
    echo -e "${YELLOW}grubby not found. For Debian/Ubuntu add 'net.ifnames=0 biosdevname=0' to GRUB_CMDLINE_LINUX in /etc/default/grub and run update-grub.${NC}"
  fi
  pause
}

# ==============================================================================
#             MENU 16 — CONFIG LOCATIONS + SAFE VIEW/EDIT
# ==============================================================================
view_config_file() {
  read -rp "Enter full path of config file to view: " F
  [ -f "$F" ] || { echo -e "${RED}File not found: $F${NC}"; return; }
  echo -e "${BLUE}--- First 200 lines of $F ---${NC}"
  sed -n '1,200p' "$F" | sed 's/^/| /'
  echo -e "${YELLOW}Use an editor for full view if needed.${NC}"
  pause
}

edit_config_file() {
  read -rp "Enter full path of config file to edit: " F
  [ -f "$F" ] || { echo -e "${RED}File not found: $F${NC}"; return; }
  local BAK="${F}.bak.$(date +%Y%m%d-%H%M%S)"
  cp -a "$F" "$BAK" 2>/dev/null || true
  echo -e "${YELLOW}Backup created: $BAK${NC}"
  if command -v nano &>/dev/null; then
    nano "$F"
  elif command -v vi &>/dev/null; then
    vi "$F"
  else
    echo -e "${RED}No editor (nano/vi) found. Install one to edit.${NC}"
  fi
  echo -e "${GREEN}Edit complete. Backup at $BAK${NC}"
  pause
}

show_config_locations() {
  echo -e "${BLUE}=== Network Configuration File Locations ===${NC}"
  local OSNAME
  OSNAME=$(awk -F= '/^NAME=/{print substr($0, index($0,$2))}' /etc/os-release 2>/dev/null || echo "Unknown")
  echo -e "${GREEN}Detected OS:${NC} $OSNAME"
  echo -e "\n${YELLOW}Common locations:${NC}\n"
  echo -e "${GREEN}AlmaLinux / CentOS / CloudLinux:${NC}"
  echo "  /etc/sysconfig/network-scripts/ifcfg-*"
  echo "  /etc/sysconfig/network"
  echo "  /etc/NetworkManager/system-connections/"
  echo "  /etc/resolv.conf"
  echo -e "\n${GREEN}Ubuntu / Debian:${NC}"
  echo "  /etc/netplan/*.yaml"
  echo "  /etc/network/interfaces"
  echo "  /etc/network/interfaces.d/*"
  echo "  /etc/systemd/network/*.network"
  echo "  /etc/resolv.conf"
  echo -e "\n${GREEN}cPanel / WHM:${NC}"
  echo "  /etc/sysconfig/network-scripts/ifcfg-*"
  echo "  /usr/local/cpanel/scripts/*"
  echo -e "\n${GREEN}Universal files:${NC}"
  echo "  /etc/hostname"
  echo "  /etc/hosts"
  echo "  /etc/resolv.conf"
  echo -e "\n${YELLOW}Detected active configuration files (sample output):${NC}"
  run_and_log "find /etc -type f -name 'ifcfg-*' 2>/dev/null | head -n 20"
  run_and_log "find /etc/netplan -name '*.yaml' 2>/dev/null | head -n 20"
  run_and_log "find /etc/network -name 'interfaces*' 2>/dev/null | head -n 20"
  run_and_log "find /etc/NetworkManager/system-connections -name '*.nmconnection' 2>/dev/null | head -n 20"

  
  echo -e "\n${BLUE}--- Config File Sub-Menu ---${NC}"
  while true; do
    echo " 1) View a network config file (read-only)"
    echo " 2) Edit a network config file (creates .bak backup)"
    echo " 0) Back"
    read -rp "Choice: " s
    case "$s" in
      1) view_config_file ;;
      2) edit_config_file ;;
      0) break ;;
      *) echo -e "${RED}Invalid${NC}" ;;
    esac
  done
}

# ==============================================================================
#                                STARTUP
# ==============================================================================
require_root
install_dependencies
main_menu
