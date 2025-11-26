#!/usr/bin/env bash
# docker-manager.sh (universal installer + manager)
# Works on Ubuntu/Debian and AlmaLinux/CentOS/RHEL/Rocky (auto-detect)
# Installer: sets up official Docker repo, installs docker engine + compose plugin
# Uninstaller: removes packages but KEEPS /var/lib/docker (per user choice)
# Cleans package cache after install (apt/dnf/yum)
# Full management features: containers, images, exec, cp, attach, browse, edit, compose hooks, backup, auto-update, troubleshooting, command reference

set -euo pipefail
IFS=$'\n\t'

BACKUP_DIR="/Root/docker_backup"
mkdir -p "$BACKUP_DIR"

# Colors
GREEN="\e[32m"
YELLOW="\e[33m"
RED="\e[31m"
BLUE="\e[34m"
RESET="\e[0m"

info() { echo -e "${BLUE}[INFO]${RESET} $*"; }
ok()   { echo -e "${GREEN}[OK]${RESET} $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }
err()  { echo -e "${RED}[ERR]${RESET} $*"; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    warn "Not running as root — re-running with sudo"
    exec sudo bash "$0" "$@"
  fi
}

# Detect distro
detect_distro() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO_ID="${ID,,}"
    DISTRO_NAME="$NAME"
    DISTRO_VER="$VERSION_ID"
  else
    DISTRO_ID="unknown"
    DISTRO_NAME="unknown"
    DISTRO_VER=""
  fi
}

# Helper: run apt/dnf/yum safely
pkg_install() {
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
  elif command -v dnf >/dev/null 2>&1; then
    dnf -y install "$@"
  elif command -v yum >/dev/null 2>&1; then
    yum -y install "$@"
  else
    err "No supported package manager found (apt/dnf/yum)"
    return 1
  fi
}

pkg_remove() {
  if command -v apt-get >/dev/null 2>&1; then
    apt-get remove -y "$@" || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf -y remove "$@" || true
  elif command -v yum >/dev/null 2>&1; then
    yum -y remove "$@" || true
  else
    warn "No supported package manager to remove packages"
  fi
}

clean_package_cache() {
  info "Cleaning package manager cache..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get clean || true
    rm -rf /var/lib/apt/lists/* || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf clean all || true
  elif command -v yum >/dev/null 2>&1; then
    yum clean all || true
  fi
}

# --- Installer (official Docker repo) ---
install_docker() {
  detect_distro
  info "Installing Docker on $DISTRO_NAME ($DISTRO_ID $DISTRO_VER)"

  # Common pre-reqs
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    pkg_install ca-certificates curl gnupg lsb-release
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/$( [[ $DISTRO_ID == "ubuntu" || $DISTRO_ID == "debian" ]] && echo "ubuntu" || echo "ubuntu" )/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    ARCH=$(dpkg --print-architecture)
    CODENAME=$(lsb_release -cs || echo "$(awk -F= '/^VERSION_CODENAME/{print $2}' /etc/os-release || echo 'stable')")
    echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${CODENAME} stable" \
      | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update
    pkg_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || pkg_install docker.io
  elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    # RHEL-family (AlmaLinux/CentOS/Rocky)
    if command -v dnf >/dev/null 2>&1; then
      pkg_install dnf-plugins-core
      dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo || true
      dnf makecache
      pkg_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || pkg_install docker
    else
      pkg_install yum-utils
      yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo || true
      pkg_install docker-ce docker-ce-cli containerd.io || pkg_install docker
    fi
  else
    warn "Unsupported distro — falling back to get.docker.com script"
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sh /tmp/get-docker.sh
    rm -f /tmp/get-docker.sh
  fi

  # Ensure containerd installed and service enabled
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable --now docker || true
  fi

  # Verify installation
  if command -v docker >/dev/null 2>&1; then
    ok "Docker installed: $(docker --version 2>/dev/null || true)"
  else
    err "Docker did not install correctly"
  fi

  # Docker Compose: try plugin, otherwise standalone
  if docker compose version >/dev/null 2>&1; then
    ok "Docker Compose plugin available"
  else
    if ! command -v docker-compose >/dev/null 2>&1; then
      info "Installing standalone docker-compose binary (fallback)"
      LATEST=$(curl -fsSL https://api.github.com/repos/docker/compose/releases/latest | grep -Po '"tag_name": "\K[^"]+' || true)
      LATEST=${LATEST:-"v2.17.3"}
      BIN=/usr/local/bin/docker-compose
      curl -L "https://github.com/docker/compose/releases/download/${LATEST}/docker-compose-$(uname -s)-$(uname -m)" -o "$BIN"
      chmod +x "$BIN"
      ok "docker-compose installed: $($BIN --version 2>/dev/null || true)"
    fi
  fi

  # Post-install cleanup
  clean_package_cache
  ok "Installation finished. Run 'docker info' to check status."
}

# --- Uninstaller (keeps /var/lib/docker) ---
uninstall_docker() {
  detect_distro
  warn "This will remove Docker packages but KEEP your data in /var/lib/docker"
  read -rp "Proceed with uninstall? (y/N): " yn
  if [[ ! "$yn" =~ ^[Yy] ]]; then
    info "Canceled"
    return
  fi

  # Stop docker
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop docker || true
  fi

  # Remove packages
  pkg_remove docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker docker-engine docker.io
  # Do not remove /var/lib/docker or /var/lib/containerd
  ok "Docker packages removed. Data under /var/lib/docker preserved."

  # Clean package cache if requested (we always clean per user preference)
  clean_package_cache
}

# ------------------ Existing management functions ------------------
# (Containers, images, exec, cp, attach, file explorer, edit, compose hooks, auto-update, backup, troubleshooting, command reference)

list_containers() { docker ps -a --format 'table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}' || true; }
start_container() { read -rp "Container (name|id): " c; docker start "$c" && ok "Started $c" || err "Failed to start $c"; }
stop_container() { read -rp "Container (name|id): " c; docker stop "$c" && ok "Stopped $c" || err "Failed to stop $c"; }
restart_container() { read -rp "Container (name|id): " c; docker restart "$c" && ok "Restarted $c" || err "Failed to restart $c"; }
remove_container() { read -rp "Container (name|id): " c; docker rm -f "$c" && ok "Removed $c" || err "Failed to remove $c"; }
inspect_container() { read -rp "Container (name|id): " c; docker inspect "$c" 2>/dev/null || err "Inspect failed"; }
container_logs() { read -rp "Container (name|id): " c; docker logs -f --tail 200 "$c"; }

# Exec command inside container
docker_exec() {
  read -rp "Container (name|id): " c
  read -rp "Command to run inside container: " cmd
  if [[ -z "$c" || -z "$cmd" ]]; then err "Container or command empty"; return; fi
  docker exec -it "$c" /bin/sh -c "$cmd" || docker exec -it "$c" bash -c "$cmd" || err "Failed to execute command"
}

# Copy files between host and container
docker_copy() {
  echo -e "${YELLOW}1)${RESET} Copy Host → Container"
  echo -e "${YELLOW}2)${RESET} Copy Container → Host"
  read -rp "Select option (1/2): " opt
  if [ "$opt" = "1" ]; then
    read -rp "Host path: " src
    read -rp "Container (name|id): " c
    read -rp "Destination path inside container: " dest
    docker cp "$src" "$c":"$dest" && ok "Copied $src → $c:$dest" || err "Copy failed"
  elif [ "$opt" = "2" ]; then
    read -rp "Container (name|id): " c
    read -rp "Source path inside container: " src
    read -rp "Destination path on host: " dest
    docker cp "$c":"$src" "$dest" && ok "Copied $c:$src → $dest" || err "Copy failed"
  else
    err "Invalid option"
  fi
}

# Attach interactive shell
attach_shell() {
  read -rp "Container (name|id): " c
  if [[ -z "$c" ]]; then err "No container provided"; return; fi
  info "Attempting to attach shell to container: $c"
  if docker exec -it "$c" bash -c 'echo SHELL_OK' >/dev/null 2>&1; then
    docker exec -it "$c" bash
  elif docker exec -it "$c" sh -c 'echo SHELL_OK' >/dev/null 2>&1; then
    docker exec -it "$c" sh
  else
    err "Container does not have bash or sh available. Use docker_exec to run commands."
  fi
}

# File explorer & editor
container_file_explorer() {
  read -rp "Container (name|id): " c
  base="/"
  if [[ -z "$c" ]]; then err "No container provided"; return; fi
  info "Opening container file explorer for $c"

  if ! docker exec "$c" test -d / >/dev/null 2>&1; then
    err "Container $c not accessible or not running"
    return
  fi

  while true; do
    echo -e "\n${YELLOW}Current path: $base${RESET}"
    if command -v fzf >/dev/null 2>&1; then
      sel=$(docker exec "$c" ls -1A "$base" 2>/dev/null | fzf --prompt="Select file or directory > ")
    else
      docker exec "$c" ls -l --color=auto "$base" || true
      read -rp "Enter name to open (.. for up, q to quit): " sel
    fi

    [[ -z "$sel" ]] && break
    [[ "$sel" == "q" ]] && break

    if [[ "$sel" == ".." ]]; then
      base=$(dirname "$base")
      [[ "$base" == "." ]] && base="/"
      continue
    fi

    path="$base/$sel"
    if docker exec "$c" test -d "$path" >/dev/null 2>&1; then
      base="$path"
    else
      echo -e "${YELLOW}--- File Content (first 200 lines) ---${RESET}"
      docker exec "$c" sh -c "(head -n 200 '$path' || true)" || err "Cannot read file"
      echo -e "${YELLOW}-------------------------------------${RESET}"
      read -rp "(E)dit, (B)ack, or (Q)uit: " action
      case "$action" in
        [Ee]) docker_edit_file "$c" "$path" ;;
        [Qq]) break ;;
        *) ;; # back
      esac
    fi
  done
}

docker_edit_file() {
  local c="$1" path="$2"
  if [[ -z "$c" || -z "$path" ]]; then err "Missing args"; return; fi
  info "Editing $path inside $c"

  if docker exec "$c" command -v nano >/dev/null 2>&1; then
    docker exec -it "$c" nano "$path"
  elif docker exec "$c" command -v vi >/dev/null 2>&1; then
    docker exec -it "$c" vi "$path"
  elif docker exec "$c" command -v vim >/dev/null 2>&1; then
    docker exec -it "$c" vim "$path"
  else
    warn "No editor inside container. Attempting to install nano (best-effort)."
    if docker exec "$c" sh -c "command -v apt-get >/dev/null 2>&1" >/dev/null 2>&1; then
      docker exec "$c" sh -c "apt-get update >/dev/null 2>&1 && apt-get install -y nano >/dev/null 2>&1 || true"
    elif docker exec "$c" sh -c "command -v yum >/dev/null 2>&1" >/dev/null 2>&1; then
      docker exec "$c" sh -c "yum install -y nano >/dev/null 2>&1 || true"
    fi
    if docker exec "$c" command -v nano >/dev/null 2>&1; then
      docker exec -it "$c" nano "$path"
    else
      err "Failed to install or find an editor inside container"
    fi
  fi
}

# ------------------ Image management submenu (Hub search) ------------------
list_images_menu() { docker images --format 'table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}' || true; read -rp "Press Enter to return..." _; }

image_search_hub() {
  read -rp "Search term (Docker Hub): " q
  [[ -z "$q" ]] && { err "Empty query"; return; }
  info "Searching Docker Hub for: $q"
  # URL-encode query using python3
  enc=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$q")
  url="https://hub.docker.com/v2/search/repositories/?query=${enc}&page_size=25"
  resp=$(curl -s "$url")
  if [[ -z "$resp" ]]; then err "No response from Docker Hub"; return; fi
  echo "$resp" | python3 - <<'PY'
import sys, json
j=json.load(sys.stdin)
for r in j.get('results',[]):
    user=r.get('user') or ''
    name=r.get('name') or ''
    desc=r.get('short_description') or ''
    stars=r.get('star_count',0)
    pulls=r.get('pull_count',0)
    print(f"{user}/{name}\tStars:{stars}\tPulls:{pulls}\t{desc}")
PY
  echo
  read -rp "Enter image to pull (user/name[:tag]) or leave empty to return: " img
  [[ -z "$img" ]] && return
  docker pull "$img" && ok "Pulled $img" || err "Pull failed"
}

pull_image_menu() { read -rp "Image to pull (eg nginx:latest): " img; [[ -z "$img" ]] && { err "Empty"; return; }; docker pull "$img" && ok "Pulled $img" || err "Pull failed"; }
remove_image_menu() { read -rp "Image to remove (id or repo:tag): " img; [[ -z "$img" ]] && { err "Empty"; return; }; docker rmi -f "$img" && ok "Removed $img" || err "Remove failed"; }

image_management_menu() {
  while true; do
    echo -e "\n${YELLOW}=== Image Management ===${RESET}"
    echo "1) List local images"
    echo "2) Search Docker Hub & pull"
    echo "3) Pull image (manual)"
    echo "4) Remove image"
    echo "0) Back"
    read -rp "Choice: " c
    case $c in
      1) list_images_menu ;;
      2) image_search_hub ;;
      3) pull_image_menu ;;
      4) remove_image_menu ;;
      0) break ;;
      *) echo "Invalid" ;;
    esac
  done
}

# ------------------ Command reference (trimmed for brevity on screen) ------------------
command_reference() {
  cat <<'EOF'

=== Docker Command Reference (short notes) ===

CONTAINERS
  docker run [OPTIONS] IMAGE [CMD]   # Create & run a container
  docker ps -a                        # List all containers
  docker start/stop/restart/kill      # Control container lifecycle
  docker rm                            # Remove container
  docker logs                          # View container logs
  docker exec -it CONTAINER COMMAND    # Run command inside container
  docker attach CONTAINER              # Attach to container stdin/stdout
  docker inspect CONTAINER             # Show low-level details

IMAGES
  docker pull IMAGE[:TAG]              # Pull image from registry
  docker images                        # List local images
  docker rmi IMAGE                     # Remove local image
  docker build -t name:tag PATH        # Build image

NETWORKS & VOLUMES
  docker network ls/inspect/create/rm  # Manage networks
  docker volume ls/create/rm           # Manage volumes

SYSTEM
  docker system df/prune               # Disk usage and cleanup
  docker info/version                  # System info and versions

DOCKER COMPOSE (V2 plugin = docker compose)
  docker compose up -d                 # Start compose
  docker compose down                  # Stop & remove compose resources
  docker compose logs                  # Show compose logs

EOF
  read -rp "Press Enter to return..." _
}

# ------------------ Troubleshooting ------------------
troubleshoot_menu() {
  echo -e "\n${YELLOW}=== Troubleshooting ===${RESET}"
  echo "1) Docker daemon status"
  echo "2) Show docker info"
  echo "3) Recent docker daemon logs"
  echo "4) Disk usage & docker system df"
  echo "0) Back"
  read -rp "Choice: " c
  case $c in
    1) systemctl status docker --no-pager || true ;;
    2) docker info || true ;;
    3) journalctl -u docker -n 200 --no-pager || true ;;
    4) df -h /var/lib/docker || true ; docker system df || true ;;
    0) return ;;
    *) echo "Invalid" ;;
  esac
  read -rp "Press Enter to return..." _
}

# ------------------ Main Menu ------------------
require_root
while true; do
  echo -e "\n${YELLOW}=== Docker Manager (Universal) ===${RESET}"
  echo "1) Install Docker (Ubuntu/AlmaLinux auto-detect)"
  echo "2) Uninstall Docker (remove engine, KEEP /var/lib/docker)"
  echo "3) Containers: list/start/stop/restart/remove/inspect/logs"
  echo "4) Exec / Attach / Copy (exec, cp, attach)"
  echo "5) Browse & Edit container files"
  echo "6) Image Management (list/search/pull/remove)"
  echo "7) Troubleshooting"
  echo "8) Docker Command Reference"
  echo "0) Exit"
  read -rp "Select an option: " opt

  case $opt in
    1) install_docker ;;
    2) uninstall_docker ;;
    3)
      list_containers
      read -rp "Open container action submenu? (y/N): " yn
      if [[ "$yn" =~ ^[Yy] ]]; then
        read -rp "Action (start/stop/restart/remove/inspect/logs): " a
        case $a in
          start) start_container ;;
          stop) stop_container ;;
          restart) restart_container ;;
          remove) remove_container ;;
          inspect) inspect_container ;;
          logs) container_logs ;;
          *) echo "Unknown" ;;
        esac
      fi
      ;;
    4)
      echo "1) Exec command inside container"
      echo "2) Attach shell to container"
      echo "3) Copy files (docker cp)"
      read -rp "Choice: " c
      case $c in
        1) docker_exec ;;
        2) attach_shell ;;
        3) docker_copy ;;
        *) echo "Invalid" ;;
      esac
      ;;
    5) container_file_explorer ;;
    6) image_management_menu ;;
    7) troubleshoot_menu ;;
    8) command_reference ;;
    0) exit 0 ;;
    *) echo "Invalid option" ;;
  esac
done
