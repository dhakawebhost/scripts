#!/bin/bash
# Version: v6.0 (2025-11-17)
#
# WHAT THIS SCRIPT DOES
# ---------------------
# 1) SSH-based migration (root SSH on SOURCE + DESTINATION)
#    - Single / Batch accounts
#    - Files only, DBs only, Files+DBs, Incremental sync
#    - DB dumps over SSH, restore on destination
#    - Auto-skip known system folders (.cpanel, logs, tmp, etc.)
#    - Auto-create cPanel account on DESTINATION (WHM) if missing (optional)
#    - NEW: Auto-detect main domain for username from SOURCE and use it in WHM createacct
#
# 2) Full cPanel Backup Mode (NO root/SSH on SOURCE)
#    - Only needs cPanel username & password on SOURCE
#    - Run on DESTINATION (root on WHM)
#    - Flow:
#        * Login via /login, use cookies, fetch "/" HTML
#        * Extract cpsessXXXX path from HTML
#        * Build CP_BASE="https://HOST:PORT/cpsessXXXX"
#        * Trigger full backup to homedir via backup interface
#        * Poll /home/USER via Fileman/list_files for backup-*_USER.tar.gz
#        * Download backup via Fileman/get_file (HTTPS)
#        * Restore via restorepkg on DESTINATION (creates account + restores)
#        * NEW: If account already exists, show WHM summary (Option E) and
#               default to restorepkg --force (Option B) with confirmation.
#
# 3) SSH Profiles
#    - Save multiple remote servers (IP+port+user)
#    - Auto-use SSH key if available; fallback to password + ssh-copy-id
#
# 4) Tools
#    - Fix ownership for a username on THIS server: chown -R user:user /home/user
#
# 5) Logs Viewer
#    - View recent migration logs from /root/migration_logs
###############################################################################
set -euo pipefail

#########################
# Colors & helpers
#########################
if [[ -t 1 ]]; then
  C_RESET='\e[0m'; C_RED='\e[31m'; C_GREEN='\e[32m'; C_YELLOW='\e[33m'
  C_BLUE='\e[34m'; C_CYAN='\e[36m'; C_BOLD='\e[1m'
else
  C_RESET=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_CYAN=''; C_BOLD=''
fi

info(){ echo -e "${C_CYAN}[INFO]${C_RESET} $*"; }
warn(){ echo -e "${C_YELLOW}[WARN]${C_RESET} $*"; }
error(){ echo -e "${C_RED}[ERROR]${C_RESET} $*" >&2; }
success(){ echo -e "${C_GREEN}[OK]${C_RESET} $*"; }
step(){ echo -e "${C_BLUE}${C_BOLD}==> $*${C_RESET}"; }

prompt(){ local v; read -r -p "$1" v; echo "$v"; }
prompt_secret(){ local v; read -r -s -p "$1" v; echo; echo "$v"; }

#########################
# Logging
#########################
LOG_DIR="/root/migration_logs"
mkdir -p "$LOG_DIR" 2>/dev/null || LOG_DIR="$PWD"
LOG="$LOG_DIR/migration_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

#########################
# Tool Check
#########################
step "Checking required tools"
NEEDED=(ssh sshpass rsync mysql mysqldump curl)
for c in "${NEEDED[@]}"; do
  if ! command_v=$(command -v "$c" 2>/dev/null); then
    error "Missing required tool: $c"
    exit 1
  fi
done
success "All required tools found."

#########################
# Safety & Role
#########################
HOSTNAME_NOW=$(hostname)
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}') || SERVER_IP="unknown"
warn "You are running this script on: $HOSTNAME_NOW (${SERVER_IP})"
CONFIRM=$(prompt "Are you sure this is the right server (SOURCE or DESTINATION)? [y/N]: "); CONFIRM=${CONFIRM:-n}
[[ "$CONFIRM" =~ ^[Yy]$ ]] || { error "Aborted by user."; exit 1; }

step "Select this server's role"
echo "  1) SOURCE (old server; data currently live here)"
echo "  2) DESTINATION (new server; target server)"
ROLE_CHOICE=$(prompt "Choose [1/2]: ")
if [[ "$ROLE_CHOICE" == "1" ]]; then
  ROLE="source"
elif [[ "$ROLE_CHOICE" == "2" ]]; then
  ROLE="destination"
else
  error "Invalid choice."
  exit 1
fi
success "This server is: $ROLE"

#########################
# SSH Profiles & Auth (SSH mode)
#########################
PROFILES_DIR="$HOME/.migration_profiles"
mkdir -p "$PROFILES_DIR"
SSH_KEY="$HOME/.ssh/id_rsa"

REMOTE_HOST=""; REMOTE_PORT=""; REMOTE_USER=""
AUTH_MODE="password"
REMOTE_PASS=""
SSH_INITIALIZED=0

profile_filename_for_host(){
  local host="$1" port="$2"
  host="${host//:/_}"
  echo "$PROFILES_DIR/${host}_${port}.ini"
}

save_profile(){
  local host="$1" port="$2" user="$3"
  local file
  file=$(profile_filename_for_host "$host" "$port")
  cat > "$file" <<EOF
REMOTE_HOST="$host"
REMOTE_PORT="$port"
REMOTE_USER="$user"
EOF
  success "SSH profile saved as $file"
}

ask_remote_server(){
  if [[ "$ROLE" == "source" ]]; then
    info "Remote server is DESTINATION (new server)."
  else
    info "Remote server is SOURCE (old server)."
  fi
  REMOTE_HOST=$(prompt "Remote server IP/host: ")
  REMOTE_PORT=$(prompt "Remote SSH port [22]: "); REMOTE_PORT=${REMOTE_PORT:-22}
  REMOTE_USER=$(prompt "SSH username [root]: "); REMOTE_USER=${REMOTE_USER:-root}
}

ssh_remote(){
  if [[ "$AUTH_MODE" == "key" ]]; then
    ssh -i "$SSH_KEY" -p "$REMOTE_PORT" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      "$REMOTE_USER@$REMOTE_HOST" "$@"
  else
    sshpass -p "$REMOTE_PASS" ssh -p "$REMOTE_PORT" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o PubkeyAuthentication=no \
      -o PreferredAuthentications=keyboard-interactive,password \
      "$REMOTE_USER@$REMOTE_HOST" "$@"
  fi
}

init_ssh(){
  local files=()
  local f

  if [[ ! -f "$SSH_KEY" ]]; then
    step "No SSH key found at $SSH_KEY. Generating a new key..."
    mkdir -p "$(dirname "$SSH_KEY")"
    ssh-keygen -t rsa -b 4096 -N "" -f "$SSH_KEY"
    success "SSH key generated at $SSH_KEY"
  fi

  for f in "$PROFILES_DIR"/*.ini; do
    [[ -f "$f" ]] && files+=("$f")
  done

  if (( ${#files[@]} > 0 )); then
    while :; do
      echo
      step "Saved SSH profiles"
      local i=1
      for f in "${files[@]}"; do
        # shellcheck disable=SC1090
        source "$f"
        local label="$REMOTE_USER@$REMOTE_HOST:$REMOTE_PORT"
        echo "  $i) $label   [$f]"
        ((i++))
      done
      echo "  $i) Add new server"
      echo "  $((i+1))) Exit"
      local choice; choice=$(prompt "Choose [1-$((i+1))]: ")

      if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
        warn "Invalid choice."
        continue
      fi

      if (( choice >=1 && choice <= ${#files[@]} )); then
        local sel_file="${files[$((choice-1))]}"
        # shellcheck disable=SC1090
        source "$sel_file"
        info "Using profile: $REMOTE_USER@$REMOTE_HOST:$REMOTE_PORT"
        break
      elif (( choice == ${#files[@]} + 1 )); then
        ask_remote_server
        break
      else
        success "Bye."
        exit 0
      fi
    done
  else
    step "No SSH profiles found. Add first server."
    ask_remote_server
  fi

  step "Testing SSH key auth to $REMOTE_USER@$REMOTE_HOST:$REMOTE_PORT (key-only)"
  if ssh -i "$SSH_KEY" -p "$REMOTE_PORT" \
       -o BatchMode=yes \
       -o StrictHostKeyChecking=no \
       -o UserKnownHostsFile=/dev/null \
       "$REMOTE_USER@$REMOTE_HOST" "echo LOGIN_OK" 2>/dev/null | grep -q "LOGIN_OK"; then
    AUTH_MODE="key"
    success "SSH key auth OK. Using key-only mode."
    save_profile "$REMOTE_HOST" "$REMOTE_PORT" "$REMOTE_USER"
    SSH_INITIALIZED=1
    return
  else
    warn "SSH key auth not working yet on remote. Will use password and try to install key."
  fi

  while :; do
    REMOTE_PASS=$(prompt_secret "SSH password for $REMOTE_USER@$REMOTE_HOST: ")
    REMOTE_PASS=$(echo -n "$REMOTE_PASS" | tr -d '\r\n')
    step "Testing SSH password auth..."
    if sshpass -p "$REMOTE_PASS" ssh -p "$REMOTE_PORT" \
         -o StrictHostKeyChecking=no \
         -o UserKnownHostsFile=/dev/null \
         -o PubkeyAuthentication=no \
         -o PreferredAuthentications=keyboard-interactive,password \
         "$REMOTE_USER@$REMOTE_HOST" "echo LOGIN_OK" 2>/dev/null | grep -q "LOGIN_OK"; then
      success "SSH password auth OK."
      break
    else
      error "SSH password auth failed. Try again or Ctrl+C to abort."
    fi
  done

  if command -v ssh-copy-id >/dev/null 2>&1; then
    step "Installing SSH key on remote using ssh-copy-id (for future passwordless access)..."
    if sshpass -p "$REMOTE_PASS" ssh-copy-id -i "$SSH_KEY.pub" \
         -p "$REMOTE_PORT" \
         -o StrictHostKeyChecking=no \
         -o UserKnownHostsFile=/dev/null \
         "$REMOTE_USER@$REMOTE_HOST" 2>/dev/null; then
      step "Re-testing SSH key auth after installing key..."
      if ssh -i "$SSH_KEY" -p "$REMOTE_PORT" \
           -o BatchMode=yes \
           -o StrictHostKeyChecking=no \
           -o UserKnownHostsFile=/dev/null \
           "$REMOTE_USER@$REMOTE_HOST" "echo LOGIN_OK" 2>/dev/null | grep -q "LOGIN_OK"; then
        AUTH_MODE="key"
        success "SSH key auth now works. Using key-only mode."
        save_profile "$REMOTE_HOST" "$REMOTE_PORT" "$REMOTE_USER"
        REMOTE_PASS=""
        SSH_INITIALIZED=1
        return
      else
        warn "SSH key still not accepted by remote. Will continue with password mode."
      fi
    else
      warn "ssh-copy-id failed; continuing with password mode."
    fi
  else
    warn "ssh-copy-id not installed; using password mode."
  fi

  AUTH_MODE="password"
  save_profile "$REMOTE_HOST" "$REMOTE_PORT" "$REMOTE_USER"
  success "Using SSH password mode (sshpass) for this server."
  SSH_INITIALIZED=1
}

ensure_ssh_initialized(){
  if [[ "$SSH_INITIALIZED" -eq 0 ]]; then
    init_ssh
  fi
}

#########################
# rsync wrappers (SSH mode)
#########################
rsync_local_to_remote(){
  local SRC="$1" DEST="$2" EXTRA_OPTS="$3"
  if [[ "$AUTH_MODE" == "key" ]]; then
    rsync -avh --info=progress2 $EXTRA_OPTS \
      -e "ssh -i $SSH_KEY -p $REMOTE_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
      "$SRC" "$REMOTE_USER@$REMOTE_HOST:$DEST"
  else
    sshpass -p "$REMOTE_PASS" rsync -avh --info=progress2 $EXTRA_OPTS \
      -e "ssh -p $REMOTE_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
      "$SRC" "$REMOTE_USER@$REMOTE_HOST:$DEST"
  fi
}

rsync_remote_to_local(){
  local SRC="$1" DEST="$2" EXTRA_OPTS="$3"
  if [[ "$AUTH_MODE" == "key" ]]; then
    rsync -avh --info=progress2 $EXTRA_OPTS \
      -e "ssh -i $SSH_KEY -p $REMOTE_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
      "$REMOTE_USER@$REMOTE_HOST:$SRC" "$DEST"
  else
    sshpass -p "$REMOTE_PASS" rsync -avh --info=progress2 $EXTRA_OPTS \
      -e "ssh -p $REMOTE_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
      "$REMOTE_USER@$REMOTE_HOST:$SRC" "$DEST"
  fi
}

#########################
# MySQL helpers (SSH mode)
#########################
SYSTEM_DBS=("information_schema" "mysql" "sys" "performance_schema" "phpmyadmin" "cphulkd")

is_system_db(){
  local db="$1"
  for s in "${SYSTEM_DBS[@]}"; do
    [[ "$db" == "$s" ]] && return 0
  done
  return 1
}

mysql_remote_query_all_dbs(){
  ssh_remote "mysql -N -e 'SHOW DATABASES;'" 2>/dev/null || true
}

detect_dbs_for_user_local(){
  local USERNAME="$1"
  declare -A seen=()
  local db

  while read -r db; do
    [[ -z "$db" ]] && continue
    is_system_db "$db" && continue
    if [[ "$db" == ${USERNAME}_* ]]; then
      seen["$db"]=1
    fi
  done < <(mysql -N -e "SHOW DATABASES;" 2>/dev/null || true)

  while read -r db; do
    [[ -z "$db" ]] && continue
    [[ "$db" == *"%"* ]] && continue
    is_system_db "$db" && continue
    seen["$db"]=1
  done < <(mysql -N -e "SELECT DISTINCT db FROM mysql.db WHERE user='${USERNAME}' OR user LIKE '${USERNAME}%';" 2>/dev/null || true)

  for db in "${!seen[@]}"; do
    echo "$db"
  done
}

detect_dbs_for_user_remote(){
  local USERNAME="$1"
  mysql_remote_query_all_dbs | grep -E "^${USERNAME}_" || true
}

select_dbs_from_array(){
  local -n REF="$1"
  (( ${#REF[@]} > 0 )) || return 1

  echo
  info "Detected databases for this account:"
  local i=1
  for d in "${REF[@]}"; do
    echo "  $i) $d"
    ((i++))
  done

  local sel
  sel=$(prompt "Select DBs (1 3 / 1,3 / * for all) [*]: "); sel=${sel:-"*"}
  if [[ "$sel" == "*" ]]; then
    return 0
  fi

  sel=$(echo "$sel" | tr ',' ' ')
  local chosen=()
  local tok
  for tok in $sel; do
    if [[ "$tok" =~ ^[0-9]+$ ]] && (( tok>=1 && tok<=${#REF[@]} )); then
      chosen+=("${REF[$((tok-1))]}")
    else
      warn "Ignoring invalid index '$tok'."
    fi
  done
  (( ${#chosen[@]} > 0 )) || return 1
  REF=("${chosen[@]}")
}

#########################
# WHM / cPanel account helpers (DESTINATION)
#########################
whm_available(){
  [[ "$ROLE" == "destination" ]] && command -v whmapi1 >/dev/null 2>&1
}

cpanel_account_exists(){
  local USER="$1"
  whmapi1 listaccts searchtype=user search="$USER" 2>/dev/null | grep -qE "user:\s+$USER"
}

# Primary domain guess from local /home (DESTINATION)
guess_primary_domain_from_home(){
  local USER="$1"
  local d
  if [[ -d "/home/$USER" ]]; then
    while read -r d; do
      [[ -z "$d" ]] && continue
      # skip hidden dirs and obvious junk
      [[ "$d" == .* ]] && continue
      [[ "$d" == "mail" ]] && continue
      [[ "$d" == "etc" ]] && continue
      [[ "$d" == "logs" ]] && continue
      [[ "$d" == "tmp" ]] && continue
      # Looks like a domain: something.tld
      if [[ "$d" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        echo "$d"
        return 0
      fi
    done < <(find "/home/$USER" -maxdepth 1 -mindepth 1 -type d -printf "%f\n" 2>/dev/null)
  fi
  return 1
}

# NEW: Try to detect primary domain for a user on REMOTE (SOURCE)
detect_remote_primary_domain_for_user(){
  local USER="$1"

  # 1) Try WHM API accountsummary on remote
  if ssh_remote "command -v whmapi1 >/dev/null 2>&1"; then
    local dom
    dom=$(ssh_remote "whmapi1 accountsummary user='${USER}' 2>/dev/null | awk '/main_domain:/{print \$2; exit}'" | tr -d '\r\n' || true)
    if [[ -n "$dom" && "$dom" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
      echo "$dom"
      return 0
    fi
  fi

  # 2) Try cPanel userdata YAML on remote
  if ssh_remote "[ -f '/var/cpanel/userdata/${USER}/main' ]"; then
    local dom
    dom=$(ssh_remote "awk '/^main_domain:/{print \$2; exit}' /var/cpanel/userdata/${USER}/main 2>/dev/null" | tr -d '\r\n' || true)
    if [[ -n "$dom" && "$dom" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
      echo "$dom"
      return 0
    fi
  fi

  # 3) Try /etc/userdatadomains on remote
  if ssh_remote "[ -f '/etc/userdatadomains' ]"; then
    local dom
    dom=$(ssh_remote "grep -E ' ${USER}\$' /etc/userdatadomains 2>/dev/null | head -n1 | awk -F: '{print \$1}'" | tr -d '\r\n' || true)
    if [[ -n "$dom" && "$dom" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
      echo "$dom"
      return 0
    fi
  fi

  return 1
}

generate_password(){
  openssl rand -base64 18 2>/dev/null | tr -d '/+=' | cut -c1-16
}

create_cpanel_account_interactive(){
  local USER="$1"

  if ! whm_available; then
    warn "WHM not available on this destination. Cannot auto-create cPanel account for '$USER'."
    return 1
  fi

  if cpanel_account_exists "$USER"; then
    info "cPanel account '$USER' already exists on this server."
    return 0
  fi

  step "Create new cPanel account on DESTINATION for user '$USER'"

  local GUESS_DOMAIN=""
  # 1) Try to detect domain from REMOTE (SOURCE) via SSH/WHM/userdata
  if [[ "$SSH_INITIALIZED" -eq 1 ]]; then
    GUESS_DOMAIN=$(detect_remote_primary_domain_for_user "$USER" 2>/dev/null || true)
    if [[ -n "$GUESS_DOMAIN" ]]; then
      info "Remote (SOURCE) reports primary domain for '$USER' as: $GUESS_DOMAIN"
    fi
  fi

  # 2) If nothing from remote, fall back to local guess
  if [[ -z "$GUESS_DOMAIN" ]]; then
    if GUESS_DOMAIN=$(guess_primary_domain_from_home "$USER" 2>/dev/null); then
      info "Guessed primary domain from /home/$USER on DESTINATION: $GUESS_DOMAIN"
    fi
  fi

  # 3) Prompt with strong default (Option: manual if no guess)
  local DOMAIN
  while :; do
    if [[ -n "$GUESS_DOMAIN" ]]; then
      DOMAIN=$(prompt "Primary domain for '$USER' [$GUESS_DOMAIN]: ")
      DOMAIN=${DOMAIN:-$GUESS_DOMAIN}
    else
      DOMAIN=$(prompt "Primary domain for '$USER' (e.g. example.com): ")
    fi

    if [[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
      break
    else
      warn "Invalid domain '$DOMAIN'. Please enter something like example.com"
    fi
  done

  local PLAN
  PLAN=$(prompt "cPanel package/plan name [default]: "); PLAN=${PLAN:-default}

  local EMAIL
  EMAIL=$(prompt "Contact email for '$USER' (optional): ")

  local PASS
  PASS=$(generate_password)

  info "Creating account with:"
  echo "  Username : $USER"
  echo "  Domain   : $DOMAIN"
  echo "  Plan     : $PLAN"
  echo "  Email    : ${EMAIL:-<none>}"
  echo "  Password : $PASS"

  local CONF
  CONF=$(prompt "Proceed with WHM createacct for '$USER'? [y/N]: "); CONF=${CONF:-n}
  [[ "$CONF" =~ ^[Yy]$ ]] || { warn "Cancelled cPanel account creation for '$USER'."; return 1; }

  if whmapi1 createacct username="$USER" domain="$DOMAIN" plan="$PLAN" password="$PASS" contactemail="$EMAIL" 2>&1 | tee -a "$LOG" | grep -q "result: 1"; then
    success "cPanel account '$USER' created successfully on DESTINATION."
    info "Remember password for '$USER': $PASS"
    if [[ -d "/home/$USER" ]]; then
      chown -R "$USER:$USER" "/home/$USER" 2>/dev/null || warn "Ownership fix failed for /home/$USER."
    fi
    return 0
  else
    error "Failed to create cPanel account '$USER' via WHM."
    return 1
  fi
}

ensure_destination_cpanel_account(){
  local USER="$1"
  if [[ "$ROLE" != "destination" ]]; then
    return 0
  fi

  if ! whm_available; then
    info "WHM not detected; skipping auto cPanel account creation for '$USER'."
    return 0
  fi

  if cpanel_account_exists "$USER"; then
    info "cPanel account '$USER' already exists; will sync into /home/$USER."
    return 0
  fi

  local CREATE
  CREATE=$(prompt "cPanel account '$USER' does not exist. Create it now on DESTINATION? [y/N]: "); CREATE=${CREATE:-n}
  if [[ "$CREATE" =~ ^[Yy]$ ]]; then
    create_cpanel_account_interactive "$USER" || warn "Auto-creation failed or cancelled for '$USER'. Files will still be synced."
  else
    warn "Skipped creating cPanel account for '$USER'. Files will be synced but ownership may need manual fix later."
  fi
}

#########################
# FILE migration (SSH mode)
#########################
file_sync_single(){
  echo
  step "Single account FILE sync"
  local USER
  USER=$(prompt "Account username (or 'b' to go back): ")
  [[ "$USER" == "b" || "$USER" == "B" ]] && return 0
  [[ -z "$USER" ]] && { error "No username."; return 1; }

  local EXCL="--exclude=.cpanel --exclude=.trash --exclude=etc --exclude=mail --exclude=logs --exclude=tmp"

  if [[ "$ROLE" == "source" ]]; then
    local DEF_SRC="/home/$USER/" DEF_DEST="/home/$USER"
    local SRC DEST
    SRC=$(prompt "Source path on THIS server [$DEF_SRC]: "); SRC=${SRC:-$DEF_SRC}
    DEST=$(prompt "Destination path on REMOTE [$DEF_DEST]: "); DEST=${DEST:-$DEF_DEST}
    info "Syncing THIS ($SRC) -> REMOTE ($DEST)"
    rsync_local_to_remote "$SRC" "$DEST" "$EXCL"
    success "File sync completed."
    ssh_remote "id '$USER' >/dev/null 2>&1 && chown -R '$USER':'$USER' '$DEST' || echo '[INFO] Remote user does not exist yet. Ownership will need fix after account creation.'" || true
  else
    ensure_destination_cpanel_account "$USER"
    local DEF_SRC="/home/$USER/" DEF_DEST="/home/$USER"
    local SRC DEST
    SRC=$(prompt "Source path on REMOTE [$DEF_SRC]: "); SRC=${SRC:-$DEF_SRC}
    DEST=$(prompt "Destination path on THIS server [$DEF_DEST]: "); DEST=${DEST:-$DEF_DEST}
    mkdir -p "$DEST"
    info "Syncing REMOTE ($SRC) -> THIS ($DEST)"
    rsync_remote_to_local "$SRC" "$DEST" "$EXCL"
    success "File sync completed."
    if id "$USER" >/dev/null 2>&1; then
      chown -R "$USER:$USER" "$DEST"
      success "Ownership fixed for $USER on DESTINATION."
    else
      warn "User '$USER' does not exist yet on DESTINATION. Ownership kept as-is; will need fix after account creation."
    fi
  fi
}

file_sync_batch(){
  echo
  step "Batch accounts FILE sync"
  local USERS
  USERS=$(prompt "Enter usernames separated by spaces (or 'b' to go back): ")
  [[ "$USERS" == "b" || "$USERS" == "B" ]] && return 0
  [[ -z "$USERS" ]] && { warn "No usernames."; return 0; }

  local EXCL="--exclude=.cpanel --exclude=.trash --exclude=etc --exclude=mail --exclude=logs --exclude=tmp"

  for USER in $USERS; do
    step "Batch file sync for user: $USER"
    if [[ "$ROLE" == "source" ]]; then
      local SRC="/home/$USER/" DEST="/home/$USER"
      rsync_local_to_remote "$SRC" "$DEST" "$EXCL" || warn "File sync failed for $USER"
      ssh_remote "id '$USER' >/dev/null 2>&1 && chown -R '$USER':'$USER' '$DEST' || echo '[INFO] Remote user does not exist yet. Ownership will need fix after account creation.'" || true
    else
      ensure_destination_cpanel_account "$USER"
      local SRC="/home/$USER/" DEST="/home/$USER"
      mkdir -p "$DEST"
      rsync_remote_to_local "$SRC" "$DEST" "$EXCL" || warn "File sync failed for $USER"
      if id "$USER" >/dev/null 2>&1; then
        chown -R "$USER:$USER" "$DEST" 2>/dev/null || warn "Ownership fix failed for $USER."
      else
        warn "User '$USER' does not exist yet on DESTINATION. Ownership kept as-is; will need fix after account creation."
      fi
    fi
    success "File sync done for $USER."
  done
}

#########################
# Incremental FILE sync (SSH mode)
#########################
incremental_sync_single(){
  echo
  step "Incremental Sync (Single Account - update only)"
  local USER
  USER=$(prompt "Account username (or 'b' to go back): ")
  [[ "$USER" == "b" || "$USER" == "B" ]] && return 0
  [[ -z "$USER" ]] && { error "No username."; return 1; }

  local EXCL="--exclude=.cpanel --exclude=.trash --exclude=etc --exclude=mail --exclude=logs --exclude=tmp"
  local EXTRA="-u $EXCL"

  if [[ "$ROLE" == "source" ]]; then
    local SRC="/home/$USER/" DEST="/home/$USER"
    info "Incremental update THIS(SOURCE) -> REMOTE(DESTINATION) for $USER"
    rsync_local_to_remote "$SRC" "$DEST" "$EXTRA"
    ssh_remote "id '$USER' >/dev/null 2>&1 && chown -R '$USER':'$USER' '$DEST' || echo '[INFO] Remote user does not exist yet. Ownership will need fix after account creation.'" || true
  else
    ensure_destination_cpanel_account "$USER"
    local SRC="/home/$USER/" DEST="/home/$USER"
    mkdir -p "$DEST"
    info "Incremental update REMOTE(SOURCE) -> THIS(DESTINATION) for $USER"
    rsync_remote_to_local "$SRC" "$DEST" "$EXTRA"
    if id "$USER" >/dev/null 2>&1; then
      chown -R "$USER:$USER" "$DEST" 2>/dev/null || warn "Ownership fix failed for $USER."
    else
      warn "User '$USER' does not exist yet on DESTINATION. Ownership kept as-is; will need fix after account creation."
    fi
  fi

  success "Incremental sync completed for $USER."
}

incremental_sync_batch(){
  echo
  step "Batch Incremental File Sync (update only)"
  local USERS
  USERS=$(prompt "Enter usernames separated by spaces (or 'b' to go back): ")
  [[ "$USERS" == "b" || "$USERS" == "B" ]] && return 0
  [[ -z "$USERS" ]] && { warn "No usernames."; return 0; }

  local EXCL="--exclude=.cpanel --exclude=.trash --exclude=etc --exclude=mail --exclude=logs --exclude=tmp"
  local EXTRA="-u $EXCL"

  for USER in $USERS; do
    step "Incremental sync for user: $USER"
    if [[ "$ROLE" == "source" ]]; then
      rsync_local_to_remote "/home/$USER/" "/home/$USER" "$EXTRA" || warn "Incremental sync failed for $USER"
      ssh_remote "id '$USER' >/dev/null 2>&1 && chown -R '$USER':'$USER' '/home/$USER' || echo '[INFO] Remote user does not exist yet. Ownership will need fix after account creation.'" || true
    else
      ensure_destination_cpanel_account "$USER"
      mkdir -p "/home/$USER"
      rsync_remote_to_local "/home/$USER/" "/home/$USER" "$EXTRA" || warn "Incremental sync failed for $USER"
      if id "$USER" >/dev/null 2>&1; then
        chown -R "$USER:$USER" "/home/$USER" 2>/dev/null || warn "Ownership fix failed for $USER."
      else
        warn "User '$USER' does not exist yet on DESTINATION. Ownership kept as-is; will need fix after account creation."
      fi
    fi
    success "Incremental sync done for $USER."
  done
}

#########################
# DB migration (single, SSH mode)
#########################
db_migrate_single(){
  echo
  step "Single account DB migration"
  local USER
  USER=$(prompt "Account username for DB detection (or 'b' to go back): ")
  [[ "$USER" == "b" || "$USER" == "B" ]] && return 0
  [[ -z "$USER" ]] && { warn "No username."; return 0; }

  local GO
  GO=$(prompt "Migrate databases for '$USER'? [y/N]: "); GO=${GO:-n}
  [[ "$GO" =~ ^[Yy]$ ]] || { warn "Skipping DB migration."; return 0; }

  local DBS=()
  if [[ "$ROLE" == "source" ]]; then
    mapfile -t DBS < <(detect_dbs_for_user_local "$USER")
  else
    mapfile -t DBS < <(detect_dbs_for_user_remote "$USER")
  fi

  if (( ${#DBS[@]} == 0 )); then
    warn "No databases auto-detected for '$USER' using current detection rules."
    return 0
  fi

  if ! select_dbs_from_array DBS; then
    warn "DB selection cancelled."
    return 0
  fi

  echo
  info "Final DB list to migrate for '$USER':"
  local db
  for db in "${DBS[@]}"; do echo "   - $db"; done

  local CONF
  CONF=$(prompt "Proceed with mysqldump for these DBs? [Y/n]: "); CONF=${CONF:-y}
  [[ "$CONF" =~ ^[Yy]$ ]] || { warn "User aborted DB dump."; return 0; }

  local TS DUMP_DIR_NAME SOURCE_DUMP_DIR DEST_DB_PATH
  TS=$(date +%Y%m%d_%H%M%S)
  DUMP_DIR_NAME="migdb_${USER}_${TS}"

  if [[ "$ROLE" == "source" ]]; then
    SOURCE_DUMP_DIR="/tmp/$DUMP_DIR_NAME"
    mkdir -p "$SOURCE_DUMP_DIR"
    step "Dumping DBs on THIS (SOURCE) into $SOURCE_DUMP_DIR (socket/.my.cnf auth)"
    for db in "${DBS[@]}"; do
      info "Dumping $db..."
      mysqldump --single-transaction --routines --triggers "$db" > "$SOURCE_DUMP_DIR/$db.sql"
    done
    success "Local DB dumps completed."

    local DEF_DEST_DB_PATH="/backup/dbbackup/$USER"
    DEST_DB_PATH=$(prompt "Remote DB storage path [$DEF_DEST_DB_PATH]: "); DEST_DB_PATH=${DEST_DB_PATH:-$DEF_DEST_DB_PATH}
    ssh_remote "mkdir -p '$DEST_DB_PATH'"

    step "Transferring dumps SOURCE -> REMOTE"
    rsync_local_to_remote "$SOURCE_DUMP_DIR/" "$DEST_DB_PATH/" ""
    success "Transferred DB dumps to REMOTE: $DEST_DB_PATH"

    local CL
    CL=$(prompt "Delete SQL dump files from THIS (SOURCE) server now? [y/N]: "); CL=${CL:-n}
    if [[ "$CL" =~ ^[Yy]$ ]]; then
      rm -rf "$SOURCE_DUMP_DIR"
      success "Deleted local SQL dumps at $SOURCE_DUMP_DIR."
    else
      warn "Kept local SQL dumps at $SOURCE_DUMP_DIR."
    fi

    local RS
    RS=$(prompt "Restore these DBs on REMOTE now? [y/N]: "); RS=${RS:-n}
    if [[ "$RS" =~ ^[Yy]$ ]]; then
      local DST_DB_USER DST_DB_PASS
      DST_DB_USER=$(prompt "REMOTE MySQL user [root]: "); DST_DB_USER=${DST_DB_USER:-root}
      DST_DB_PASS=$(prompt_secret "REMOTE MySQL password: ")

      step "Restoring DBs on REMOTE (Mode A: CREATE IF NOT EXISTS, no user creation)"
      ssh_remote "DEST_DB_PATH='$DEST_DB_PATH' DST_DB_USER='$DST_DB_USER' DST_DB_PASS='$DST_DB_PASS' bash -s" <<'EOF'
set -euo pipefail
shopt -s nullglob
SYSTEM_DBS=("information_schema" "mysql" "sys" "performance_schema" "phpmyadmin" "cphulkd")
for sqlfile in "$DEST_DB_PATH"/*.sql; do
  base=$(basename "$sqlfile")
  dbname="${base%.sql}"
  skip=false
  for s in "${SYSTEM_DBS[@]}"; do
    [[ "$dbname" == "$s" ]] && skip=true && break
  done
  $skip && { echo "[REMOTE] Skipping system DB $dbname"; continue; }
  echo "[REMOTE] Restoring $dbname ..."
  mysql -u"$DST_DB_USER" -p"$DST_DB_PASS" -e "CREATE DATABASE IF NOT EXISTS \`$dbname\`;"
  mysql -u"$DST_DB_USER" -p"$DST_DB_PASS" "$dbname" < "$sqlfile"
done
echo "[REMOTE] DB restore completed."
EOF
      success "DB restore completed on REMOTE."

      local CL2
      CL2=$(prompt "Delete SQL dump files from REMOTE (DESTINATION) now? [y/N]: "); CL2=${CL2:-n}
      if [[ "$CL2" =~ ^[Yy]$ ]]; then
        ssh_remote "rm -f '$DEST_DB_PATH'/*.sql"
        success "Deleted SQL dumps from REMOTE path $DEST_DB_PATH."
      else
        warn "Kept SQL dumps on REMOTE at $DEST_DB_PATH."
      fi
    else
      warn "Skipped remote restore; SQL dumps remain at: $DEST_DB_PATH"
    fi

  else
    SOURCE_DUMP_DIR="/tmp/$DUMP_DIR_NAME"
    local DEF_DEST_DB_PATH="/backup/dbbackup/$USER"
    DEST_DB_PATH=$(prompt "Local DB storage path on THIS server [$DEF_DEST_DB_PATH]: "); DEST_DB_PATH=${DEST_DB_PATH:-$DEF_DEST_DB_PATH}
    mkdir -p "$DEST_DB_PATH"

    step "Dumping DBs on REMOTE (SOURCE) into $SOURCE_DUMP_DIR (using remote .my.cnf if present)"
    local DB_LIST_STR=""
    for db in "${DBS[@]}"; do DB_LIST_STR="$DB_LIST_STR $db"; done
    ssh_remote "SOURCE_DUMP_DIR='$SOURCE_DUMP_DIR' DB_LIST_STR='$DB_LIST_STR' bash -s" <<'EOF'
set -euo pipefail
mkdir -p "$SOURCE_DUMP_DIR"
for db in $DB_LIST_STR; do
  echo "[REMOTE] Dumping $db -> $SOURCE_DUMP_DIR/$db.sql"
  mysqldump --single-transaction --routines --triggers "$db" > "$SOURCE_DUMP_DIR/$db.sql"
done
echo "[REMOTE] DB dump completed."
EOF
    success "Remote DB dumps created."

    step "Transferring dumps REMOTE -> THIS"
    rsync_remote_to_local "$SOURCE_DUMP_DIR/" "$DEST_DB_PATH/" ""
    success "DB dumps copied locally to: $DEST_DB_PATH"

    local CL_R
    CL_R=$(prompt "Delete SQL dump files from REMOTE (SOURCE) now? [y/N]: "); CL_R=${CL_R:-n}
    if [[ "$CL_R" =~ ^[Yy]$ ]]; then
      ssh_remote "rm -rf '$SOURCE_DUMP_DIR'"
      success "Deleted remote SQL dumps at $SOURCE_DUMP_DIR."
    else
      warn "Kept remote SQL dumps at $SOURCE_DUMP_DIR."
    fi

    local RS2
    RS2=$(prompt "Restore these DBs on THIS server now? [y/N]: "); RS2=${RS2:-n}
    if [[ "$RS2" =~ ^[Yy]$ ]]; then
      step "Restoring DBs on THIS server (Mode A via socket)"
      shopt -s nullglob
      for sqlfile in "$DEST_DB_PATH"/*.sql; do
        base=$(basename "$sqlfile")
        dbname="${base%.sql}"
        is_system_db "$dbname" && { warn "Skipping system DB $dbname"; continue; }
        info "Restoring $dbname ..."
        mysql -e "CREATE DATABASE IF NOT EXISTS \`$dbname\`;"
        mysql "$dbname" < "$sqlfile"
      done
      success "DB restore completed on THIS server."

      local CL_L
      CL_L=$(prompt "Delete SQL dump files from THIS (DESTINATION) server now? [y/N]: "); CL_L=${CL_L:-n}
      if [[ "$CL_L" =~ ^[Yy]$ ]]; then
        rm -f "$DEST_DB_PATH"/*.sql
        success "Deleted local SQL dumps from $DEST_DB_PATH."
      else
        warn "Kept local SQL dumps at $DEST_DB_PATH."
      fi
    else
      warn "Skipped local restore; SQL dumps remain at: $DEST_DB_PATH"
    fi
  fi

  success "DB migration finished for '$USER'."
}

#########################
# Batch DB migration (SSH mode)
#########################
db_migrate_batch(){
  echo
  step "Batch DB migration"
  local USERS
  USERS=$(prompt "Enter usernames separated by spaces (or 'b' to go back): ")
  [[ "$USERS" == "b" || "$USERS" == "B" ]] && return 0
  [[ -z "$USERS" ]] && { warn "No usernames."; return 0; }

  for USER in $USERS; do
    step "Batch DB migration for user: $USER"
    local DBS=()
    if [[ "$ROLE" == "source" ]]; then
      mapfile -t DBS < <(detect_dbs_for_user_local "$USER")
    else
      mapfile -t DBS < <(detect_dbs_for_user_remote "$USER")
    fi

    if (( ${#DBS[@]} == 0 )); then
      warn "No DBs auto-detected for $USER; skipping."
      continue
    fi

    echo "  Detected DBs for $USER: ${DBS[*]}"
    local TS DUMP_DIR_NAME SOURCE_DUMP_DIR DEST_DB_PATH
    TS=$(date +%Y%m%d_%H%M%S)
    DUMP_DIR_NAME="migdb_${USER}_${TS}"

    if [[ "$ROLE" == "source" ]]; then
      SOURCE_DUMP_DIR="/tmp/$DUMP_DIR_NAME"
      mkdir -p "$SOURCE_DUMP_DIR"
      for db in "${DBS[@]}"; do
        info "[Batch] Dumping $db for $USER..."
        mysqldump --single-transaction --routines --triggers "$db" > "$SOURCE_DUMP_DIR/$db.sql" || warn "Dump failed for $db"
      done
      DEST_DB_PATH="/backup/dbbackup/$USER"
      ssh_remote "mkdir -p '$DEST_DB_PATH'"
      rsync_local_to_remote "$SOURCE_DUMP_DIR/" "$DEST_DB_PATH/" ""
      local CLB
      CLB=$(prompt "Delete SQL dump files from THIS (SOURCE) server for $USER now? [y/N]: "); CLB=${CLB:-n}
      if [[ "$CLB" =~ ^[Yy]$ ]]; then
        rm -rf "$SOURCE_DUMP_DIR"
        success "Deleted local SQL dumps at $SOURCE_DUMP_DIR for $USER."
      else
        warn "Kept local SQL dumps at $SOURCE_DUMP_DIR for $USER."
      fi
      success "Batch DB dumps for $USER sent to REMOTE:$DEST_DB_PATH (restore manually)."
    else
      SOURCE_DUMP_DIR="/tmp/$DUMP_DIR_NAME"
      DEST_DB_PATH="/backup/dbbackup/$USER"
      mkdir -p "$DEST_DB_PATH"
      local DB_LIST_STR=""
      for db in "${DBS[@]}"; do DB_LIST_STR="$DB_LIST_STR $db"; done
      ssh_remote "SOURCE_DUMP_DIR='$SOURCE_DUMP_DIR' DB_LIST_STR='$DB_LIST_STR' bash -s" <<'EOF'
set -euo pipefail
mkdir -p "$SOURCE_DUMP_DIR"
for db in $DB_LIST_STR; do
  echo "[REMOTE-BATCH] Dumping $db -> $SOURCE_DUMP_DIR/$db.sql"
  mysqldump --single-transaction --routines --triggers "$db" > "$SOURCE_DUMP_DIR/$db.sql" || echo "[REMOTE-BATCH] Dump failed for $db"
done
echo "[REMOTE-BATCH] Remote batch DB dump completed."
EOF
      rsync_remote_to_local "$SOURCE_DUMP_DIR/" "$DEST_DB_PATH/" ""
      local CLBR
      CLBR=$(prompt "Delete SQL dump files from REMOTE (SOURCE) for $USER now? [y/N]: "); CLBR=${CLBR:-n}
      if [[ "$CLBR" =~ ^[Yy]$ ]]; then
        ssh_remote "rm -rf '$SOURCE_DUMP_DIR'"
        success "Deleted remote SQL dumps at $SOURCE_DUMP_DIR for $USER."
      else
        warn "Kept remote SQL dumps at $SOURCE_DUMP_DIR for $USER."
      fi
      success "Batch DB dumps for $USER pulled to THIS:$DEST_DB_PATH (restore manually)."
    fi
  done
}

#########################
# Full single account migration (FILES+DB, SSH mode)
#########################
full_migrate_single(){
  echo
  step "Full single account migration (Files + DBs)"
  local USER
  USER=$(prompt "Account username (or 'b' to go back): ")
  [[ "$USER" == "b" || "$USER" == "B" ]] && return 0
  [[ -z "$USER" ]] && { error "No username."; return 1; }

  local EXCL="--exclude=.cpanel --exclude=.trash --exclude=etc --exclude=mail --exclude=logs --exclude=tmp"
  if [[ "$ROLE" == "source" ]]; then
    local DEF_SRC="/home/$USER/" DEF_DEST="/home/$USER"
    local SRC DEST
    SRC=$(prompt "Source path on THIS server [$DEF_SRC]: "); SRC=${SRC:-$DEF_SRC}
    DEST=$(prompt "Dest path on REMOTE [$DEF_DEST]: "); DEST=${DEST:-$DEF_DEST}
    info "Syncing THIS ($SRC) -> REMOTE ($DEST)"
    rsync_local_to_remote "$SRC" "$DEST" "$EXCL"
    success "File sync done."
    ssh_remote "id '$USER' >/dev/null 2>&1 && chown -R '$USER':'$USER' '$DEST' || echo '[INFO] Remote user does not exist yet. Ownership will need fix after account creation.'" || true
  else
    ensure_destination_cpanel_account "$USER"
    local DEF_SRC="/home/$USER/" DEF_DEST="/home/$USER"
    local SRC DEST
    SRC=$(prompt "Source path on REMOTE [$DEF_SRC]: "); SRC=${SRC:-$DEF_SRC}
    DEST=$(prompt "Dest path on THIS server [$DEF_DEST]: "); DEST=${DEST:-$DEF_DEST}
    mkdir -p "$DEST"
    info "Syncing REMOTE ($SRC) -> THIS ($DEST)"
    rsync_remote_to_local "$SRC" "$DEST" "$EXCL"
    success "File sync done."
    if id "$USER" >/dev/null 2>&1; then
      chown -R "$USER:$USER" "$DEST" 2>/dev/null || warn "Ownership fix failed for $USER."
    else
      warn "User '$USER' does not exist yet on DESTINATION. Ownership kept as-is; will need fix after account creation."
    fi
  fi

  db_migrate_single

  if [[ "$ROLE" == "source" && -x /usr/local/cpanel/scripts/suspendacct ]]; then
    local SUSP
    SUSP=$(prompt "Suspend account '$USER' on SOURCE now? [y/N]: "); SUSP=${SUSP:-n}
    if [[ "$SUSP" =~ ^[Yy]$ ]]; then
      /usr/local/cpanel/scripts/suspendacct "$USER" && success "Account '$USER' suspended on SOURCE."
    fi
  fi
}

#########################
# cPanel login + cpsess (no root/SSH on SOURCE)
#########################
cpanel_login_and_get_cpsess(){
  local CP_HOST="$1" CP_PORT="$2" CP_USER="$3" CP_PASS="$4" COOKIES="$5"
  local LOGIN_URL="https://$CP_HOST:$CP_PORT/login/"
  rm -f "$COOKIES"

  info "Logging into cPanel via /login/ to obtain cpsess token..."
  curl -ks -L -c "$COOKIES" -b "$COOKIES" \
    -d "user=$CP_USER&pass=$CP_PASS" "$LOGIN_URL" >/dev/null 2>&1 || true

  local HTML
  HTML=$(curl -ks -L -c "$COOKIES" -b "$COOKIES" \
    "https://$CP_HOST:$CP_PORT/" 2>/dev/null || true)

  local CPS_PATH
  CPS_PATH=$(echo "$HTML" | grep -oE '/cpsess[0-9]+/' | head -n1 | tr -d '\r\n')

  if [[ -n "$CPS_PATH" ]]; then
    CPS_PATH="${CPS_PATH#/}"
    CPS_PATH="${CPS_PATH%/}"
    local CP_BASE="https://$CP_HOST:$CP_PORT/$CPS_PATH"
    success "Got cpsess token path: $CPS_PATH"
    echo "$CP_BASE"
  else
    warn "Could not extract cpsess from HTML. Using non-cpsess base (may fail)."
    echo "https://$CP_HOST:$CP_PORT"
  fi
}

#########################
# cPanel Fileman list_files helper
#########################
cpanel_list_homedir_files(){
  local CP_BASE="$1" COOKIES="$2" CP_USER="$3"
  local JSON
  JSON=$(curl -ks -b "$COOKIES" "$CP_BASE/execute/Fileman/list_files?dir=/home/$CP_USER" 2>/dev/null || true)
  echo "$JSON" | grep -o '"file":"[^"]*"' | sed 's/"file":"//;s/"$//' || true
}

#########################
# Full cPanel Backup Mode (no root/SSH on SOURCE)
#########################
cpanel_full_backup_mode(){
  echo
  step "Full cPanel backup → transfer → restore (no root/SSH on source)"

  if [[ "$ROLE" != "destination" ]]; then
    warn "This mode must be run on the DESTINATION (new) server with WHM root access."
    return
  fi

  if [[ ! -x /usr/local/cpanel/bin/restorepkg ]]; then
    error "restorepkg not found. This must be a WHM/cPanel server."
    return
  fi

  echo
  info "Source cPanel account details (no root/SSH on source):"
  local CP_HOST CP_PORT CP_USER CP_PASS
  CP_HOST=$(prompt "Source cPanel host/IP (e.g. 5.9.106.155): ")
  CP_PORT=$(prompt "Source cPanel port [2083]: "); CP_PORT=${CP_PORT:-2083}
  CP_USER=$(prompt "cPanel username: ")
  CP_PASS=$(prompt_secret "cPanel password for '$CP_USER': ")

  if [[ -z "$CP_HOST" || -z "$CP_USER" || -z "$CP_PASS" ]]; then
    error "Host, username, and password are required."
    return
  fi

  local DEST_DIR
  while :; do
    DEST_DIR=$(prompt "Local backup storage directory (absolute path) on THIS server: ")
    if [[ -z "$DEST_DIR" ]]; then
      warn "Path cannot be empty."
    else
      break
    fi
  done
  mkdir -p "$DEST_DIR"

  info "Source cPanel: https://$CP_HOST:$CP_PORT  User: $CP_USER"
  info "Destination backup dir: $DEST_DIR"

  local COOKIES="/tmp/cp_cookies_$$"
  local CP_BASE
  CP_BASE=$(cpanel_login_and_get_cpsess "$CP_HOST" "$CP_PORT" "$CP_USER" "$CP_PASS" "$COOKIES")

  echo
  step "Taking initial snapshot of /home/$CP_USER file list (before backup trigger)"
  local BASELINE_LIST
  BASELINE_LIST=$(cpanel_list_homedir_files "$CP_BASE" "$COOKIES" "$CP_USER")
  info "Initial file count in /home/$CP_USER: $(echo "$BASELINE_LIST" | wc -l | awk '{print $1}')"

  echo
  step "Triggering full backup via backup interface under cpsess (homedir)"

  local CP_SKIN
  local HTTP_JUP
  HTTP_JUP=$(curl -ks -o /dev/null -w '%{http_code}' \
    "$CP_BASE/frontend/jupiter/backup/wizard-fullbackup.html" || true)
  if [[ "$HTTP_JUP" == "200" ]]; then
    CP_SKIN="jupiter"
  else
    CP_SKIN="paper_lantern"
  fi

  info "Using cPanel theme: $CP_SKIN"

  local BACKUP_POST_URL
  if [[ "$CP_SKIN" == "jupiter" ]]; then
    BACKUP_POST_URL="$CP_BASE/frontend/jupiter/backup/wizard-fullbackup.html"
  else
    BACKUP_POST_URL="$CP_BASE/frontend/paper_lantern/backup/dofullbackup.html"
  fi

  info "Submitting full backup request (dest=homedir, no email)..."
  local BACKUP_RESP
  BACKUP_RESP=$(curl -ks -b "$COOKIES" \
    -d "dest=homedir&email_radio=0&email=&submit=Generate+Backup" \
    "$BACKUP_POST_URL" || true)

  if echo "$BACKUP_RESP" | grep -qi "The system failed to create or deliver the requested backup"; then
    error "cPanel responded: 'The system failed to create or deliver the requested backup.'"
    warn "If manual UI works but this does not, theme/CSRF details may differ. Try again or use SSH mode."
    rm -f "$COOKIES"
    return
  fi

  success "Backup requested! Now watching /home/$CP_USER for new backup tarball."

  echo
  step "Waiting for new backup tar.gz in /home/$CP_USER"
  local BACKUP_FILE=""
  local MAX_TRIES=40
  local SLEEP_SEC=30

  for ((i=1; i<=MAX_TRIES; i++)); do
    info "Detection attempt $i/$MAX_TRIES ..."
    local CUR_LIST
    CUR_LIST=$(cpanel_list_homedir_files "$CP_BASE" "$COOKIES" "$CP_USER")

    local NEW_FILE=""
    while read -r f; do
      [[ -z "$f" ]] && continue
      # accept backup-MM-DD-YYYY_USER.tar.gz or cpmove-USER.tar.gz
      if [[ "$f" =~ ^backup-.*_${CP_USER}\.tar\.gz$ || "$f" =~ ^cpmove-${CP_USER}\.tar\.gz$ ]]; then
        if ! grep -qx "$f" <<<"$BASELINE_LIST"; then
          NEW_FILE="$f"
          break
        fi
      fi
    done <<<"$CUR_LIST"

    if [[ -n "$NEW_FILE" ]]; then
      BACKUP_FILE="$NEW_FILE"
      success "Detected new backup file: $BACKUP_FILE"
      break
    fi

    info "No new backup tarball yet. Sleeping ${SLEEP_SEC}s..."
    sleep "$SLEEP_SEC"
  done

  if [[ -z "${BACKUP_FILE:-}" ]]; then
    error "Timed out waiting for new backup tarball in /home/$CP_USER."
    rm -f "$COOKIES"
    return
  fi

  echo
  step "Downloading backup via HTTPS (Fileman/get_file under cpsess)"
  local LOCAL_BACKUP_PATH="$DEST_DIR/$BACKUP_FILE"
  local REMOTE_PATH="/home/$CP_USER/$BACKUP_FILE"

  local ENC_PATH
  ENC_PATH=$(printf '%s' "$REMOTE_PATH" | sed 's/\//%2F/g')

  local GET_URL="$CP_BASE/execute/Fileman/get_file?path=$ENC_PATH"

  info "Downloading $REMOTE_PATH -> $LOCAL_BACKUP_PATH"
  if ! curl -ks -b "$COOKIES" "$GET_URL" -o "$LOCAL_BACKUP_PATH"; then
    error "Download failed via Fileman/get_file."
    rm -f "$COOKIES"
    return
  fi

  if [[ ! -s "$LOCAL_BACKUP_PATH" ]]; then
    error "Downloaded file is empty or missing: $LOCAL_BACKUP_PATH"
    rm -f "$COOKIES"
    return
  fi

  success "Backup downloaded to: $LOCAL_BACKUP_PATH"
  rm -f "$COOKIES"

  echo
  step "Restoring cPanel account on THIS (destination) server using restorepkg"

  if id "$CP_USER" >/dev/null 2>&1; then
    warn "Local user '$CP_USER' already exists on DESTINATION."

    # Option E: show WHM account summary if possible
    if whm_available; then
      info "Existing account summary for '$CP_USER':"
      whmapi1 accountsummary user="$CP_USER" 2>/dev/null | sed 's/^/  /'
    else
      warn "WHM CLI not available or not functional; cannot show accountsummary."
    fi

    # Option 1B: Default to --force, but still confirm
    local FORCE
    FORCE=$(prompt "Use restorepkg --force (overwrite existing account data)? [Y/n]: "); FORCE=${FORCE:-y}
    if [[ "$FORCE" =~ ^[Yy]$ ]]; then
      info "Running: restorepkg --force \"$LOCAL_BACKUP_PATH\""
      /usr/local/cpanel/bin/restorepkg --force "$LOCAL_BACKUP_PATH"
    else
      error "Aborting restore because user '$CP_USER' already exists and you chose not to force."
      return
    fi
  else
    info "Running: restorepkg \"$LOCAL_BACKUP_PATH\""
    /usr/local/cpanel/bin/restorepkg "$LOCAL_BACKUP_PATH"
  fi

  success "Restore completed for account '$CP_USER'."

  if id "$CP_USER" >/dev/null 2>&1 && [[ -d "/home/$CP_USER" ]]; then
    chown -R "$CP_USER:$CP_USER" "/home/$CP_USER" 2>/dev/null || warn "Ownership fix failed for /home/$CP_USER."
  fi

  echo
  local DEL
  DEL=$(prompt "Delete local backup file $LOCAL_BACKUP_PATH to save space? [y/N]: "); DEL=${DEL:-n}
  if [[ "$DEL" =~ ^[Yy]$ ]]; then
    rm -f "$LOCAL_BACKUP_PATH"
    success "Deleted local backup archive."
  else
    info "Kept local backup archive at $LOCAL_BACKUP_PATH."
  fi

  success "Full cPanel backup → transfer → restore completed using ONLY cPanel HTTPS + cpsess."
}

#########################
# Remote server menu (SSH mode)
#########################
remote_server_menu(){
  while :; do
    echo
    step "Remote Server Management"
    echo "  1) Select / switch SSH server"
    echo "  2) Back to Main Menu"
    local C; C=$(prompt "Choose [1-2]: ")
    case "$C" in
      1) init_ssh ;;
      2) return ;;
      *) warn "Invalid option." ;;
    esac
  done
}

#########################
# Tools / Ownership Menu
#########################
tools_menu(){
  while :; do
    echo
    step "Tools / Fix Ownership"
    echo "  1) Fix ownership for a local user (/home/USER)"
    echo "  2) Back to Main Menu"
    local C; C=$(prompt "Choose [1-2]: ")
    case "$C" in
      1)
        local U
        U=$(prompt "Enter local username (or 'b' to go back): ")
        [[ "$U" == "b" || "$U" == "B" ]] && continue
        if ! id "$U" >/dev/null 2>&1; then
          error "User '$U' does not exist on this server."
        else
          if [[ -d "/home/$U" ]]; then
            step "Fixing ownership: chown -R $U:$U /home/$U"
            chown -R "$U:$U" "/home/$U"
            success "Ownership fixed for /home/$U."
          else
            warn "/home/$U does not exist."
          fi
        fi
        ;;
      2) return ;;
      *) warn "Invalid option." ;;
    esac
  done
}

#########################
# Logs Viewer Menu
#########################
logs_menu(){
  while :; do
    echo
    step "Logs Viewer"
    if ! ls "$LOG_DIR"/migration_*.log >/dev/null 2>&1; then
      warn "No logs found in $LOG_DIR"
      return
    fi
    echo "Recent logs:"
    ls -1t "$LOG_DIR"/migration_*.log 2>/dev/null | head -n 10 | nl -ba
    echo "  q) Back to Main Menu"
    local CH
    CH=$(prompt "Enter log number to view (tail -50) or 'q' to go back: ")
    [[ "$CH" == "q" || "$CH" == "Q" ]] && return
    if [[ "$CH" =~ ^[0-9]+$ ]]; then
      local FILE
      FILE=$(ls -1t "$LOG_DIR"/migration_*.log 2>/dev/null | sed -n "${CH}p" || true)
      if [[ -n "$FILE" && -f "$FILE" ]]; then
        step "Showing last 50 lines of $FILE"
        tail -n 50 "$FILE"
      else
        warn "Invalid selection."
      fi
    else
      warn "Invalid input."
    fi
  done
}

#########################
# Migration Menu (SSH-based)
#########################
migration_menu(){
  ensure_ssh_initialized
  while :; do
    echo
    step "Migration (SSH-based)"
    echo "  1) Single – Files only"
    echo "  2) Single – Databases only"
    echo "  3) Single – Files + Databases (full)"
    echo "  4) Single – Incremental file sync"
    echo "  5) Batch – Files only"
    echo "  6) Batch – Databases only (dump + transfer)"
    echo "  7) Batch – Incremental files"
    echo "  8) Back to Main Menu"
    local C; C=$(prompt "Choose [1-8]: ")
    case "$C" in
      1) file_sync_single ;;
      2) db_migrate_single ;;
      3) full_migrate_single ;;
      4) incremental_sync_single ;;
      5) file_sync_batch ;;
      6) db_migrate_batch ;;
      7) incremental_sync_batch ;;
      8) return ;;
      *) warn "Invalid option." ;;
    esac
  done
}

#########################
# Main Menu
#########################
main_menu(){
  while :; do
    echo
    step "Main Menu"
    echo "  1) Migration (SSH-based)"
    echo "  2) Full cPanel backup → transfer → restore (no root/SSH on source)"
    echo "  3) SSH Server Profiles"
    echo "  4) Tools / Fix Ownership"
    echo "  5) View Logs"
    echo "  6) Exit"
    local C; C=$(prompt "Choose [1-6]: ")
    case "$C" in
      1) migration_menu ;;
      2) cpanel_full_backup_mode ;;
      3) ensure_ssh_initialized; remote_server_menu ;;
      4) tools_menu ;;
      5) logs_menu ;;
      6) success "Bye."; exit 0 ;;
      *) warn "Invalid option." ;;
    esac
  done
}

#########################
# Start
#########################
main_menu
