#!/usr/bin/env bash
# bash disk_monitor.sh --allow-root --health (Ubuntu) and sh disk_monitor.sh --allow-root --health (Almalinux)
# disk_analyzer_v6.1.1.sh  (v6.1.1)
# Advanced Disk Analysis + Safe Cleaning for cPanel/Linux servers
# - Reports saved to /var/log/disk_monitor/advanced
# - JSON + terminal text output
# - JSON escaping via sed using '|' delimiter (safe for / in paths)
# - Optimizations: find -print0 | xargs -0 for large-file operations
# - Fix: removed -n1 when combined with -I{} for xargs (no warnings)
#
set -euo pipefail

### ---------- Configurable Defaults ----------
BASE_DIR="/var/log/disk_monitor"
ADV_DIR="${BASE_DIR}/advanced"
LOGFILE="${ADV_DIR}/disk_analyzer_v6.1.1.log"
DEFAULT_TOP_N=10
DEFAULT_MIN_BYTES=$((100 * 1024 * 1024))   # 100 MB
BIG_FILE_THRESHOLD=$((200 * 1024 * 1024))  # 200 MB
ALLOW_ROOT=true
ROOT_FLAG=0
YES_CLEAN=0
OUTPUT_DIR_OVERRIDE=""

### ---------- Colors ----------
RED='\033[1;31m'; YELLOW='\033[1;33m'; GREEN='\033[1;32m'; CYAN='\033[1;36m'; RESET='\033[0m'
DATE_ISO(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }

### ---------- Helpers ----------
require_cmd(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing required: $1" >&2; exit 1; }; }
human_size() {
  local b=$1
  if [ "$b" -ge $((1024**3)) ]; then awk -v b="$b" 'BEGIN{printf "%.2f GB",b/1024/1024/1024}'
  elif [ "$b" -ge $((1024**2)) ]; then awk -v b="$b" 'BEGIN{printf "%.2f MB",b/1024/1024}'
  elif [ "$b" -ge 1024 ]; then awk -v b="$b" 'BEGIN{printf "%.2f KB",b/1024}'
  else printf "%d B" "$b"; fi
}
color_size() {
  local b=$1
  if (( b >= 5*1024*1024*1024 )); then echo -e "${RED}$(human_size ${b})${RESET}"
  elif (( b >= 1024*1024*1024 )); then echo -e "${YELLOW}$(human_size ${b})${RESET}"
  else echo -e "${GREEN}$(human_size ${b})${RESET}"; fi
}
log(){ mkdir -p "${ADV_DIR}" || true; echo "$(DATE_ISO) $*" | tee -a "${LOGFILE}"; }

safe_init(){
  mkdir -p "${ADV_DIR}" "${BASE_DIR}" || { echo "Cannot create ${ADV_DIR}"; exit 1; }
  touch "${LOGFILE}" 2>/dev/null || echo "WARN: cannot write ${LOGFILE}"
  if [ -n "${OUTPUT_DIR_OVERRIDE}" ]; then
    ADV_DIR="${OUTPUT_DIR_OVERRIDE}"
    mkdir -p "${ADV_DIR}" || { echo "Cannot create override output ${ADV_DIR}"; exit 1; }
  fi
}

ensure_not_root() {
  if [ "$(id -u)" -eq 0 ]; then
    if [ "${ROOT_FLAG}" -ne 1 ] && [ "${ALLOW_ROOT}" != "true" ]; then
      echo "Refusing to run as root. To run as root pass --allow-root or set ALLOW_ROOT=true inside script." >&2
      exit 3
    fi
  fi
}

confirm_action() {
  local message="$1"
  if [ "${YES_CLEAN}" -eq 1 ]; then
    return 0
  fi
  echo ""
  echo ">>> ${message}"
  echo "Type YES to confirm:"
  read -r conf
  if [ "${conf}" = "YES" ]; then return 0; else echo "Aborted."; return 1; fi
}

# Pretty table helpers
print_header(){ echo -e "${CYAN}────────────────────────────────────────────────────────────────────${RESET}"; echo -e "${CYAN} $* ${RESET}"; echo -e "${CYAN}────────────────────────────────────────────────────────────────────${RESET}"; }
print_table_start(){ printf "%-3s | %-12s | %-8s | %-8s | %s\n" "#" "Size" "Owner" "Inode" "Path"; echo "---+--------------+----------+----------+--------------------------------------"; }
print_row(){
  local idx="$1" bytes="$2" owner="$3" inode="$4" path="$5"
  local csize="$(color_size ${bytes})"
  printf "%-3s | %-12s | %-8s | %-8s | %s\n" "${idx}" "${csize}" "${owner}" "${inode}" "${path}"
}
write_json_array_start(){ local f="$1"; printf "[" > "${f}"; }
write_json_array_end(){ local f="$1"; sed -i '$ s/,$//' "${f}" || true; printf "]\n" >> "${f}"; }

### ---------- Quick dependency check ----------
REQ_CMDS=(find stat awk sort head du df gzip sha1sum xargs sed printf mysql)
for cmd in "${REQ_CMDS[@]}"; do
  require_cmd "${cmd}"
done

### ---------- Basic Disk Analysis (Main Menu Options 1–3) ----------

disk_analyze_path() {
  local path="$1" top="$2"
  local ts=$(DATE_ISO)
  local out="${ADV_DIR}/home_top${top}_${ts}.json"
  write_json_array_start "${out}"
  print_header "Top ${top} directories in ${path} (sizes in MB/GB)"
  print_table_start
  local idx=0
  if [ ! -d "${path}" ]; then echo "Path not found: ${path}"; return 1; fi
  du -sb "${path}"/* 2>/dev/null | sort -nr | head -n "${top}" | while read -r size pe; do
    [ -z "${pe}" ] && continue
    idx=$((idx+1))
    owner="$(stat -c '%U' "$pe" 2>/dev/null || echo unknown)"
    inode="$(stat -c '%i' "$pe" 2>/dev/null || echo 0)"
    escaped_path=$(printf '%s' "$pe" | sed 's|"|\\\"|g')
    print_row "${idx}" "${size}" "${owner}" "${inode}" "${pe}"
    printf '{"path":"%s","size_bytes":%s,"size_human":"%s","owner":"%s","inode":%s},\n' \
      "${escaped_path}" "${size}" "$(human_size ${size})" "${owner}" "${inode}" >> "${out}"
  done
  write_json_array_end "${out}"
  echo "Report saved to: ${out}"
  log "disk_analyze_path(${path},top=${top}) -> ${out}"
}

disk_analyze_all() {
  local path="$1"
  local ts=$(DATE_ISO)
  local out="${ADV_DIR}/home_all_${ts}.json"
  write_json_array_start "${out}"
  print_header "All directories in ${path} (sizes in MB/GB)"
  print_table_start
  local idx=0
  if [ ! -d "${path}" ]; then echo "Path not found: ${path}"; return 1; fi
  du -sb "${path}"/* 2>/dev/null | sort -nr | while read -r size pe; do
    [ -z "${pe}" ] && continue
    idx=$((idx+1))
    owner="$(stat -c '%U' "$pe" 2>/dev/null || echo unknown)"
    inode="$(stat -c '%i' "$pe" 2>/dev/null || echo 0)"
    escaped_path=$(printf '%s' "$pe" | sed 's|"|\\\"|g')
    print_row "${idx}" "${size}" "${owner}" "${inode}" "${pe}"
    printf '{"path":"%s","size_bytes":%s,"size_human":"%s","owner":"%s","inode":%s},\n' \
      "${escaped_path}" "${size}" "$(human_size ${size})" "${owner}" "${inode}" >> "${out}"
  done
  write_json_array_end "${out}"
  echo "Full ${path} report saved to: ${out}"
  log "disk_analyze_all(${path}) -> ${out}"
}

disk_analyze_system() {
  local ts=$(DATE_ISO)
  local out="${ADV_DIR}/system_topdirs_${ts}.json"
  write_json_array_start "${out}"
  print_header "Full system disk analysis (top-level directories)"
  print_table_start
  local idx=0
  du -sb /* 2>/dev/null | sort -nr | while read -r size dir; do
    [ -z "${dir}" ] && continue
    idx=$((idx+1))
    owner="$(stat -c '%U' "$dir" 2>/dev/null || echo root)"
    inode="$(stat -c '%i' "$dir" 2>/dev/null || echo 0)"
    escaped_path=$(printf '%s' "$dir" | sed 's|"|\\\"|g')
    print_row "${idx}" "${size}" "${owner}" "${inode}" "${dir}"
    printf '{"path":"%s","size_bytes":%s,"size_human":"%s","owner":"%s","inode":%s},\n' \
      "${escaped_path}" "${size}" "$(human_size ${size})" "${owner}" "${inode}" >> "${out}"
  done
  write_json_array_end "${out}"
  echo "System disk report saved to: ${out}"
  log "disk_analyze_system -> ${out}"
}

### ---------- Existing analysis functions (logs/backups/tmp/top/inode/mount) ----------

find_large_logs(){
  local minbytes="${1:-${DEFAULT_MIN_BYTES}}"
  local ts=$(DATE_ISO)
  local out="${ADV_DIR}/large_logs_${minbytes}_bytes_${ts}.json"
  write_json_array_start "${out}"
  print_header "Large log files (> $(human_size ${minbytes})) - full filesystem"
  print_table_start
  local idx=0
  find / -type f \( -iname "*.log" -o -iname "error_log" -o -iname "*.txt" \) -size +"$((minbytes/1024))"k -print0 2>/dev/null | xargs -0 -I{} bash -c '
    file="{}"
    [ -f "$file" ] || exit 0
    size=$(stat -c %s "$file" 2>/dev/null || echo 0)
    owner=$(stat -c %U "$file" 2>/dev/null || echo unknown)
    inode=$(stat -c %i "$file" 2>/dev/null || echo 0)
    escaped=$(printf "%s" "$file" | sed '"'"'s|"|\\\"|g'"'"')
    printf "%s\t%s\t%s\t%s\n" "$size" "$owner" "$inode" "$file"
  ' | sort -nr | while IFS=$'\t' read -r size owner inode file; do
    idx=$((idx+1))
    escaped=$(printf '%s' "$file" | sed 's|"|\\\"|g')
    print_row "${idx}" "${size}" "${owner}" "${inode}" "${file}"
    printf '{"path":"%s","size_bytes":%s,"size_human":"%s","owner":"%s","inode":%s},\n' \
      "${escaped}" "${size}" "$(human_size ${size})" "${owner}" "${inode}" >> "${out}"
  done
  write_json_array_end "${out}"
  echo "Report: ${out}"
  log "find_large_logs -> ${out}"
}

find_error_logs_home(){
  local minbytes="${1:-${DEFAULT_MIN_BYTES}}"
  local ts=$(DATE_ISO)
  local out="${ADV_DIR}/home_error_logs_${minbytes}_bytes_${ts}.json"
  write_json_array_start "${out}"
  print_header "error_log files in /home > $(human_size ${minbytes})"
  print_table_start
  local idx=0
  find /home -type f -iname "error_log" -size +"$((minbytes/1024))"k -print0 2>/dev/null | xargs -0 -I{} bash -c '
    file="{}"
    [ -f "$file" ] || exit 0
    size=$(stat -c %s "$file" 2>/dev/null || echo 0)
    owner=$(stat -c %U "$file" 2>/dev/null || echo unknown)
    inode=$(stat -c %i "$file" 2>/dev/null || echo 0)
    escaped=$(printf "%s" "$file" | sed '"'"'s|"|\\\"|g'"'"')
    printf "%s\t%s\t%s\t%s\n" "$size" "$owner" "$inode" "$file"
  ' | sort -nr | while IFS=$'\t' read -r size owner inode file; do
    idx=$((idx+1))
    escaped=$(printf '%s' "$file" | sed 's|"|\\\"|g')
    print_row "${idx}" "${size}" "${owner}" "${inode}" "${file}"
    printf '{"path":"%s","size_bytes":%s,"size_human":"%s","owner":"%s","inode":%s},\n' \
      "${escaped}" "${size}" "$(human_size ${size})" "${owner}" "${inode}" >> "${out}"
  done
  write_json_array_end "${out}"
  echo "Report: ${out}"
  log "find_error_logs_home -> ${out}"
}

find_large_backups(){
  local minbytes="${1:-$DEFAULT_MIN_BYTES}"
  local ts=$(DATE_ISO)
  local out="${ADV_DIR}/large_backups_${minbytes}_bytes_${ts}.json"
  write_json_array_start "${out}"
  print_header "Large backups > $(human_size ${minbytes}) (.tar.gz, .zip, .sql)"
  print_table_start
  local idx=0
  find / -type f \( -iname "*.tar.gz" -o -iname "*.zip" -o -iname "*.sql" -o -iname "*.tgz" \) -size +"$((minbytes/1024))"k -print0 2>/dev/null | xargs -0 -I{} bash -c '
    file="{}"
    [ -f "$file" ] || exit 0
    size=$(stat -c %s "$file" 2>/dev/null || echo 0)
    owner=$(stat -c %U "$file" 2>/dev/null || echo unknown)
    inode=$(stat -c %i "$file" 2>/dev/null || echo 0)
    printf "%s\t%s\t%s\t%s\n" "$size" "$owner" "$inode" "$file"
  ' | sort -nr | while IFS=$'\t' read -r size owner inode file; do
    idx=$((idx+1))
    escaped=$(printf '%s' "$file" | sed 's|"|\\\"|g')
    print_row "${idx}" "${size}" "${owner}" "${inode}" "${file}"
    printf '{"path":"%s","size_bytes":%s,"size_human":"%s","owner":"%s","inode":%s},\n' \
      "${escaped}" "${size}" "$(human_size ${size})" "${owner}" "${inode}" >> "${out}"
  done
  write_json_array_end "${out}"
  echo "Report: ${out}"
  log "find_large_backups -> ${out}"
}

scan_tmp_dirs(){
  local minbytes="${1:-$((50*1024*1024))}"  # 50MB default
  local older_days="${2:-7}"
  local ts=$(DATE_ISO)
  local out="${ADV_DIR}/tmp_scan_${minbytes}_bytes_older${older_days}d_${ts}.json"
  write_json_array_start "${out}"
  print_header "/tmp and user tmp: files > $(human_size ${minbytes}) or older than ${older_days} days"
  print_table_start
  local idx=0
  # /tmp
  find /tmp -type f \( -size +"$((minbytes/1024))"k -o -mtime +"${older_days}" \) -print0 2>/dev/null | xargs -0 -I{} bash -c '
    file="{}"
    size=$(stat -c %s "$file" 2>/dev/null || echo 0)
    owner=$(stat -c %U "$file" 2>/dev/null || echo unknown)
    inode=$(stat -c %i "$file" 2>/dev/null || echo 0)
    mtime=$(stat -c %Y "$file" 2>/dev/null || echo 0)
    printf "%s\t%s\t%s\t%s\t%s\n" "$size" "$owner" "$inode" "$mtime" "$file"
  ' | sort -nr | while IFS=$'\t' read -r size owner inode mtime file; do
    idx=$((idx+1))
    escaped=$(printf '%s' "$file" | sed 's|"|\\\"|g')
    print_row "${idx}" "${size}" "${owner}" "${inode}" "${file}"
    printf '{"path":"%s","size_bytes":%s,"size_human":"%s","owner":"%s","inode":%s,"mtime_epoch":%s},\n' \
      "${escaped}" "${size}" "$(human_size ${size})" "${owner}" "${inode}" "${mtime}" >> "${out}"
  done

  # user tmp under /home
  find /home -path "*/tmp/*" -type f \( -size +"$((minbytes/1024))"k -o -mtime +"${older_days}" \) -print0 2>/dev/null | xargs -0 -I{} bash -c '
    file="{}"
    size=$(stat -c %s "$file" 2>/dev/null || echo 0)
    owner=$(stat -c %U "$file" 2>/dev/null || echo unknown)
    inode=$(stat -c %i "$file" 2>/dev/null || echo 0)
    mtime=$(stat -c %Y "$file" 2>/dev/null || echo 0)
    printf "%s\t%s\t%s\t%s\t%s\n" "$size" "$owner" "$inode" "$mtime" "$file"
  ' | sort -nr | while IFS=$'\t' read -r size owner inode mtime file; do
    idx=$((idx+1))
    escaped=$(printf '%s' "$file" | sed 's|"|\\\"|g')
    print_row "${idx}" "${size}" "${owner}" "${inode}" "${file}"
    printf '{"path":"%s","size_bytes":%s,"size_human":"%s","owner":"%s","inode":%s,"mtime_epoch":%s},\n' \
      "${escaped}" "${size}" "$(human_size ${size})" "${owner}" "${inode}" "${mtime}" >> "${out}"
  done

  write_json_array_end "${out}"
  echo "Report: ${out}"
  log "scan_tmp_dirs -> ${out}"
}

top_biggest_files(){
  local top="${1:-50}"
  local ts=$(DATE_ISO)
  local out="${ADV_DIR}/top_files_${top}_${ts}.json"
  write_json_array_start "${out}"
  print_header "Top ${top} biggest files on filesystem (by bytes)"
  print_table_start
  local idx=0
  # safe list across filesystems
  find / -xdev -type f -printf "%s\t%p\0" 2>/dev/null | sort -z -rn | tr '\0' '\n' | head -n "${top}" | while IFS=$'\t' read -r size file; do
    [ -z "${file}" ] && continue
    owner=$(stat -c %U "$file" 2>/dev/null || echo unknown)
    inode=$(stat -c %i "$file" 2>/dev/null || echo 0)
    idx=$((idx+1))
    escaped=$(printf '%s' "$file" | sed 's|"|\\\"|g')
    print_row "${idx}" "${size}" "${owner}" "${inode}" "${file}"
    printf '{"path":"%s","size_bytes":%s,"size_human":"%s","owner":"%s","inode":%s},\n' \
      "${escaped}" "${size}" "$(human_size ${size})" "${owner}" "${inode}" >> "${out}"
  done
  write_json_array_end "${out}"
  echo "Report: ${out}"
  log "top_biggest_files -> ${out}"
}

inode_usage(){
  local ts=$(DATE_ISO)
  local out="${ADV_DIR}/inode_usage_${ts}.json"
  write_json_array_start "${out}"
  print_header "Inode usage per mount (highlight >80%)"
  printf "%-20s %-10s %-10s %-8s\n" "Mount" "InodesUsed" "InodesFree" "Use%"
  df -i 2>/dev/null | awk 'NR>1{printf "%-20s %10s %10s %8s\n",$6,$3,$4,$5}' | while read -r mount used free usepct; do
    pct=$(echo "${usepct}" | tr -d '%')
    color="${GREEN}"
    if [ "${pct}" -ge 90 ]; then color="${RED}"; elif [ "${pct}" -ge 80 ]; then color="${YELLOW}"; fi
    printf "%-20s %-10s %-10s ${color}%8s${RESET}\n" "${mount}" "${used}" "${free}" "${usepct}"
    printf '{"mount":"%s","used":%s,"free":%s,"use_percent":"%s"},\n' "${mount}" "${used}" "${free}" "${usepct}" >> "${out}"
  done
  write_json_array_end "${out}"
  echo "Report: ${out}"
  log "inode_usage -> ${out}"
}

mount_summary(){
  local ts=$(DATE_ISO)
  local out="${ADV_DIR}/mount_summary_${ts}.json"
  write_json_array_start "${out}"
  print_header "Mount summary (df -h)"
  printf "%-8s %-8s %-8s %-6s %s\n" "Filesystem" "Size" "Used" "Use%" "MountedOn"
  ( df -h --type=ext4 --type=xfs 2>/dev/null || df -h 2>/dev/null ) | awk 'NR>1{printf "%-8s %-8s %-8s %-6s %s\n",$1,$2,$3,$5,$6}' | while read -r fs size used usepct mount; do
    printf "%-8s %-8s %-8s %-6s %s\n" "${fs}" "${size}" "${used}" "${usepct}" "${mount}"
    escaped=$(printf '%s' "${fs}" | sed 's|"|\\\"|g')
    printf '{"filesystem":"%s","size":"%s","used":"%s","use_percent":"%s","mount":"%s"},\n' "${escaped}" "${size}" "${used}" "${usepct}" "${mount}" >> "${out}"
  done
  write_json_array_end "${out}"
  echo "Report: ${out}"
  log "mount_summary -> ${out}"
}

### ---------- Advanced features ----------

# A) File Type / Extension Statistics
analyze_file_types(){
  local path="${1:-/home}"
  local ts=$(DATE_ISO)
  local out="${ADV_DIR}/file_type_stats_${ts}.json"
  write_json_array_start "${out}"
  print_header "Top file extensions by total size under ${path}"
  echo -e "Ext\tCount\tTotal_MB"
  find "${path}" -type f -print0 2>/dev/null | xargs -0 -I{} bash -c '
    f="{}"; base=$(basename "$f"); size=$(stat -c %s "$f" 2>/dev/null || echo 0); printf "%s\t%s\n" "$base" "$size"
  ' | awk -F'\t' '{
      name=$1; size=$2; n=split(name,parts,".");
      if(n>1){ ext=tolower(parts[n]); } else { ext="(none)"; }
      count[ext]++; sum[ext]+=size;
    } END {
      for (e in sum) { printf "%s\t%d\t%.2f\n", e, count[e], sum[e]/1024/1024 }
    }' | sort -k3 -nr | head -n 50 | while IFS=$'\t' read -r ext cnt mb; do
      printf "%-8s %-8s %-8s\n" "${ext}" "${cnt}" "${mb}"
      escaped_ext=$(printf '%s' "${ext}" | sed 's|"|\\\"|g')
      printf '{"ext":"%s","count":%s,"total_MB":%.2f},\n' "${escaped_ext}" "${cnt}" "${mb}" >> "${out}"
    done
  write_json_array_end "${out}"
  echo "Report: ${out}"
  log "analyze_file_types(${path}) -> ${out}"
}

# B) Directory Growth History Comparison (awk-based)
compare_growth_reports(){
  print_header "Compare growth between last two /home reports (awk-based)"
  last_two=( $(ls -1t ${ADV_DIR}/home_top*.json 2>/dev/null | head -n 2) )
  if [ ${#last_two[@]} -lt 2 ]; then echo "Not enough reports (need two home_top*.json)"; return; fi
  old="${last_two[1]}"
  new="${last_two[0]}"
  echo "Comparing:"
  echo "  Older: ${old}"
  echo "  Newer: ${new}"

  awk '
    function get_path(s,   m) { if (match(s, /"path"[[:space:]]*:[[:space:]]*"([^"]+)"/, m)) return m[1]; return ""; }
    function get_size(s,   m) { if (match(s, /"size_bytes"[[:space:]]*:[[:space:]]*([0-9]+)/, m)) return m[1]; return 0; }
    NR==FNR { p=get_path($0); s=get_size($0); if(p!="") old[p]=s; next; }
    { p=get_path($0); s=get_size($0); if(p!="") { delta = s - (old[p]+0); growth[p]=delta; } }
    END { for (p in growth) print growth[p] "\t" p; }
  ' "${old}" "${new}" | sort -nr | head -n 20 | awk -F'\t' '{printf "%2d) %s | %+10.2f MB\n", NR, $2, $1/1024/1024}'
  out="${ADV_DIR}/growth_compare_$(date -u +%Y%m%dT%H%M%SZ).json"
  awk '
    function get_path(s,   m) { if (match(s, /"path"[[:space:]]*:[[:space:]]*"([^"]+)"/, m)) return m[1]; return ""; }
    function get_size(s,   m) { if (match(s, /"size_bytes"[[:space:]]*:[[:space:]]*([0-9]+)/, m)) return m[1]; return 0; }
    NR==FNR { p=get_path($0); s=get_size($0); if(p!="") old[p]=s; next; }
    { p=get_path($0); s=get_size($0); if(p!="") { delta = s - (old[p]+0); arr[++c]=p "\t" old[p] "\t" s "\t" delta } }
    END {
      printf "[" > "'"${out}"'";
      n = (c<50?c:50);
      for(i=1;i<=n;i++){
        split(arr[i],f,"\t");
        gsub(/"/,"\\\"",f[1]);
        printf "{\"path\":\"%s\",\"old\":%d,\"new\":%d,\"delta\":%d},\n", f[1], f[2], f[3], f[4] > "'"${out}"'";
      }
      printf "]\n" >> "'"${out}"'";
    }
  ' "${old}" "${new}"
  echo "JSON report: ${out}"
  log "compare_growth_reports -> ${out}"
}

# C) Duplicate File Finder (sha1) - safer with -print0/xargs -0
find_duplicates(){
  local minsize_bytes="${1:-$((10*1024*1024))}"  # default 10MB
  local ts=$(DATE_ISO)
  local out="${ADV_DIR}/duplicates_over_${minsize_bytes}_bytes_${ts}.json"
  write_json_array_start "${out}"
  print_header "Detecting duplicate files (sha1) for files > $(human_size ${minsize_bytes})"
  local tmp="${ADV_DIR}/sha1_list_${ts}.tmp"
  # produce stable sorted list: "<hash> <filepath>"
  find /home -type f -size +"${minsize_bytes}c" -print0 2>/dev/null | xargs -0 -n50 sha1sum 2>/dev/null | sort > "${tmp}" || true

  # identify duplicate hashes
  awk '{print $1}' "${tmp}" | uniq -d | while read -r hash; do
    count=$(grep -c "^${hash} " "${tmp}" || echo 0)
    echo "Duplicate hash: ${hash} (${count} files)"
    grep "^${hash} " "${tmp}" | while read -r h file; do
      [ -z "${file}" ] && continue
      size=$(stat -c %s "${file}" 2>/dev/null || echo 0)
      owner=$(stat -c %U "${file}" 2>/dev/null || echo unknown)
      inode=$(stat -c %i "${file}" 2>/dev/null || echo 0)
      escaped_file=$(printf '%s' "${file}" | sed 's|"|\\\"|g')
      printf '{"hash":"%s","path":"%s","size_bytes":%s,"owner":"%s","inode":%s},\n' \
        "${hash}" "${escaped_file}" "${size}" "${owner}" "${inode}" >> "${out}"
    done
  done
  rm -f "${tmp}" 2>/dev/null || true
  write_json_array_end "${out}"
  echo "Duplicate report: ${out}"
  log "find_duplicates(min=${minsize_bytes}) -> ${out}"
}

# D) MySQL Database Size Analyzer (exclude system schemas, map owners)
mysql_usage_summary(){
  print_header "MySQL Database Size Summary (excluding system schemas)"
  local ts=$(DATE_ISO)
  local out="${ADV_DIR}/mysql_db_sizes_${ts}.json"
  write_json_array_start "${out}"

  # Build DB owner map from cPanel dbindex if available
  declare -A DB_OWNER_MAP
  if [ -f /var/cpanel/databases/dbindex.db ]; then
    while IFS=':' read -r user rest; do
      dbs=$(echo "$rest" | tr -d '[],"' | tr ' ' '\n')
      for db in $dbs; do
        [ -n "$db" ] && DB_OWNER_MAP["$db"]="$user"
      done
    done < /var/cpanel/databases/dbindex.db
  fi

  mysql -NBe "
    SELECT table_schema AS db,
           ROUND(SUM(data_length+index_length)/1024/1024,2) AS size_mb
    FROM information_schema.tables
    WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys')
    GROUP BY table_schema
    ORDER BY size_mb DESC;
  " 2>/dev/null | while read -r db size; do
    [ -z "$db" ] && continue
    size_bytes=$(awk -v mb="${size}" 'BEGIN{print int(mb*1024*1024)}')
    owner="${DB_OWNER_MAP[$db]:-}"
    if [ -z "$owner" ]; then owner="${db%%_*}"; fi
    escaped_db=$(printf '%s' "${db}" | sed 's|"|\\\"|g')
    printf "%-40s %10s MB (owner: %s)\n" "$db" "$size" "$owner"
    printf '{"database":"%s","size_bytes":%s,"size_human":"%s MB","owner":"%s"},\n' \
      "${escaped_db}" "${size_bytes}" "${size}" "${owner}" >> "${out}"
  done

  write_json_array_end "${out}"
  echo "MySQL JSON report: ${out}"
  log "mysql_usage_summary -> ${out}"
}

# E) Inode Hotspot Detector
inode_hotspots(){
  print_header "Directories with highest number of files (inode hotspots) under /home"
  local out="${ADV_DIR}/inode_hotspots_$(DATE_ISO).csv"
  echo "file_count,dir" > "${out}"
  find /home -type d -print0 2>/dev/null | xargs -0 -I{} bash -c '
    d="{}"
    cnt=$(find "$d" -maxdepth 1 -type f 2>/dev/null | wc -l)
    if [ "$cnt" -gt 0 ]; then printf "%s,%s\n" "$cnt" "$d"; fi
  ' | sort -t, -k1,1nr | head -n 20 | awk -F, '{printf "%3d | %s\n",$1,$2}' > "${out}.top"
  cat "${out}.top"
  mv "${out}.top" "${out}" 2>/dev/null || true
  echo "Report: ${out}"
  log "inode_hotspots -> ${out}"
}

# F) Smart Cleanup Suggestions
smart_cleanup_suggestions(){
  print_header "Smart Cleanup Suggestions (heuristics)"
  local ts=$(DATE_ISO)
  local out="${ADV_DIR}/cleanup_suggestions_${ts}.json"
  write_json_array_start "${out}"

  find /tmp -type f -mtime +7 -size +50M -print0 2>/dev/null | xargs -0 -I{} bash -c '
    p="{}"; s=$(stat -c %s "$p" 2>/dev/null || echo 0); mt=$(stat -c %TY-%Tm-%Td "$p" 2>/dev/null || echo "")
    printf "%s\t%s\t%s\n" "$p" "$s" "$mt"
  ' | while IFS=$'\t' read -r p s mt; do
    escaped=$(printf '%s' "${p}" | sed 's|"|\\\"|g')
    echo "  - ${p} ($(human_size ${s})) lastmod:${mt}"
    printf '{"action":"consider_delete","reason":"stale_tmp","path":"%s","size_bytes":%s},\n' "${escaped}" "${s}" >> "${out}"
  done

  find / -type f \( -iname "*.tar.gz" -o -iname "*.zip" -o -iname "*.tgz" -o -iname "*.sql" \) -mtime +30 -size +500M -print0 2>/dev/null | xargs -0 -I{} bash -c '
    p="{}"; s=$(stat -c %s "$p" 2>/dev/null || echo 0); mt=$(stat -c %TY-%Tm-%Td "$p" 2>/dev/null || echo "")
    printf "%s\t%s\t%s\n" "$p" "$s" "$mt"
  ' | while IFS=$'\t' read -r p s mt; do
    escaped=$(printf '%s' "${p}" | sed 's|"|\\\"|g')
    echo "  - ${p} ($(human_size ${s})) lastmod:${mt}"
    printf '{"action":"review_delete","reason":"old_large_backup","path":"%s","size_bytes":%s},\n' "${escaped}" "${s}" >> "${out}"
  done

  find / -type f \( -iname "*.log" -o -iname "error_log" \) -mtime +14 -size +200M -print0 2>/dev/null | xargs -0 -I{} bash -c '
    p="{}"; s=$(stat -c %s "$p" 2>/dev/null || echo 0); mt=$(stat -c %TY-%Tm-%Td "$p" 2>/dev/null || echo "")
    printf "%s\t%s\t%s\n" "$p" "$s" "$mt"
  ' | while IFS=$'\t' read -r p s mt; do
    escaped=$(printf '%s' "${p}" | sed 's|"|\\\"|g')
    echo "  - ${p} ($(human_size ${s})) lastmod:${mt} -> consider compressing"
    printf '{"action":"compress","reason":"old_large_log","path":"%s","size_bytes":%s},\n' "${escaped}" "${s}" >> "${out}"
  done

  write_json_array_end "${out}"
  echo "Cleanup suggestions JSON: ${out}"
  log "smart_cleanup_suggestions -> ${out}"
}

### ---------- Custom Directory Analyzer (Main Menu) ----------
custom_dir_analyzer(){
  local dir="${1:-.}"
  if [ ! -d "${dir}" ]; then echo "Not a directory: ${dir}"; return 1; fi
  pushd "${dir}" >/dev/null || return 1
  print_header "Custom Directory Analysis for $(pwd)"
  du -sk ./* ./.[^.]* 2>/dev/null | sort -nr | awk 'BEGIN{ pref[1]="K"; pref[2]="M"; pref[3]="G";} { total = total + $1; x = $1; y = 1; while( x > 1024 ) { x = (x + 1023)/1024; y++; } printf("%g%s\t%s\n",int(x*10)/10,pref[y],$2); } END { y = 1; while( total > 1024 ) { total = (total + 1023)/1024; y++; } printf("Total: %g%s\n",int(total*10)/10,pref[y]); }'
  ts=$(DATE_ISO)
  safe_name=$(printf '%s' "$(pwd)" | sed 's#/##g' | sed 's/[^A-Za-z0-9._-]/_/g')
  out="${ADV_DIR}/custom_dir_${safe_name}_${ts}.json"
  write_json_array_start "${out}"
  for p in ./* ./.[^.]*; do
    [ -e "$p" ] || continue
    if [ -f "$p" ]; then
      sz=$(stat -c %s "$p" 2>/dev/null || echo 0)
    else
      sz=$(du -sb "$p" 2>/dev/null | awk '{print $1}' || echo 0)
    fi
    escaped=$(printf '%s' "$(realpath "$p")" | sed 's|"|\\\"|g')
    printf '{"path":"%s","size_bytes":%s,"size_human":"%s"},\n' "${escaped}" "${sz}" "$(human_size ${sz})" >> "${out}"
  done
  write_json_array_end "${out}"
  echo "Saved JSON: ${out}"
  popd >/dev/null || true
  log "custom_dir_analyzer(${dir}) -> ${out}"
}

### ---------- Cleanup helpers ----------
compress_file(){
  local file="$1"
  if [ ! -f "${file}" ]; then echo "Not found: ${file}"; return 1; fi
  if confirm_action "Compress ${file} using gzip?"; then
    gzip -9 "${file}" && echo "Compressed: ${file}.gz" && log "Compressed ${file}"
  fi
}

delete_file(){
  local file="$1"
  if [ ! -f "${file}" ]; then echo "Not found: ${file}"; return 1; fi
  if confirm_action "Delete file ${file}? This is irreversible."; then
    rm -f "${file}" && echo "Deleted: ${file}" && log "Deleted ${file}"
  fi
}

### ---------- Main menu (Exit last) ----------
main_menu(){
  safe_init
  ensure_not_root
  while true; do
    echo ""
    echo -e "${CYAN}Disk Analyzer v6.1.1 - Main Menu${RESET}"
    echo " 1) /home Analysis (Top ${DEFAULT_TOP_N} directories)"
    echo " 2) /home Full Analysis (All directories)"
    echo " 3) Full System Disk Analysis (top directories under /)"
    echo " 4) Advanced Analysis (submenu)"
    echo " 5) Custom Directory Analysis (interactive)"
    echo " 6) Exit"
    read -rp "Choice [1-6]: " choice
    case "${choice}" in
      1) disk_analyze_path "/home" "${DEFAULT_TOP_N}" ;;
      2) disk_analyze_all "/home" ;;
      3) disk_analyze_system ;;
      4) advanced_menu ;;
      5)
         read -rp "Enter directory path (default current): " cdpath
         cdpath="${cdpath:-.}"
         custom_dir_analyzer "${cdpath}"
         ;;
      6) echo "Bye."; exit 0 ;;
      *) echo "Invalid option." ;;
    esac
  done
}

### ---------- Advanced menu ----------
advanced_menu(){
  while true; do
    echo ""
    echo -e "${CYAN}Advanced Disk Analysis Menu${RESET}"
    echo " 1) Find log files > 100MB (anywhere)"
    echo " 2) Find error_log > 100MB under /home"
    echo " 3) Find large backups (.tar.gz .zip .sql) > 100MB"
    echo " 4) Scan /tmp and /home/*/tmp for large/stale files"
    echo " 5) Top 50 biggest files on server"
    echo " 6) Inode usage summary"
    echo " 7) Mount summary (df -h)"
    echo " 8) Compress or delete from last report (interactive)"
    echo " 9) File type / extension summary (new)"
    echo "10) Compare growth between last two /home reports (new)"
    echo "11) Find duplicate large files (sha1) (new)"
    echo "12) MySQL DB size summary (terminal + JSON) (new)"
    echo "13) Inode hotspots under /home (new)"
    echo "14) Smart cleanup suggestions (new)"
    echo "15) Back to main menu"
    read -rp "Choice [1-15]: " ch
    case "${ch}" in
      1) read -rp "Minimum size in MB (default 100): " mb; mb="${mb:-100}"; find_large_logs $((mb*1024*1024)) ;;
      2) read -rp "Minimum size in MB (default 100): " mb; mb="${mb:-100}"; find_error_logs_home $((mb*1024*1024)) ;;
      3) read -rp "Minimum size in MB (default 100): " mb; mb="${mb:-100}"; find_large_backups $((mb*1024*1024)) ;;
      4) read -rp "Min size in MB (default 50): " mb; mb="${mb:-50}"; read -rp "Older than days (default 7): " d; d="${d:-7}"; scan_tmp_dirs $((mb*1024*1024)) "${d}" ;;
      5) read -rp "Top N files (default 50): " n; n="${n:-50}"; top_biggest_files "${n}" ;;
      6) inode_usage ;;
      7) mount_summary ;;
      8)
         echo "You will be prompted to provide a path from any recent report or enter a path manually."
         read -rp "Enter full filepath to compress/delete (or press Enter to choose from last report file): " fp
         if [ -z "${fp}" ]; then
           last="$(ls -1t ${ADV_DIR}/*.json 2>/dev/null | head -n1 || true)"
           if [ -z "${last}" ]; then echo "No recent report file found."; continue; fi
           echo "Most recent report: ${last}"
           echo "You can open it and pick a file path to act on."
           read -rp "Enter path to act on: " fp
           [ -z "${fp}" ] && echo "No path entered." && continue
         fi
         read -rp "Action: (c)ompress or (d)elete? " act
         case "${act}" in
           c|C) compress_file "${fp}" ;;
           d|D) delete_file "${fp}" ;;
           *) echo "Unknown action" ;;
         esac
         ;;
      9)
         read -rp "Path to analyze (default /home): " p; p="${p:-/home}"
         analyze_file_types "${p}"
         ;;
      10)
         compare_growth_reports
         ;;
      11)
         read -rp "Minimum file size to consider in MB (default 10): " ms; ms="${ms:-10}"
         find_duplicates $((ms*1024*1024))
         ;;
      12)
         echo "Running MySQL DB summary (requires mysql access)..."
         mysql_usage_summary
         ;;
      13)
         inode_hotspots
         ;;
      14)
         smart_cleanup_suggestions
         ;;
      15) break ;;
      *) echo "Invalid choice" ;;
    esac
  done
}

### ---------- CLI flags ----------
while [ "$#" -gt 0 ]; do
  case "$1" in
    --allow-root) ROOT_FLAG=1; shift ;;
    --yes-clean) YES_CLEAN=1; shift ;;
    --output-dir) OUTPUT_DIR_OVERRIDE="$2"; shift 2 ;;
    --help) echo "Usage: $0 [--allow-root] [--yes-clean] [--output-dir <dir>]"; exit 0 ;;
    *) shift ;;
  esac
done

# Start
main_menu
