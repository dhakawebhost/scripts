#!/bin/bash
# =========================================================
# Node.js Smart Troubleshooter v1.1 (cPanel + CloudLinux)
# ---------------------------------------------------------
# Features:
#   ✅ Root-execution protection
#   ✅ Detect Node.js app
#   ✅ .env backup
#   ✅ Check Node/NPM versions
#   ✅ Verify dependencies
#   ✅ Detect running processes (Passenger/PM2/Node)
#   ✅ Check ports, CPU, memory, disk
#   ✅ JSON report output
#   ✅ Auto-delete old reports (>30 days)
# =========================================================

set -euo pipefail

# === Prevent running as root ===
if [ "$(id -u)" -eq 0 ]; then
  echo "🚫 Error: This script must NOT be run as root or with sudo."
  echo "💡 Please log in as your cPanel user (e.g., via SSH or terminal in cPanel)."
  exit 1
fi

echo "🔧 Node.js Smart Troubleshooter v1.1 (Safe Mode)"
echo "------------------------------------------------------"

# === Inputs ===
read -p "📂 Enter full Node.js app path (where package.json is): " APP_DIR
read -p "👤 Enter your cPanel username: " WEB_USER

# === Validate directory ===
if [ ! -d "$APP_DIR" ]; then
  echo "❌ Directory not found: $APP_DIR"
  exit 1
fi

cd "$APP_DIR" || { echo "❌ Cannot access: $APP_DIR"; exit 1; }

if [ ! -f "package.json" ]; then
  echo "❌ Not a Node.js app (package.json missing) in: $APP_DIR"
  exit 1
fi

echo "✅ Node.js app detected in: $APP_DIR"

# === Setup report directory ===
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT_DIR="$SCRIPT_DIR/diagnostics_logs"
mkdir -p "$REPORT_DIR"

# === Auto-delete old JSON reports (>30 days) ===
find "$REPORT_DIR" -name "node_diagnostic_*.json" -type f -mtime +30 -exec rm -f {} \; 2>/dev/null
echo "🧹 Old diagnostic reports (>30 days) cleaned."

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
JSON_REPORT="$REPORT_DIR/node_diagnostic_${TIMESTAMP}.json"

# === Step 1: Backup .env ===
if [ -f ".env" ]; then
  ENV_BACKUP=".env.backup_${TIMESTAMP}"
  cp .env "$ENV_BACKUP"
  echo "💾 .env backed up as $ENV_BACKUP"
else
  ENV_BACKUP="none"
  echo "⚠️ No .env file found — skipping backup."
fi

# === Step 2: Environment checks ===
NODE_VERSION=$(node -v 2>/dev/null || echo "not_installed")
NPM_VERSION=$(npm -v 2>/dev/null || echo "not_installed")

# === Step 3: Dependency check ===
MISSING_MODULES=$(npm ls --depth=0 2>&1 | grep "missing" || true)
if [ -z "$MISSING_MODULES" ]; then
  DEP_STATUS="OK"
else
  DEP_STATUS="Missing modules detected"
fi

# === Step 4: Detect start file ===
START_FILE="unknown"
if [ -f "server.js" ]; then
  START_FILE="server.js"
elif [ -f "app.js" ]; then
  START_FILE="app.js"
else
  START_FILE=$(jq -r '.main // empty' package.json 2>/dev/null || echo "unknown")
fi

# === Step 5: Detect running processes ===
PM2_STATUS="not_found"
PASSENGER_STATUS="not_detected"
NODE_PROCS=$(ps aux | grep node | grep "$APP_DIR" | grep -v grep || true)

if echo "$NODE_PROCS" | grep -q "pm2"; then
  PM2_STATUS="running"
elif echo "$NODE_PROCS" | grep -q "Passenger"; then
  PASSENGER_STATUS="running"
elif [ -n "$NODE_PROCS" ]; then
  PM2_STATUS="node_process_active"
fi

# === Step 6: Port usage ===
PORTS_USED=$(ss -tuln 2>/dev/null | awk '/LISTEN/ {print $5}' | sed 's/.*://g' | sort -u | tr '\n' ',' | sed 's/,$//')
[ -z "$PORTS_USED" ] && PORTS_USED="none"

# === Step 7: Resource usage ===
MEM_USAGE=$(ps -u "$USER" -o rss,comm | grep node | awk '{sum+=$1} END {print sum/1024 " MB"}' || echo "0")
CPU_USAGE=$(ps -u "$USER" -o %cpu,comm | grep node | awk '{sum+=$1} END {print sum "%"}' || echo "0")

# === Step 8: Disk usage ===
DISK_USAGE=$(du -sh . 2>/dev/null | awk '{print $1}')

# === Step 9: Passenger config check ===
PASSENGER_FILE="absent"
if [ -f ".htaccess" ] && grep -q "PassengerAppRoot" .htaccess; then
  PASSENGER_FILE="present"
fi

# === Step 10: Logs ===
LOG_ERRORS="0"
LOG_SAMPLE=""
LOG_FILE="none"
for candidate in "error.log" "logs/error.log" "logs/app.log"; do
  if [ -f "$candidate" ]; then
    LOG_FILE="$candidate"
    LOG_ERRORS=$(tail -n 15 "$candidate" 2>/dev/null | wc -l)
    LOG_SAMPLE=$(tail -n 15 "$candidate" 2>/dev/null | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')
    break
  fi
done

# === Step 11: JSON Report ===
cat <<EOF > "$JSON_REPORT"
{
  "timestamp": "$TIMESTAMP",
  "app_path": "$APP_DIR",
  "web_user": "$WEB_USER",
  "node_version": "$NODE_VERSION",
  "npm_version": "$NPM_VERSION",
  "start_file": "$START_FILE",
  "dependencies": "$DEP_STATUS",
  "missing_modules_output": "$(echo "$MISSING_MODULES" | sed 's/"/\\"/g')",
  "passenger_htaccess": "$PASSENGER_FILE",
  "pm2_status": "$PM2_STATUS",
  "passenger_status": "$PASSENGER_STATUS",
  "memory_usage": "$MEM_USAGE",
  "cpu_usage": "$CPU_USAGE",
  "disk_usage": "$DISK_USAGE",
  "ports_in_use": "$PORTS_USED",
  "error_log_file": "$LOG_FILE",
  "error_log_count": "$LOG_ERRORS",
  "error_log_sample": "$LOG_SAMPLE",
  "env_backup": "$ENV_BACKUP",
  "report_file": "$JSON_REPORT"
}
EOF

echo "🧾 JSON diagnostic report saved to:"
echo "   $JSON_REPORT"
echo "------------------------------------------------------"
echo "✅ Node.js troubleshooting completed successfully."
echo "✨ Done!"
