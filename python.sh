#!/bin/bash
# =========================================================
# Python App Checker v1.1 (cPanel + CloudLinux)
# - Single-site diagnostics
# - JSON report only
# - Auto-clean old reports
# - NOW includes root-user protection
# =========================================================

set -euo pipefail

# --- Prevent root execution (safety for cPanel shared hosting) ---
if [ "$(id -u)" -eq 0 ]; then
  echo "🚫 Error: This script must NOT be run as root or with sudo."
  echo "💡 Please run it as your cPanel user (e.g., via SSH login to your account)."
  exit 1
fi

echo "🔧 Python App Checker v1.1 (Safe Mode)"
echo "-------------------------------------------------"

# --- Inputs ---
read -p "📂 Enter full Python app path (where manage.py / app.py / package is): " APP_DIR
read -p "👤 Enter your cPanel username: " WEB_USER

# --- Validate path ---
if [ ! -d "$APP_DIR" ]; then
  echo "❌ Directory not found: $APP_DIR"
  exit 1
fi

cd "$APP_DIR" || { echo "❌ Cannot cd to $APP_DIR"; exit 1; }

# --- Detect Python app structure ---
PY_DETECTED=false
if [ -f "manage.py" ] || [ -f "app.py" ] || [ -f "wsgi.py" ] || [ -f "main.py" ] || [ -f "requirements.txt" ] || [ -f "pyproject.toml" ]; then
  PY_DETECTED=true
fi

if ! $PY_DETECTED ; then
  echo "❌ No Python app detected (missing manage.py/app.py/wsgi.py/etc)."
  exit 1
fi

echo "✅ Python app detected at: $APP_DIR"

# --- Setup report dir & cleanup old reports (>30 days) ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT_DIR="$SCRIPT_DIR/diagnostics_logs"
mkdir -p "$REPORT_DIR"
find "$REPORT_DIR" -name "python_diagnostic_*.json" -type f -mtime +30 -exec rm -f {} \; 2>/dev/null || true
echo "🧹 Old diagnostic reports (>30 days) cleaned."

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
JSON_REPORT="$REPORT_DIR/python_diagnostic_${TIMESTAMP}.json"

# --- Backup .env if exists ---
ENV_BACKUP="none"
if [ -f ".env" ]; then
  ENV_BACKUP=".env.backup_${TIMESTAMP}"
  cp .env "$ENV_BACKUP" && echo "💾 .env backed up as $ENV_BACKUP" || ENV_BACKUP="backup_failed"
fi

# --- Detect virtualenv ---
VENV_PATH=""
for v in ".venv" "venv" "env" ".env" "venv3"; do
  if [ -x "$v/bin/python" ]; then
    VENV_PATH="$v"
    break
  fi
done

# --- Helper to run python/pip ---
run_python() {
  if [ -n "$VENV_PATH" ]; then
    "$VENV_PATH/bin/python" -c "$1"
  else
    python3 -c "$1"
  fi
}
run_pip() {
  if [ -n "$VENV_PATH" ]; then
    "$VENV_PATH/bin/pip" "$@"
  else
    pip3 "$@"
  fi
}

# --- Versions ---
PYTHON_VERSION=$(run_python 'import sys; print(sys.version.split()[0])' 2>/dev/null || echo "unknown")
PIP_VERSION=$(run_pip --version 2>/dev/null | awk '{print $2}' || echo "unknown")

# --- Detect framework ---
FRAMEWORK="unknown"
if [ -f "manage.py" ]; then FRAMEWORK="django"; fi
if grep -R "Flask" -m1 . 2>/dev/null >/dev/null; then FRAMEWORK="flask"; fi
if grep -R "FastAPI" -m1 . 2>/dev/null >/dev/null; then FRAMEWORK="fastapi"; fi
if [ -f "wsgi.py" ]; then FRAMEWORK="wsgi"; fi

# --- Dependency check ---
PIP_CHECK=$(run_pip check 2>&1 || true)
if echo "$PIP_CHECK" | grep -qi "No broken"; then
  DEP_STATUS="OK"
else
  DEP_STATUS="Issues"
fi

# --- Running processes ---
PROCESS_COUNT=$(ps aux | grep python | grep "$APP_DIR" | grep -v grep | wc -l || echo 0)
PROCESS_SAMPLE=$(ps aux | grep python | grep "$APP_DIR" | grep -v grep | head -n 10 | sed ':a;N;$!ba;s/\n/\\n/g')

# --- Resource usage ---
MEMORY_MB=$(ps aux | grep python | grep "$APP_DIR" | grep -v grep | awk '{sum+=$6} END {print sum/1024}' || echo 0)
CPU_PCT=$(ps aux | grep python | grep "$APP_DIR" | grep -v grep | awk '{sum+=$3} END {print sum"%"}' || echo 0)

# --- Disk usage ---
DISK_USAGE=$(du -sh . 2>/dev/null | awk '{print $1}' || echo 0)

# --- Logs ---
LOG_FILE="none"
LOG_SAMPLE=""
for f in error.log logs/error.log gunicorn.log uwsgi.log app.log; do
  if [ -f "$f" ]; then
    LOG_FILE="$f"
    LOG_SAMPLE=$(tail -n 10 "$f" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')
    break
  fi
done

# --- JSON Report ---
cat <<EOF > "$JSON_REPORT"
{
  "timestamp": "$TIMESTAMP",
  "app_path": "$APP_DIR",
  "web_user": "$WEB_USER",
  "python_version": "$PYTHON_VERSION",
  "pip_version": "$PIP_VERSION",
  "framework": "$FRAMEWORK",
  "virtualenv_path": "$VENV_PATH",
  "dependency_status": "$DEP_STATUS",
  "process_count": "$PROCESS_COUNT",
  "process_sample": "$PROCESS_SAMPLE",
  "memory_usage_mb": "$MEMORY_MB",
  "cpu_usage_pct": "$CPU_PCT",
  "disk_usage": "$DISK_USAGE",
  "log_file": "$LOG_FILE",
  "log_sample": "$LOG_SAMPLE",
  "env_backup": "$ENV_BACKUP",
  "report_file": "$JSON_REPORT"
}
EOF

echo "🧾 JSON diagnostic report saved at:"
echo "   $JSON_REPORT"
echo "-------------------------------------------------"
echo "✅ Python App Check completed successfully."
