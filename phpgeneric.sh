#!/bin/bash
# =========================================================
# PHP Generic WebApp Checker v1 (cPanel-safe)
# - Single-site mode (you provide the site path)
# - JSON diagnostic report only
# - Auto-clean old reports (>30 days)
# - Prevents running as root
# =========================================================

set -euo pipefail

# --- Prevent root execution (safety for cPanel shared hosting) ---
if [ "$(id -u)" -eq 0 ]; then
  echo "🚫 Error: This script must NOT be run as root or with sudo."
  echo "💡 Please run it as your cPanel user (e.g., via SSH login to your account)."
  exit 1
fi

echo "🔎 PHP Generic WebApp Checker v1"
echo "-------------------------------------------------"

# --- Inputs ---
read -p "📂 Enter full PHP app path (where index.php / wp-config.php / artisan may be): " SITE_DIR
read -p "👤 Enter cPanel username (web user): " WEB_USER

# --- Validate site path ---
if [ ! -d "$SITE_DIR" ]; then
  echo "❌ Directory not found: $SITE_DIR"
  exit 1
fi

cd "$SITE_DIR" || { echo "❌ Cannot cd to $SITE_DIR"; exit 1; }

# --- Basic detection (Laravel, WordPress, Drupal, Generic) ---
APP_TYPE="generic"
if [ -f "artisan" ]; then APP_TYPE="laravel"; fi
if [ -f "wp-config.php" ]; then APP_TYPE="wordpress"; fi
if [ -d "sites/default" ] && [ -f "index.php" ] && grep -q "Drupal" index.php 2>/dev/null; then APP_TYPE="drupal"; fi
if [ -f "index.php" ] && [ "$APP_TYPE" = "generic" ]; then APP_TYPE="generic-php"; fi

echo "✅ Detected app type: $APP_TYPE"

# --- Setup report dir & cleanup old reports (>30 days) ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT_DIR="$SCRIPT_DIR/diagnostics_logs"
mkdir -p "$REPORT_DIR"
find "$REPORT_DIR" -name "php_webapp_diagnostic_*.json" -type f -mtime +30 -exec rm -f {} \; 2>/dev/null || true
echo "🧹 Old diagnostic reports (>30 days) cleaned."

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
JSON_REPORT="$REPORT_DIR/php_webapp_diagnostic_${TIMESTAMP}.json"

# --- Backup config (prefer .env or wp-config.php) ---
CONFIG_BACKUP="none"
if [ -f ".env" ]; then
  CONFIG_BACKUP=".env.backup_${TIMESTAMP}"
  cp .env "$CONFIG_BACKUP" 2>/dev/null && echo "💾 .env backed up as $CONFIG_BACKUP" || CONFIG_BACKUP="backup_failed"
elif [ -f "wp-config.php" ]; then
  CONFIG_BACKUP="wp-config.backup_${TIMESTAMP}.php"
  cp wp-config.php "$CONFIG_BACKUP" 2>/dev/null && echo "💾 wp-config.php backed up as $CONFIG_BACKUP" || CONFIG_BACKUP="backup_failed"
fi

# --- PHP & environment info ---
PHP_CLI_VERSION=$(php -v 2>/dev/null | head -n1 | sed 's/"/\\"/g' || echo "php_cli_not_found")
PHP_SAPI=$(php -r 'echo PHP_SAPI;' 2>/dev/null || echo "unknown")
COMPOSER_PRESENT="no"
if command -v composer >/dev/null 2>&1; then COMPOSER_PRESENT="yes"; fi

# --- Composer/vendor checks ---
VENDOR_EXISTS="no"
if [ -d "vendor" ]; then VENDOR_EXISTS="yes"; fi
COMPOSER_JSON_EXISTS="no"
if [ -f "composer.json" ]; then COMPOSER_JSON_EXISTS="yes"; fi

# If composer present and vendor missing -> report recommendation (do NOT run composer install)
COMPOSER_NOTE=""
if [ "$COMPOSER_PRESENT" = "yes" ] && [ "$COMPOSER_JSON_EXISTS" = "yes" ] && [ "$VENDOR_EXISTS" = "no" ]; then
  COMPOSER_NOTE="composer.json present but vendor/ missing - consider running 'composer install' as the site user."
fi

# --- Writable / permission checks (common dirs) ---
WRITABLE_ISSUES=0
WRITABLE_LIST=""
# Laravel dirs
if [ -d "storage" ] || [ -d "bootstrap/cache" ]; then
  find storage bootstrap/cache -maxdepth 5 -type d ! -writable 2>/dev/null | while read -r d; do
    WRITABLE_ISSUES=$((WRITABLE_ISSUES+1))
    WRITABLE_LIST="${WRITABLE_LIST}${d}; "
  done
fi
# WordPress uploads
if [ -d "wp-content/uploads" ]; then
  find wp-content/uploads -maxdepth 5 -type d ! -writable 2>/dev/null | while read -r d; do
    WRITABLE_ISSUES=$((WRITABLE_ISSUES+1))
    WRITABLE_LIST="${WRITABLE_LIST}${d}; "
  done
fi
# generic: check public_html or current dir
find . -maxdepth 3 -type d ! -writable 2>/dev/null | head -n 1 >/dev/null && {
  # only add a couple of entries
  find . -maxdepth 3 -type d ! -writable 2>/dev/null | while read -r d; do
    WRITABLE_ISSUES=$((WRITABLE_ISSUES+1))
    WRITABLE_LIST="${WRITABLE_LIST}${d}; "
  done
}

# --- Ownership issues (root-owned files) ---
OWNERSHIP_ISSUES_COUNT=$(find . -maxdepth 3 \( -user root -o -group root \) 2>/dev/null | wc -l || echo 0)
OWNERSHIP_SAMPLE=$(find . -maxdepth 3 \( -user root -o -group root \) 2>/dev/null | sed ':a;N;$!ba;s/\n/; /g' || echo "")

# --- Logs: look for common names and tail samples ---
LOG_FILE="none"
LOG_SAMPLE=""
LOG_LINES=0
if [ -f "storage/logs/laravel.log" ]; then
  LOG_FILE="storage/logs/laravel.log"
elif [ -f "wp-content/debug.log" ]; then
  LOG_FILE="wp-content/debug.log"
elif [ -f "error_log" ]; then
  LOG_FILE="error_log"
elif [ -f "logs/error.log" ]; then
  LOG_FILE="logs/error.log"
elif [ -f "error.log" ]; then
  LOG_FILE="error.log"
fi

if [ "$LOG_FILE" != "none" ]; then
  LOG_LINES=$(tail -n 20 "$LOG_FILE" 2>/dev/null | wc -l || echo 0)
  LOG_SAMPLE=$(tail -n 20 "$LOG_FILE" 2>/dev/null | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g' || echo "")
fi

# --- Config cache checks (Laravel) ---
CONFIG_CACHE="not_applicable"
if [ -f "bootstrap/cache/config.php" ]; then CONFIG_CACHE="present"; fi

# --- .htaccess presence and suspicious rules check (basic) ---
HTACCESS="missing"
if [ -f ".htaccess" ]; then
  HTACCESS="present"
  # quick suspicious redirect check
  SUSPICIOUS_HTACCESS=$(grep -Ei "base64_decode|eval\(|preg_replace\(|redirect .*http" .htaccess 2>/dev/null || true)
else
  SUSPICIOUS_HTACCESS=""
fi

# --- Disk usage for site dir ---
DISK_USAGE=$(du -sh . 2>/dev/null | awk '{print $1}' || echo "unknown")

# --- Cron / scheduler check (Laravel scheduler, WP CRON disabled?) ---
SCHEDULER_CRON="unknown"
if crontab -l 2>/dev/null | grep -q "schedule:run"; then SCHEDULER_CRON="present"; else SCHEDULER_CRON="missing"; fi

# WordPress: check if wp-cron disabled in config (WP_INSTALL constant or DISABLE_WP_CRON)
WP_CRON_DISABLED="unknown"
if [ -f "wp-config.php" ]; then
  if grep -qi "DISABLE_WP_CRON" wp-config.php 2>/dev/null; then
    WP_CRON_DISABLED="defined"
  else
    WP_CRON_DISABLED="not_defined"
  fi
fi

# --- PHP-FPM / FastCGI process count for this user (best-effort) ---
PHP_FPM_PROCS=$(ps aux | grep -E "php-fpm|php-fpm: pool" | grep -v grep | wc -l || echo 0)

# --- Basic DB check for common apps (attempt, but do not require credentials) ---
DB_STATUS="unknown"
if [ -f "wp-config.php" ]; then
  # attempt to read DB constants from wp-config.php (best-effort & not secure)
  DB_RAW=$(php -r "require 'wp-config.php'; if(defined('DB_NAME')) echo 'have_db';" 2>/dev/null || echo "")
  DB_STATUS=$( [ "$DB_RAW" = "have_db" ] && echo "db_config_present" || echo "db_config_missing" )
elif [ -f "artisan" ]; then
  # check if .env exists with DB vars
  if [ -f ".env" ] && grep -E "DB_DATABASE|DB_HOST|DB_USERNAME" .env >/dev/null 2>&1; then
    DB_STATUS="env_db_config_present"
  else
    DB_STATUS="db_config_missing"
  fi
fi

# --- Security quick checks (simple heuristics) ---
SUSPICIOUS_PHP_COUNT=$(grep -R --include="*.php" -E "base64_decode|eval\(|gzinflate|preg_replace\(|str_rot13" . 2>/dev/null | wc -l || echo 0)

# --- Plugins / Modules summary for WordPress / Composer ---
WP_PLUGINS_COUNT="n/a"
if [ -f "wp-config.php" ]; then
  WP_PLUGINS_COUNT=$(ls -1 wp-content/plugins 2>/dev/null | wc -l || echo 0)
fi
COMPOSER_PACKAGES="n/a"
if [ "$COMPOSER_PRESENT" = "yes" ] && [ "$COMPOSER_JSON_EXISTS" = "yes" ]; then
  COMPOSER_PACKAGES=$(composer show --no-ansi --no-interaction 2>/dev/null | head -n 20 | sed 's/"/\\"/g' || echo "composer_list_failed")
fi

# --- Recent modified files (top 10) to spot changes ---
RECENT_MODIFIED=$(find . -type f -mtime -7 -printf "%T@ %p\n" 2>/dev/null | sort -nr | head -n 10 | awk '{ $1=""; sub(/^ +/,""); print }' | sed ':a;N;$!ba;s/\n/; /g' || echo "")

# --- Compose JSON report ---
cat <<EOF > "$JSON_REPORT"
{
  "timestamp": "$TIMESTAMP",
  "site_path": "$(echo "$SITE_DIR" | sed 's/"/\\"/g')",
  "web_user": "$(echo "$WEB_USER" | sed 's/"/\\"/g')",
  "app_type": "$APP_TYPE",
  "php_cli_version": "$PHP_CLI_VERSION",
  "php_sapi": "$PHP_SAPI",
  "composer_present": "$COMPOSER_PRESENT",
  "composer_json": "$COMPOSER_JSON_EXISTS",
  "vendor_present": "$VENDOR_EXISTS",
  "composer_note": "$(echo "$COMPOSER_NOTE" | sed 's/"/\\"/g')",
  "config_backup": "$CONFIG_BACKUP",
  "writable_issues_count": "$WRITABLE_ISSUES",
  "writable_issues_list": "$(echo "$WRITABLE_LIST" | sed 's/"/\\"/g')",
  "ownership_issues_count": "$OWNERSHIP_ISSUES_COUNT",
  "ownership_issues_sample": "$(echo "$OWNERSHIP_SAMPLE" | sed 's/"/\\"/g')",
  "log_file": "$LOG_FILE",
  "log_lines_sampled": "$LOG_LINES",
  "log_sample": "$LOG_SAMPLE",
  "config_cache": "$CONFIG_CACHE",
  "htaccess": "$HTACCESS",
  "suspicious_htaccess_snippet": "$(echo "$SUSPICIOUS_HTACCESS" | sed 's/"/\\"/g')",
  "disk_usage": "$DISK_USAGE",
  "scheduler_cron": "$SCHEDULER_CRON",
  "wp_cron_disabled": "$WP_CRON_DISABLED",
  "php_fpm_processes": "$PHP_FPM_PROCS",
  "db_config_status": "$DB_STATUS",
  "suspicious_php_findings": "$SUSPICIOUS_PHP_COUNT",
  "wp_plugins_count": "$WP_PLUGINS_COUNT",
  "composer_packages_sample": "$(echo "$COMPOSER_PACKAGES" | sed 's/"/\\"/g')",
  "recent_modified_files": "$(echo "$RECENT_MODIFIED" | sed 's/"/\\"/g')",
  "report_file": "$JSON_REPORT"
}
EOF

echo "🧾 Diagnostic JSON written to: $JSON_REPORT"
echo "-------------------------------------------------"
echo "✅ PHP WebApp check completed successfully."
echo "You can parse the JSON file for monitoring or further automation."
