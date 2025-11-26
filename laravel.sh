#!/bin/bash
# =========================================================
# Laravel Smart Maintenance & Troubleshooter v7
# ---------------------------------------------------------
# Works on both cPanel and Root/LEMP environments
# Features:
#   ✅ Auto-detect Laravel projects
#   ✅ .env backup
#   ✅ Cache clear + rebuild
#   ✅ Composer autoload optimize
#   ✅ Log cleanup + storage link fix
#   ✅ Permission fix
#   ✅ Smart Diagnostics (PHP, DB, Logs, Cron, Queues)
#   ✅ JSON Report Output
#   ✅ Auto-delete old JSON reports (>30 days)
# =========================================================

echo "🔧 Laravel Smart Maintenance & Troubleshooter v7"
echo "-------------------------------------------------"

# === Step 1: Ask for search path ===
read -p "📂 Enter parent directory to search for Laravel apps (e.g. /home/username or /var/www): " SEARCH_DIR

if [ ! -d "$SEARCH_DIR" ]; then
    echo "❌ Invalid directory: $SEARCH_DIR"
    exit 1
fi

# === Step 2: Search for Laravel apps ===
echo "🔍 Searching for Laravel projects..."
mapfile -t LARAVEL_APPS < <(find "$SEARCH_DIR" -type f -name "artisan" 2>/dev/null | sed 's|/artisan||')

if [ ${#LARAVEL_APPS[@]} -eq 0 ]; then
    echo "❌ No Laravel applications found under: $SEARCH_DIR"
    exit 1
fi

# === Step 3: Choose project ===
echo "✅ Found ${#LARAVEL_APPS[@]} Laravel project(s):"
for i in "${!LARAVEL_APPS[@]}"; do
    echo "  [$((i+1))] ${LARAVEL_APPS[$i]}"
done

read -p "➡️  Select the Laravel app number: " choice
APP_DIR="${LARAVEL_APPS[$((choice-1))]}"

if [ -z "$APP_DIR" ]; then
    echo "❌ Invalid choice. Exiting."
    exit 1
fi

echo "📁 Selected Laravel app: $APP_DIR"

# === Step 4: Ask for user ===
read -p "👤 Enter web user (e.g. www-data or your cPanel username): " WEB_USER

cd "$APP_DIR" || { echo "❌ Cannot access directory: $APP_DIR"; exit 1; }

# === Step 5: Validate Laravel structure ===
if [ ! -f "artisan" ] || [ ! -d "bootstrap" ] || [ ! -d "vendor" ]; then
    echo "❌ Not a valid Laravel app (missing artisan/bootstrap/vendor)."
    exit 1
fi

# === Step 6: Detect environment ===
if [ "$(id -u)" -eq 0 ]; then
    EXEC="sudo -u $WEB_USER"
else
    EXEC=""  # For cPanel user
fi

echo "🧭 Detected environment: $([ -z "$EXEC" ] && echo 'cPanel/shared hosting' || echo 'Root/LEMP stack')"
echo "-------------------------------------------------"

# === Step 7: Backup .env file ===
if [ -f ".env" ]; then
    BACKUP_NAME=".env.backup_$(date +%Y%m%d_%H%M%S)"
    cp .env "$BACKUP_NAME"
    echo "💾 .env file backed up as: $BACKUP_NAME"
else
    echo "⚠️ No .env file found — skipping backup."
fi

# === Step 8: Clear Laravel caches ===
echo "🧹 Clearing old caches..."
$EXEC php artisan cache:clear
$EXEC php artisan config:clear
$EXEC php artisan route:clear
$EXEC php artisan view:clear
$EXEC php artisan event:clear

# === Step 9: Optimize composer autoload ===
echo "⚙️ Optimizing Composer autoload..."
if [ -f "composer.json" ]; then
    $EXEC composer dump-autoload --optimize
else
    echo "⚠️ composer.json not found — skipping autoload optimization."
fi

# === Step 10: Rebuild caches ===
echo "⚡ Rebuilding Laravel caches..."
$EXEC php artisan config:cache
$EXEC php artisan route:cache
$EXEC php artisan view:cache
$EXEC php artisan event:cache

# === Step 11: Clean up large log files ===
if [ -f "storage/logs/laravel.log" ]; then
    LOG_SIZE=$(du -m "storage/logs/laravel.log" | cut -f1)
    if [ "$LOG_SIZE" -gt 10 ]; then
        echo "🧾 Clearing large Laravel log file (${LOG_SIZE}MB)..."
        : > storage/logs/laravel.log
    else
        echo "🧾 Log file size is small (${LOG_SIZE}MB) — skipping clear."
    fi
else
    echo "⚠️ No laravel.log file found."
fi

# === Step 12: Ensure storage link ===
if [ ! -L "public/storage" ]; then
    echo "🔗 Recreating storage link..."
    $EXEC php artisan storage:link || echo "⚠️ Failed to create storage link (might require manual fix)."
else
    echo "🔗 Storage link already exists."
fi

# === Step 13: Fix ownership and permissions ===
echo "🔐 Fixing permissions..."
if [ "$(id -u)" -eq 0 ]; then
    sudo chown -R $WEB_USER:$WEB_USER storage bootstrap/cache 2>/dev/null
fi
chmod -R 775 storage bootstrap/cache 2>/dev/null

# === Step 14: Diagnostics Section ===
echo ""
echo "🧩 Running Smart Diagnostics..."
echo "-------------------------------------------------"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT_DIR="$SCRIPT_DIR/diagnostics_logs"
mkdir -p "$REPORT_DIR"

# === Auto-delete old JSON reports (older than 30 days) ===
find "$REPORT_DIR" -name "diagnostic_*.json" -type f -mtime +30 -exec rm -f {} \; 2>/dev/null
echo "🧹 Old diagnostic reports (>30 days) cleaned."

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
JSON_REPORT="$REPORT_DIR/diagnostic_${TIMESTAMP}.json"

CLI_PHP_VERSION=$(php -r "echo PHP_VERSION;")
WRITABLE_ISSUES=$(find storage bootstrap/cache ! -writable 2>/dev/null | wc -l)
DB_STATUS=$($EXEC php artisan tinker --execute="DB::connection()->getPdo(); echo 'OK';" 2>/dev/null)
[ -z "$DB_STATUS" ] && DB_STATUS="Failed"

CRON_STATUS=$(crontab -l 2>/dev/null | grep "schedule:run" >/dev/null && echo "OK" || echo "Missing")
QUEUE_STATUS=$(ps aux | grep "queue:work" | grep -v grep >/dev/null && echo "Running" || echo "Stopped")

ERROR_LINES=$(tail -n 15 storage/logs/laravel.log 2>/dev/null | grep -E "Error|Exception|PDO|Denied" | wc -l)
DISK_USAGE=$(du -sh storage 2>/dev/null | awk '{print $1}')
CONFIG_CACHE=$( [ -f "bootstrap/cache/config.php" ] && echo "Present" || echo "Missing")

cat <<EOF > "$JSON_REPORT"
{
  "timestamp": "$TIMESTAMP",
  "app_path": "$APP_DIR",
  "web_user": "$WEB_USER",
  "php_version": "$CLI_PHP_VERSION",
  "db_connection": "$DB_STATUS",
  "writable_issues": "$WRITABLE_ISSUES",
  "cron_job": "$CRON_STATUS",
  "queue_worker": "$QUEUE_STATUS",
  "recent_errors": "$ERROR_LINES",
  "disk_usage_storage": "$DISK_USAGE",
  "config_cache": "$CONFIG_CACHE"
}
EOF

echo "🧾 Diagnostic report saved:"
echo "   JSON: $JSON_REPORT"

echo "-------------------------------------------------"
echo "✅ Laravel maintenance and diagnostics completed successfully!"
echo "📂 App path: $APP_DIR"
echo "👤 Executed as: $WEB_USER"
echo "✨ All done!"
