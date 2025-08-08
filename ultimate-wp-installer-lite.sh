#!/usr/bin/env bash
# ==============================================================================
# WOO v13 — WordPress Ultimate Operations (Self-Installing)
# Target: Ubuntu 22.04/24.04 LTS
# Design: Run-once bootstrap; afterwards `woo` only launches the menu.
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# --------------------------- Colors & Logging ---------------------------------
readonly RED='\033[0;31m'; readonly GREEN='\033[0;32m'; readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'; readonly NC='\033[0m'
readonly LOG_DIR="/var/log/woo-toolkit"
readonly LOG_FILE="${LOG_DIR}/woo-run-$(date +%Y%m%d_%H%M%S).log"

_log() {
  local msg="${1:-}"
  sudo mkdir -p "$LOG_DIR" >/dev/null 2>&1 || true
  sudo touch "$LOG_FILE" >/dev/null 2>&1 || true
  echo "[$(date '+%F %T')] $msg" | sudo tee -a "$LOG_FILE" >/dev/null || true
}
log()     { echo -e "${BLUE}[$(date '+%F %T')]${NC} $1"; _log "$1"; }
success() { echo -e "${GREEN}✓${NC} $1"; _log "OK: $1"; }
warn()    { echo -e "${YELLOW}‼${NC} $1"; _log "WARN: $1"; }
fail()    { echo -e "${RED}✗${NC} $1"; _log "ERR: $1"; exit 1; }

# ------------------------------ Globals ---------------------------------------
readonly PHP_VERSION="${PHP_VERSION:-8.2}"
readonly WEBROOT="${WEBROOT:-/var/www}"
readonly MIN_RAM=2048          # MB
readonly F2B_MAXRETRY=5
readonly F2B_BANTIME="1d"
readonly INSTALL_DIR="/opt/woo"
readonly TARGET_SCRIPT="${INSTALL_DIR}/woo.sh"
readonly CONFIG_DIR="$HOME/.woo-toolkit"
readonly BACKUP_CONFIG_FILE="$CONFIG_DIR/backup.conf"
readonly XMLRPC_WHITELIST_FILE="/etc/nginx/conf.d/xmlrpc_whitelist.conf"
declare -A SITE_DATA=()

# --------------------------- MySQL Safe Wrappers ------------------------------
mysql_exec() {
  local q="${1:-}"
  if [[ -f "$HOME/.my.cnf" ]]; then
    mysql --defaults-file="$HOME/.my.cnf" -e "$q"
  else
    sudo mysql -e "$q"
  fi
}
mysqldump_pipe_restore() {
  local src="${1:-}" dst="${2:-}"
  [[ -n "$src" && -n "$dst" ]] || return 1
  if [[ -f "$HOME/.my.cnf" ]]; then
    mysqldump --defaults-file="$HOME/.my.cnf" "$src" | mysql --defaults-file="$HOME/.my.cnf" "$dst"
  else
    sudo mysqldump "$src" | sudo mysql "$dst"
  fi
}

# ------------------------------ Error Handler ---------------------------------
error_handler() {
  local line="${1:-?}" cmd="${2:-?}" status="${3:-$?}"
  log "Critical error at line $line: $cmd (exit $status). Starting rollback..."

  set +e
  if [[ -n "${SITE_DATA[DB_NAME]:-}" ]]; then
    log "Dropping DB: ${SITE_DATA[DB_NAME]}"
    mysql_exec "DROP DATABASE IF EXISTS \`${SITE_DATA[DB_NAME]}\`;"
  fi
  if [[ -n "${SITE_DATA[DB_USER]:-}" ]]; then
    log "Dropping DB user: ${SITE_DATA[DB_USER]}"
    mysql_exec "DROP USER IF EXISTS '${SITE_DATA[DB_USER]}'@'localhost'; FLUSH PRIVILEGES;"
  fi
  if [[ -n "${SITE_DATA[SITE_DIR]:-}" ]]; then
    log "Removing site dir: ${SITE_DATA[SITE_DIR]}"
    sudo rm -rf "${SITE_DATA[SITE_DIR]}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${SITE_DATA[DOMAIN]:-}" ]]; then
    log "Removing Nginx/PHP config for ${SITE_DATA[DOMAIN]}"
    sudo rm -f "/etc/nginx/sites-available/${SITE_DATA[DOMAIN]}" "/etc/nginx/sites-enabled/${SITE_DATA[DOMAIN]}" >/dev/null 2>&1 || true
    sudo rm -f "/etc/php/${PHP_VERSION}/fpm/pool.d/${SITE_DATA[DOMAIN]}.conf" >/dev/null 2>&1 || true
  fi

  sudo systemctl restart nginx >/dev/null 2>&1 || true
  sudo systemctl restart mariadb >/dev/null 2>&1 || true
  sudo systemctl restart "php${PHP_VERSION}-fpm" >/dev/null 2>&1 || true
  fail "Installation failed and rollback completed. See log: $LOG_FILE"
}
trap 'error_handler "$LINENO" "$BASH_COMMAND" "$?"' ERR

# ---------------------------- Preconditions -----------------------------------
require_sudo() {
  if [[ "$(id -u)" -eq 0 ]]; then
    warn "Running as root; continuing, but recommended to use 'ubuntu' with sudo."
  else
    sudo -n true 2>/dev/null || { log "Sudo required. Prompting..."; sudo -v || fail "Sudo not available."; }
  fi
}
check_os() {
  [[ -f /etc/os-release ]] || fail "Unsupported OS."
  . /etc/os-release
  dpkg --compare-versions "${VERSION_ID}" lt "22.04" && warn "Ubuntu ${VERSION_ID} < 22.04. Proceeding, but only 22.04+ is tested."
  success "Ubuntu ${VERSION_ID} detected."
}
ensure_swap_if_low_ram() {
  local ram_mb; ram_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
  if (( ram_mb < MIN_RAM )); then
    if ! sudo swapon --show | grep -q '^/swapfile'; then
      warn "Low RAM (${ram_mb}MB). Creating 2G swap..."
      sudo fallocate -l 2G /swapfile 2>/dev/null || sudo dd if=/dev/zero of=/swapfile bs=1M count=2048
      sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
      grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
      success "Swap created."
    else
      success "Swap already present."
    fi
  else
    success "Sufficient RAM (${ram_mb}MB)."
  fi
}

# ------------------------- Self-Install (permanent woo) -----------------------
self_install() {
  sudo mkdir -p "$INSTALL_DIR"
  if ! sudo cmp -s <(cat "$0") "$TARGET_SCRIPT" 2>/dev/null; then
    cat "$0" | sudo tee "$TARGET_SCRIPT" >/dev/null
    sudo chmod +x "$TARGET_SCRIPT"
    success "Installed/updated core script at ${TARGET_SCRIPT}"
  else
    success "Core script already up-to-date at ${TARGET_SCRIPT}"
  fi

  if [[ ! -f /usr/local/bin/woo ]] || ! grep -q "/opt/woo/woo.sh menu" /usr/local/bin/woo; then
    sudo tee /usr/local/bin/woo >/dev/null <<'EOF'
#!/usr/bin/env bash
exec bash /opt/woo/woo.sh menu
EOF
    sudo chmod +x /usr/local/bin/woo
    success "System-wide 'woo' command installed."
  else
    success "'woo' launcher already present."
  fi
}

# ------------------------------ Nginx helpers ---------------------------------
configure_nginx_includes() {
  if ! grep -q 'include /etc/nginx/conf.d/\*\.conf;' /etc/nginx/nginx.conf; then
    sudo sed -i '/http {/a \    include /etc/nginx/conf.d/*.conf;' /etc/nginx/nginx.conf
  fi

  sudo tee /etc/nginx/sites-available/default >/dev/null <<'EOF'
server {
  listen 80 default_server;
  listen [::]:80 default_server;
  server_name _;
  root /var/www/html;
  return 444;
}
EOF
  [[ -L /etc/nginx/sites-enabled/default ]] || sudo ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
  sudo nginx -t && sudo systemctl reload nginx || true
}

ensure_nginx_cache_zone() {
  local zfile="/etc/nginx/conf.d/woo-cache.conf"
  if ! grep -qs "keys_zone=WORDPRESS" "$zfile" 2>/dev/null; then
    sudo tee "$zfile" >/dev/null <<'EOF'
# Global cache zone for WordPress (http context)
fastcgi_cache_path /var/run/nginx-cache levels=1:2 keys_zone=WORDPRESS:100m inactive=60m use_temp_path=off;
EOF
    sudo nginx -t && sudo systemctl reload nginx || warn "Nginx reload failed after adding cache zone."
  fi
}

# ------------------------------ Bootstrap -------------------------------------
add_ppa_once() {
  local ppa="$1"
  if ! grep -Rq "^deb .*$ppa" /etc/apt/sources.list.d /etc/apt/sources.list 2>/dev/null; then
    sudo add-apt-repository -y "ppa:$ppa" || true
  fi
}
install_dependencies() {
  log "Installing core packages..."
  sudo apt-get update -y
  sudo apt-get install -y software-properties-common curl wget unzip git rsync psmisc dnsutils gnupg ca-certificates ufw || true

  add_ppa_once "ondrej/php"
  add_ppa_once "ondrej/nginx"
  sudo apt-get update -y

  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    nginx mariadb-server redis-server fail2ban certbot python3-certbot-nginx postfix unattended-upgrades haveged \
    "php${PHP_VERSION}-fpm" "php${PHP_VERSION}-mysql" "php${PHP_VERSION}-curl" "php${PHP_VERSION}-mbstring" \
    "php${PHP_VERSION}-xml" "php${PHP_VERSION}-zip" "php${PHP_VERSION}-gd" "php${PHP_VERSION}-opcache" \
    "php${PHP_VERSION}-redis" "php${PHP_VERSION}-imagick" "php${PHP_VERSION}-bcmath"

  if ! command -v wp >/dev/null 2>&1; then
    log "Installing WP-CLI..."
    curl -fsSL -o /tmp/wp-cli.phar https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
    chmod +x /tmp/wp-cli.phar && sudo mv /tmp/wp-cli.phar /usr/local/bin/wp
  fi

  echo 'APT::Periodic::Update-Package-Lists "1";' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades >/dev/null
  echo 'APT::Periodic::Unattended-Upgrade "1";' | sudo tee -a /etc/apt/apt.conf.d/20auto-upgrades >/dev/null

  success "Dependencies installed."
}

configure_tuned_mariadb() {
  log "Tuning MariaDB..."
  local total_ram_kb; total_ram_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
  local ibp=$(( total_ram_kb / 4 ))
  (( ibp > 4194304 )) && ibp=4194304
  sudo tee /etc/mysql/mariadb.conf.d/99-woo-tuned.cnf >/dev/null <<EOF
[mysqld]
innodb_buffer_pool_size = ${ibp}K
innodb_log_file_size = 256M
innodb_file_per_table = 1
max_allowed_packet = 256M
EOF
  sudo systemctl restart mariadb
  success "MariaDB tuned."
}

secure_mysql() {
  log "Securing MariaDB..."
  if [[ -f "$HOME/.my.cnf" ]]; then success "MariaDB already secured."; return; fi
  if sudo mysql -e "SELECT 1" >/dev/null 2>&1; then
    local db_root_pass; db_root_pass="$(openssl rand -base64 32)"
    sudo mysql <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '${db_root_pass}';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');
DROP DATABASE IF EXISTS test;
FLUSH PRIVILEGES;
EOF
    printf "[client]\nuser=root\npassword=%s\n" "$db_root_pass" > "$HOME/.my.cnf"
    chmod 600 "$HOME/.my.cnf"
    success "MariaDB secured; credentials written to ~/.my.cnf"
  else
    warn "Could not connect to MariaDB via socket; assuming already secured."
  fi
}

harden_server() {
  log "Hardening server..."
  if ! sudo ufw status | grep -q "Status: active"; then
    sudo ufw default deny incoming || true
    sudo ufw default allow outgoing || true
    sudo ufw allow OpenSSH || true
    sudo ufw allow 'Nginx Full' || true
    echo "y" | sudo ufw enable || true
  fi

  sudo tee /etc/fail2ban/jail.d/wordpress.conf >/dev/null <<EOF
[sshd]
enabled = true
maxretry = 3
bantime = ${F2B_BANTIME}

[wordpress-hard]
enabled  = true
filter   = wordpress-hard
logpath  = /var/log/nginx/*access.log
maxretry = ${F2B_MAXRETRY}
bantime  = ${F2B_BANTIME}
port     = http,https
EOF

  sudo tee /etc/fail2ban/filter.d/wordpress-hard.conf >/dev/null <<'EOF'
[Definition]
failregex = ^<HOST> - - \[.*\] "POST /wp-login\.php
            ^<HOST> - - \[.*\] "GET /wp-login\.php
            ^<HOST> - - \[.*\] "POST /xmlrpc\.php
ignoreregex =
EOF
  sudo systemctl restart fail2ban || true

  sudo sed -i -E 's@^;?\s*expose_php\s*=\s*On@expose_php = Off@' "/etc/php/${PHP_VERSION}/fpm/php.ini" || true
  sudo sed -i -E 's@^;?\s*cgi\.fix_pathinfo\s*=\s*1@cgi.fix_pathinfo=0@' "/etc/php/${PHP_VERSION}/fpm/php.ini" || true
  sudo systemctl restart "php${PHP_VERSION}-fpm" || true

  if [[ ! -f "$XMLRPC_WHITELIST_FILE" ]]; then
    sudo tee "$XMLRPC_WHITELIST_FILE" >/dev/null <<'EOF'
# Managed by WOO Toolkit
geo $xmlrpc_allowed {
    default 0;
    # Add IPs below as: 1.2.3.4 1;
}
EOF
  fi
  sudo nginx -t && sudo systemctl reload nginx || true

  success "Hardening applied."
}

setup_alias() {
  local usr_rc="$HOME/.bashrc"
  grep -q "alias woo=" "$usr_rc" 2>/dev/null || echo "alias woo='bash ${TARGET_SCRIPT}'" >> "$usr_rc"
  if sudo test -f /root/.bashrc; then
    sudo grep -q "alias woo=" /root/.bashrc 2>/dev/null || echo "alias woo='bash ${TARGET_SCRIPT}'" | sudo tee -a /root/.bashrc >/dev/null
  fi
}

# --------------------------- Site Operations ----------------------------------
create_php_pool() {
  local domain="$1"
  sudo tee "/etc/php/${PHP_VERSION}/fpm/pool.d/${domain}.conf" >/dev/null <<EOF
[${domain}]
user = www-data
group = www-data
listen = /run/php/php${PHP_VERSION}-${domain}.sock
listen.owner = www-data
listen.group = www-data
pm = ondemand
pm.max_children = 50
pm.process_idle_timeout = 10s
pm.max_requests = 500
slowlog = /var/log/php-fpm/${domain}-slow.log
php_admin_value[error_log] = /var/log/php-fpm/${domain}-error.log
php_admin_flag[log_errors] = on
php_value[session.save_handler] = redis
php_value[session.save_path] = "tcp://127.0.0.1:6379"
EOF
  sudo mkdir -p /var/log/php-fpm
  sudo touch "/var/log/php-fpm/${domain}-error.log" "/var/log/php-fpm/${domain}-slow.log"
  sudo chown -R www-data:www-data /var/log/php-fpm || true
  sudo systemctl restart "php${PHP_VERSION}-fpm"
}

configure_nginx_site() {
  local domain="$1" enable_cache="${2:-false}"
  local config_file="/etc/nginx/sites-available/${domain}"

  # Ensure global cache zone exists when enabling cache
  if [[ "$enable_cache" == "true" ]]; then ensure_nginx_cache_zone; fi

  local cache_config=""
  if [[ "$enable_cache" == "true" ]]; then
    cache_config=$(cat <<'EOF'
set $skip_cache 0;
if ($request_method = POST) { set $skip_cache 1; }
if ($query_string != "") { set $skip_cache 1; }
if ($request_uri ~* "/wp-admin/|/xmlrpc.php|wp-.*.php|/feed/|index.php|sitemap(_index)?.xml") { set $skip_cache 1; }
if ($http_cookie ~* "comment_author|wordpress_logged_in|wp-postpass") { set $skip_cache 1; }

# Use the global cache zone "WORDPRESS" defined in /etc/nginx/conf.d/woo-cache.conf
fastcgi_cache_key "$scheme$request_method$host$request_uri";
fastcgi_cache_use_stale error timeout invalid_header http_500;
fastcgi_ignore_headers Cache-Control Expires Set-Cookie;
fastcgi_cache WORDPRESS;
fastcgi_cache_valid 200 60m;
fastcgi_cache_bypass $skip_cache;
fastcgi_no_cache $skip_cache;
EOF
)
  fi

  local multisite_rules=""
  if sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp core is-installed --network --path="${WEBROOT}/${domain}" >/dev/null 2>&1; then
    if sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp config get SUBDOMAIN_INSTALL --path="${WEBROOT}/${domain}" --quiet >/dev/null 2>&1; then
      multisite_rules=$(cat <<'EOF'
if (!-e $request_filename) {
    rewrite /wp-admin$ $scheme://$host$uri/ permanent;
    rewrite ^/([_0-9a-zA-Z-]+/)?(wp-(content|admin|includes).*) /$2 last;
    rewrite ^/([_0-9a-zA-Z-]+/)?(.*\.php)$ /$2 last;
    rewrite /. /index.php last;
}
EOF
)
    else
      multisite_rules=$(cat <<'EOF'
if (!-e $request_filename) {
    rewrite /wp-admin$ $scheme://$host$uri/ permanent;
    rewrite ^/[_0-9a-zA-Z-]+/(wp-(content|admin|includes).*) /$1 last;
    rewrite ^/[_0-9a-zA-Z-]+/(.*\.php)$ /$1 last;
    rewrite /. /index.php last;
}
EOF
)
    fi
  fi

  sudo tee "$config_file" >/dev/null <<EOF
server {
  listen 80;
  server_name ${domain} www.${domain};
  root ${WEBROOT}/${domain};
  index index.php;

  add_header X-Frame-Options "SAMEORIGIN" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header X-XSS-Protection "1; mode=block" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  add_header Content-Security-Policy "upgrade-insecure-requests;" always;

  ${cache_config}

  location / { try_files \$uri \$uri/ /index.php\$is_args\$args; }
  ${multisite_rules}

  location ~ \.php\$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/run/php/php${PHP_VERSION}-${domain}.sock;
  }

  location = /xmlrpc.php {
    if (\$xmlrpc_allowed = 0) { return 403; }
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/run/php/php${PHP_VERSION}-${domain}.sock;
  }

  location ~* /(?:uploads|files)/.*\.php\$ { deny all; }
  location ~* \.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist)\$ { deny all; }
  location ~ /\. { deny all; }
  location = /readme.html { deny all; }
  location = /license.txt { deny all; }
}
EOF

  [[ -L "/etc/nginx/sites-enabled/${domain}" ]] || sudo ln -s "$config_file" "/etc/nginx/sites-enabled/${domain}"

  # Test & reload without tripping ERR trap
  set +e
  sudo nginx -t
  local rc=$?
  set -e
  if (( rc == 0 )); then
    sudo systemctl reload nginx
  else
    warn "Nginx config test failed; leaving previous config active."
    return 1
  fi
}

save_credentials() {
  local domain="$1" admin_user="$2" admin_pass="$3" db_name="$4" db_user="$5" db_pass="$6"
  mkdir -p "$HOME/woo_credentials"
  local cred_file="$HOME/woo_credentials/${domain}.txt"
  tee "$cred_file" >/dev/null <<EOF
############################################
# WordPress Credentials for: ${domain}
############################################

Site URL: https://${domain}
Admin URL: https://${domain}/wp-admin
Admin Username: ${admin_user}
Admin Password: ${admin_pass}

--------------------------------------------

Database Name: ${db_name}
Database User: ${db_user}
Database Pass: ${db_pass}
############################################
EOF
  chmod 600 "$cred_file"
  success "Credentials saved to $cred_file"
}

print_site_report() {
  local domain="$1" admin_user="$2" admin_pass="$3" db_name="$4" db_user="$5" db_pass="$6" admin_email="$7" site_dir="$8"
  local report_dir="$HOME/woo_credentials"
  local report_file="${report_dir}/${domain}_report.txt"
  local php_pool="/etc/php/${PHP_VERSION}/fpm/pool.d/${domain}.conf"
  local nginx_vhost="/etc/nginx/sites-available/${domain}"
  local cert_status="Pending"
  local redis_status="Enabled"
  local cache_tip="Disabled (enable via: Menu → Manage Site Caching)"

  mkdir -p "$report_dir"
  if [ -f "/etc/letsencrypt/live/${domain}/fullchain.pem" ]; then cert_status="Active"; fi
  if grep -q "fastcgi_cache WORDPRESS;" "$nginx_vhost" 2>/dev/null; then cache_tip="Enabled (you can toggle from the menu)"; fi

  local box_line="================================================================================"
  tee "$report_file" >/dev/null <<EOF
$box_line
WOO Site Provision Report — ${domain}
$box_line

Site URLs:
- Frontend:            https://${domain}
- Admin:               https://${domain}/wp-admin

Admin Credentials:
- Username:            ${admin_user}
- Password:            ${admin_pass}
- Admin Email:         ${admin_email}

Database:
- DB Name:             ${db_name}
- DB User:             ${db_user}
- DB Pass:             ${db_pass}

Paths & Services:
- Webroot:             ${site_dir}
- PHP-FPM Pool:        ${php_pool}
- Nginx vHost:         ${nginx_vhost}
- Redis Object Cache:  ${redis_status}
- HTTPS (Let's Encrypt): ${cert_status}
- FastCGI Cache:       ${cache_tip}

What was done:
- Created per-site DB + DB user with limited scope
- Downloaded and configured WordPress with secure salts and custom table prefix
- Set Redis object caching and sensible WP constants (SSL admin, no file editor, memory limits)
- Created isolated PHP-FPM pool/socket for ${domain}
- Wrote Nginx vhost (HTTP first; Certbot upgrades to HTTPS)
- Requested Let's Encrypt certificate (if DNS ready)
- Secured file permissions

Recommended next steps:
- Verify DNS A/AAAA records for ${domain} and www.${domain}
- If HTTPS shows "Pending": re-run cert issuance later with:
    sudo certbot --nginx -d ${domain} -d www.${domain} --redirect --hsts --staple-ocsp
- Enable/disable FastCGI cache from: Menu → "Manage Site Caching"
- Create a first on-demand backup from: Menu → "Backup Management"
- (Optional) Configure scheduled backups with off-site rsync/scp in the same menu

This report is saved at:
${report_file}
$box_line
EOF

  echo -e "\n${GREEN}Provision report written to:${NC} ${report_file}\n"
  echo "----- COPY/PASTE CREDENTIALS -----"
  echo "URL: https://${domain}"
  echo "Admin: https://${domain}/wp-admin"
  echo "User: ${admin_user}"
  echo "Pass: ${admin_pass}"
  echo "DB:   ${db_name} | ${db_user} | ${db_pass}"
  echo "----------------------------------"
}

install_standard_site() {
  local domain="$1" site_dir="$2" admin_user="$3" admin_pass="$4" admin_email="$5"
  sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp core install \
    --path="$site_dir" --url="https://${domain}" --title="${domain}" \
    --admin_user="${admin_user}" --admin_password="${admin_pass}" --admin_email="${admin_email}"
  sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp plugin install redis-cache --activate --path="$site_dir"
  sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp redis enable --path="$site_dir"
}

install_multisite() {
  local domain="$1" site_dir="$2" admin_user="$3" admin_pass="$4" admin_email="$5"
  sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp config set WP_ALLOW_MULTISITE true --raw --path="$site_dir"
  local subdomains_flag=""
  if dig +short "wildcard-check.${domain}" | grep -Eq "([0-9]{1,3}\.){3}[0-9]{1,3}"; then subdomains_flag="--subdomains"; fi
  sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp core multisite-install \
    --path="$site_dir" --url="https://${domain}" --title="${domain}" \
    --admin_user="${admin_user}" --admin_password="${admin_pass}" --admin_email="${admin_email}" \
    ${subdomains_flag:+$subdomains_flag}
  sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp plugin install redis-cache --activate --network --path="$site_dir"
  sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp redis enable --path="$site_dir"
}

add_site() {
  clear; echo -e "${GREEN}--- Add New WordPress Site ---${NC}\n"
  local domain admin_user admin_email admin_pass site_type
  read -rp "Domain (e.g., example.com): " domain
  [[ -n "$domain" ]] || { warn "Domain cannot be empty."; return; }

  read -rp "Admin username (avoid 'admin'): " admin_user
  [[ -n "$admin_user" ]] || admin_user="siteadmin"
  read -rp "Admin email: " admin_email
  [[ -n "$admin_email" ]] || admin_email="admin@${domain}"
  admin_pass="$(openssl rand -base64 16)"
  read -rp "Install type [1=Standard, 2=Multisite] (default 1): " site_type
  site_type="${site_type:-1}"

  local site_dir="${WEBROOT}/${domain}"
  SITE_DATA[DOMAIN]="$domain"; SITE_DATA[SITE_DIR]="$site_dir"

  if [[ -d "$site_dir" ]]; then
    warn "Directory exists: $site_dir — wiping for fresh install."
    sudo rm -rf "$site_dir"
  fi

  local db_name="wp_$(echo "$domain" | tr '.' '_' | cut -c 1-20)_$(openssl rand -hex 4)"
  local db_user="usr_$(openssl rand -hex 6)"
  local db_pass; db_pass="$(openssl rand -base64 24)"
  SITE_DATA[DB_NAME]="$db_name"; SITE_DATA[DB_USER]="$db_user"

  log "Creating DB/user..."
  mysql_exec "CREATE DATABASE \`${db_name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
  mysql_exec "CREATE USER '${db_user}'@'localhost' IDENTIFIED BY '${db_pass}';"
  mysql_exec "GRANT ALL PRIVILEGES ON \`${db_name}\`.* TO '${db_user}'@'localhost'; FLUSH PRIVILEGES;"

  log "Preparing site dir: $site_dir"
  sudo mkdir -p "$site_dir"
  sudo chown -R www-data:www-data "$site_dir"

  log "Downloading WordPress..."
  sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp core download --path="$site_dir" --locale=en_US

  log "Generating wp-config.php..."
  local table_prefix="wp_$(openssl rand -hex 3)_"
  sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp config create \
    --path="$site_dir" --dbname="${db_name}" --dbuser="${db_user}" --dbpass="${db_pass}" --dbprefix="${table_prefix}" \
    --extra-php <<PHP
define('WP_CACHE', true);
define('WP_REDIS_HOST', '127.0.0.1');
define('WP_REDIS_PORT', 6379);
define('FS_METHOD', 'direct');
define('FORCE_SSL_ADMIN', true);
define('DISALLOW_FILE_EDIT', true);
define('WP_AUTO_UPDATE_CORE', 'minor');
define('WP_DEBUG', false);
define('WP_MEMORY_LIMIT', '128M');
define('WP_MAX_MEMORY_LIMIT', '256M');
PHP
  sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp config set WP_CACHE_KEY_SALT "'${domain}'" --path="$site_dir" --raw

  if [[ "$site_type" == "2" ]]; then
    install_multisite "$domain" "$site_dir" "$admin_user" "$admin_pass" "$admin_email"
  else
    install_standard_site "$domain" "$site_dir" "$admin_user" "$admin_pass" "$admin_email"
  fi

  log "Securing file perms..."
  sudo find "$site_dir" -type d -exec chmod 755 {} \;
  sudo find "$site_dir" -type f -exec chmod 644 {} \;
  sudo chmod 600 "${site_dir}/wp-config.php"

  create_php_pool "$domain"
  configure_nginx_site "$domain" "false"

  log "Requesting Let's Encrypt SSL..."
  if ! sudo certbot --nginx --hsts --staple-ocsp --non-interactive --agree-tos -m "$admin_email" -d "$domain" -d "www.$domain" --redirect; then
    warn "Certbot failed (likely DNS/propagation). Site remains on HTTP; retry later with: sudo certbot --nginx -d $domain -d www.$domain"
  fi

  save_credentials "$domain" "$admin_user" "$admin_pass" "$db_name" "$db_user" "$db_pass"
  print_site_report "$domain" "$admin_user" "$admin_pass" "$db_name" "$db_user" "$db_pass" "$admin_email" "$site_dir"
  success "Site '${domain}' installed."
  SITE_DATA=()
}

remove_site() {
  clear; echo -e "${RED}--- Remove WordPress Site ---${NC}\n"
  local domain; domain=$(select_site) || return
  warn "This will permanently delete ${domain} (files, DB, users, config)."
  read -rp "Type the domain to confirm: " confirm
  local clean_confirm clean_domain
  clean_confirm="$(echo -n "$confirm" | tr -d ' \t\r\n')"
  clean_domain="$(echo -n "$domain" | tr -d ' \t\r\n')"
  [[ "$clean_confirm" == "$clean_domain" ]] || { warn "Confirmation mismatch. Aborted."; return; }
  remove_site_silent "$domain"
  success "Site ${domain} removed."
}

remove_site_silent() {
  local domain="$1"
  local site_dir="${WEBROOT}/${domain}"
  local db_name="" db_user=""

  if [[ -d "$site_dir" ]]; then
    if sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp config get DB_NAME --path="$site_dir" --quiet >/dev/null 2>&1; then
      db_name=$(sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp config get DB_NAME --path="$site_dir" --quiet)
      db_user=$(sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp config get DB_USER --path="$site_dir" --quiet)
    elif sudo test -r "${site_dir}/wp-config.php"; then
      db_name=$(sudo awk -F"'" '/DB_NAME/{print $4;exit}' "${site_dir}/wp-config.php" 2>/dev/null || echo "")
      db_user=$(sudo awk -F"'" '/DB_USER/{print $4;exit}' "${site_dir}/wp-config.php" 2>/dev/null || echo "")
    fi
  fi

  sudo rm -f "/etc/nginx/sites-available/${domain}" "/etc/nginx/sites-enabled/${domain}"
  sudo rm -f "/etc/php/${PHP_VERSION}/fpm/pool.d/${domain}.conf"
  if [[ -n "${db_name:-}" ]]; then
    mysql_exec "DROP DATABASE IF EXISTS \`${db_name}\`;"
    mysql_exec "DROP USER IF EXISTS '${db_user}'@'localhost'; FLUSH PRIVILEGES;"
  else
    warn "DB credentials not found; skipped DB cleanup for ${domain}"
  fi
  sudo rm -rf "$site_dir"
  sudo systemctl reload nginx "php${PHP_VERSION}-fpm"
}

list_sites() {
  clear; echo -e "${BLUE}--- Managed WordPress Sites ---${NC}\n"
  if ls -1 "${WEBROOT}" 2>/dev/null | grep -v '^html$' >/dev/null; then
    ls -1 "${WEBROOT}" | grep -v '^html$' | sed 's/^/ - /'
  else
    warn "No sites found."
  fi
}

# ---- domain selector ----------------------------------------------------------
select_site() {
  local arr=()
  mapfile -t arr < <(ls -1 "${WEBROOT}" 2>/dev/null | grep -v '^html$' || true)
  ((${#arr[@]})) || { warn "No sites available."; return 1; }
  >&2 echo "Please select a site to manage:"
  local i
  for i in "${!arr[@]}"; do >&2 echo "  $((i+1))) ${arr[$i]}"; done
  local choice
  read -rp "Enter number or domain: " choice
  for i in "${!arr[@]}"; do [[ "$choice" == "${arr[$i]}" ]] && { echo "$choice"; return 0; }; done
  if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice>=1 && choice<=${#arr[@]} )); then
      echo "${arr[$((choice-1))]}"
  else
      warn "Invalid selection."
      return 1
  fi
}

# ---- caching manager (fixed: answering 'n' no longer trips ERR) --------------
manage_caching() {
  clear; echo -e "${BLUE}--- Manage Site Caching ---${NC}\n"
  local domain; domain=$(select_site) || return
  local conf="/etc/nginx/sites-available/${domain}"
  if grep -q "fastcgi_cache WORDPRESS;" "$conf" 2>/dev/null; then
    echo -e "Current: ${GREEN}ENABLED${NC}"
    read -rp "Disable caching? (y/N): " a
    if [[ "${a,,}" == "y" ]]; then
      configure_nginx_site "$domain" "false"
      success "Cache disabled."
    else
      success "No changes."
    fi
  else
    echo -e "Current: ${RED}DISABLED${NC}"
    read -rp "Enable caching? (y/N): " a
    if [[ "${a,,}" == "y" ]]; then
      configure_nginx_site "$domain" "true"
      success "Cache enabled."
    else
      success "No changes."
    fi
  fi
}

manage_xmlrpc() {
  clear; echo -e "${BLUE}--- Manage XML-RPC Whitelist (global) ---${NC}\n"
  while true; do
    echo "Whitelisted IPs:"
    grep -E '^[[:space:]]*([0-9]{1,3}\.){3}[0-9]{1,3}[[:space:]]+1;' "$XMLRPC_WHITELIST_FILE" 2>/dev/null \
      | awk '{print " - " $1}' || echo " - None"
    echo -e "\n1) Add IP  2) Remove IP  3) Back"
    read -rp "Choice: " c
    case "$c" in
      1)
        read -rp "IP to add: " ip
        [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { warn "Invalid IP."; continue; }
        if grep -q "$ip" "$XMLRPC_WHITELIST_FILE"; then warn "Already present."
        else
          sudo sed -i "/^geo /a \    ${ip} 1;" "$XMLRPC_WHITELIST_FILE"
          sudo nginx -t && sudo systemctl reload nginx
          success "Added."
        fi
        ;;
      2)
        read -rp "IP to remove: " ip
        if sudo grep -q "$ip" "$XMLRPC_WHITELIST_FILE"; then
          sudo sed -i -E "/^[[:space:]]*${ip}[[:space:]]+1;/d" "$XMLRPC_WHITELIST_FILE"
          sudo nginx -t && sudo systemctl reload nginx
          success "Removed."
        else
          warn "Not found."
        fi
        ;;
      3) break ;;
      *) warn "Invalid." ;;
    esac
  done
}

create_on_demand_backup() {
  local domain; domain=$(select_site) || return
  local site_dir="${WEBROOT}/${domain}"
  local backup_dir="$HOME/woo_backups/${domain}"
  mkdir -p "$backup_dir"

  local ts; ts="$(date +%Y%m%d_%H%M%S)"
  local file_backup="${backup_dir}/files_${ts}.tar.gz"
  local db_backup="${backup_dir}/db_${ts}.sql"
  local tmp_db="/tmp/db_${domain}_${ts}.sql"

  sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp db export "$tmp_db" --path="$site_dir"
  sudo mv "$tmp_db" "$db_backup"
  sudo tar -czf "$file_backup" -C "$WEBROOT" "$domain"

  success "Backup complete.\n  Files: $file_backup\n  DB:    $db_backup"
}

configure_scheduled_backups() {
  clear; echo -e "${BLUE}--- Scheduled Backups ---${NC}\n"
  read -rp "Enable daily backups at 02:00? (y/N): " a
  if [[ "${a,,}" != "y" ]]; then
    (crontab -l 2>/dev/null | grep -v "${TARGET_SCRIPT} backup-all") | crontab - || true
    success "Scheduled backups disabled."
    return
  fi

  mkdir -p "$CONFIG_DIR"
  read -rp "Enable off-site rsync/scp? (y/N): " r
  if [[ "${r,,}" == "y" ]]; then
    read -rp "Remote user: " RU; read -rp "Remote host: " RH; read -rp "Remote path: " RP
    printf "REMOTE_USER=%s\nREMOTE_HOST=%s\nREMOTE_PATH=%s\n" "$RU" "$RH" "$RP" > "$BACKUP_CONFIG_FILE"
    chmod 600 "$BACKUP_CONFIG_FILE"
    warn "Ensure SSH keys are set up for passwordless transfer."
  else
    rm -f "$BACKUP_CONFIG_FILE" || true
  fi

  (crontab -l 2>/dev/null | grep -v "${TARGET_SCRIPT} backup-all"; echo "0 2 * * * bash ${TARGET_SCRIPT} backup-all") | crontab -
  success "Daily backups scheduled."
}

backup_all_sites() {
  log "--- All-Sites Scheduled Backup ---"
  local s; mapfile -t s < <(ls -1 "${WEBROOT}" 2>/dev/null | grep -v '^html$' || true)
  for domain in "${s[@]}"; do
    local sd="${WEBROOT}/${domain}" bd="$HOME/woo_backups/${domain}"
    mkdir -p "$bd"
    local d; d="$(date +%Y%m%d)"
    local tmp_db="/tmp/db_${domain}_${d}.sql"
    sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp db export "$tmp_db" --path="$sd"
    local archive="${bd}/full_${d}.tar.gz"
    sudo tar -czf "$archive" -C "$WEBROOT" "$domain" -C /tmp "$(basename "$tmp_db")"
    sudo rm -f "$tmp_db"
    log "Backup: $archive"

    if [[ -f "$BACKUP_CONFIG_FILE" ]]; then
      # shellcheck disable=SC1090
      source "$BACKUP_CONFIG_FILE"
      rsync -a -e ssh "$archive" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH}" || warn "Off-site sync failed for ${domain}"
    fi

    ls -tp "${bd}"/full_*.tar.gz 2>/dev/null | tail -n +8 | xargs -r -d $'\n' rm -f --
  done
  log "--- Backups Done ---"
}

clone_to_staging() {
  clear; echo -e "${BLUE}--- Clone Site to Staging ---${NC}\n"
  local domain; domain=$(select_site) || return
  local staging="staging.${domain}"
  local sd="${WEBROOT}/${domain}"
  local td="${WEBROOT}/${staging}"

  [[ -d "$sd" ]] || { warn "Source does not exist."; return; }
  [[ -d "$td" ]] && { warn "Staging exists. Removing."; remove_site_silent "$staging"; }

  log "Cloning files..."
  sudo cp -a "$sd" "$td"

  log "Cloning DB..."
  local db_name db_user
  db_name=$(sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp config get DB_NAME --path="$sd" --quiet)
  db_user=$(sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp config get DB_USER --path="$sd" --quiet)
  local sdb="${db_name}_stg_$(openssl rand -hex 3)"

  mysql_exec "CREATE DATABASE \`${sdb}\`;"
  mysqldump_pipe_restore "${db_name}" "${sdb}"
  mysql_exec "GRANT ALL PRIVILEGES ON \`${sdb}\`.* TO '${db_user}'@'localhost'; FLUSH PRIVILEGES;"

  log "Pointing staging to new DB..."
  sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp config set DB_NAME "$sdb" --path="$td"

  log "Search-replace URLs..."
  sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp search-replace "https://${domain}" "https://${staging}" --all-tables --path="$td"

  create_php_pool "$staging"
  configure_nginx_site "$staging" "false"

  local admin_email; admin_email=$(sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp option get admin_email --path="$sd" --quiet || echo "admin@${domain}")
  if ! sudo certbot --nginx --hsts --staple-ocsp --non-interactive --agree-tos -m "$admin_email" -d "$staging" --redirect; then
    warn "Staging SSL failed. Check DNS for ${staging}."
  fi

  sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp option update blog_public 0 --path="$td"
  success "Staging ready: https://${staging}"
}

site_toolkit() {
  clear; echo -e "${BLUE}--- Site Toolkit ---${NC}\n"
  local domain; domain=$(select_site) || return
  local dir="${WEBROOT}/${domain}"
  while true; do
    echo -e "\n${YELLOW}${domain}${NC}"
    echo "1) List users"
    echo "2) Optimize DB"
    echo "3) List cron events"
    echo "4) Quick health (checksums, plugin status)"
    echo "5) Back"
    read -rp "Choice: " c
    case "$c" in
      1) sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp user list --path="$dir" ;;
      2) sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp db optimize --path="$dir" ;;
      3) sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp cron event list --path="$dir" ;;
      4)
        sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp core verify-checksums --path="$dir" || true
        sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp plugin status --path="$dir" || true
        ;;
      5) break ;;
      *) warn "Invalid." ;;
    esac
    read -n 1 -s -r -p "Press any key..."
  done
}

manage_debugging() {
  clear; echo -e "${BLUE}--- Debugging ---${NC}\n"
  local domain; domain=$(select_site) || return
  local dir="${WEBROOT}/${domain}"
  while true; do
    local dbg_val; dbg_val=$(sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp config get WP_DEBUG --path="$dir" --quiet 2>/dev/null || echo "false")
    local dbg_display="OFF"; [[ "$dbg_val" == "true" ]] && dbg_display="ON"
    echo "WP_DEBUG: $dbg_display"
    echo "1) Toggle WP_DEBUG"
    echo "2) Tail debug.log"
    echo "3) Back"
    read -rp "Choice: " c
    case "$c" in
      1)
        if [[ "$dbg_val" == "true" ]]; then
          sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp config set WP_DEBUG false --raw --path="$dir"
          sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp config set WP_DEBUG_LOG false --raw --path="$dir"
          sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp config set WP_DEBUG_DISPLAY false --raw --path="$dir"
        else
          sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp config set WP_DEBUG true --raw --path="$dir"
          sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp config set WP_DEBUG_LOG true --raw --path="$dir"
          sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp config set WP_DEBUG_DISPLAY false --raw --path="$dir"
        fi
        success "Toggled."
        ;;
      2)
        log "Tailing ${dir}/wp-content/debug.log (Ctrl+C to stop)"
        sudo tail -f "${dir}/wp-content/debug.log" || true
        ;;
      3) break ;;
      *) warn "Invalid." ;;
    esac
  done
}

manage_backups() {
  clear; echo -e "${BLUE}--- Backups ---${NC}\n"
  echo "1) Create On-Demand Backup"
  echo "2) Configure Scheduled Backups"
  echo "3) Back"
  read -rp "Choice: " c
  case "$c" in
    1) create_on_demand_backup ;;
    2) configure_scheduled_backups ;;
    *) : ;;
  esac
}

# ------------------------------- Menu -----------------------------------------
main_menu() {
  while true; do
    clear
    echo -e "${BLUE}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ WordPress Ultimate Operations (WOO) ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}"
    echo " 1) List Managed Sites"
    echo " 2) Add New Site (Standard/Multisite)"
    echo " 3) Remove Existing Site"
    echo " 4) Manage Site Caching"
    echo " 5) Manage XML-RPC Whitelist"
    echo " 6) Backup Management"
    echo " 7) Clone Site to Staging"
    echo " 8) Site Toolkit"
    echo " 9) Debugging Tools"
    echo "10) Setup SSH MFA (google-authenticator)"
    echo "11) Exit"
    read -rp "Choose: " ch
    case "$ch" in
      1) list_sites ;;
      2) add_site ;;
      3) remove_site ;;
      4) manage_caching ;;
      5) manage_xmlrpc ;;
      6) manage_backups ;;
      7) clone_to_staging ;;
      8) site_toolkit ;;
      9) manage_debugging ;;
      10) sudo apt-get install -y libpam-google-authenticator && google-authenticator || warn "MFA setup skipped." ;;
      11) echo "Bye."; exit 0 ;;
      *) warn "Invalid option." ;;
    esac
    echo -e "\nPress any key to return to menu..."
    read -n 1 -s || true
  done
}

# ------------------------------- Entry ----------------------------------------
main() {
  if [[ "${1:-}" == "menu" ]]; then
    main_menu
    exit 0
  fi

  if [[ "${1:-}" == "backup-all" ]]; then backup_all_sites; exit 0; fi
  if [[ "${1:-}" == "remove-site-silent" && -n "${2:-}" ]]; then remove_site_silent "$2"; exit 0; fi

  require_sudo
  check_os
  self_install
  ensure_swap_if_low_ram
  install_dependencies
  configure_nginx_includes
  ensure_nginx_cache_zone
  secure_mysql
  configure_tuned_mariadb
  harden_server
  setup_alias

  success "Initial server setup complete."
  main_menu
}

main "$@"
