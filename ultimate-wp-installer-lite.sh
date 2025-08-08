#!/usr/bin/env bash
# ============================================================================
# WOO v12 — WordPress Operations Orchestrator (Interactive, One-Command)
# Target: Ubuntu 22.04 / 24.04 LTS
#
# Goals:
#  - Run once to setup the server. After that, just type `woo` for the menu.
#  - Always install the latest stable/LTS stack from Ubuntu + trusted PPAs.
#  - Per-site isolation: separate PHP-FPM pool, DB+user, Nginx vhost, filesystem.
#  - No Multisite, No Staging, No Cloudflare, No remote backups (local only).
#  - Keep XML-RPC enabled but protected by a global whitelist (for Odoo).
#  - Smart, safe, zero-fail as much as possible with rollback on errors.
#  - Explain what is happening; produce a clear installation report.
#
# What you get:
#  - Stack: Nginx, PHP-FPM (8.3 preferred, fallback to 8.2), MariaDB, Redis,
#           Fail2Ban, UFW, Certbot, WP-CLI, logrotate config.
#  - Menu actions: Add site, Remove site, List sites, Manage Cache, XML-RPC
#                  whitelist, Backups (local), Doctor report, Exit.
#
# Author intent: make this a reference-quality, readable shell script.
# ============================================================================

set -euo pipefail
IFS=$'\n\t'

# --------------------------- Colors & Log -----------------------------------
c_blue='\033[0;34m'; c_green='\033[0;32m'; c_yellow='\033[1;33m'; c_red='\033[0;31m'; c_nc='\033[0m'

readonly LOG_DIR="/var/log/woo-toolkit"
readonly LOG_FILE="${LOG_DIR}/woo-$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$LOG_DIR"; touch "$LOG_FILE"

log()  { echo -e "${c_blue}[$(date '+%F %T')]${c_nc} $*" | tee -a "$LOG_FILE"; }
ok()   { echo -e "${c_green}✓${c_nc} $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "${c_yellow}‼${c_nc} $*" | tee -a "$LOG_FILE"; }
fail(){ echo -e "${c_red}✗${c_nc} $*" | tee -a "$LOG_FILE"; exit 1; }

trap 'error_handler $LINENO "$BASH_COMMAND"' ERR

error_handler(){
  local line="$1"; local cmd="$2"
  log "Error on line $line: $cmd"
  rollback_safe
  fail "Aborted. See log: $LOG_FILE"
}

# --------------------------- Global Defaults --------------------------------
readonly WEBROOT="/var/www"
readonly CONFIG_DIR="/etc/woo"
readonly PHP_CANDIDATES=("8.3" "8.2")
PHP_VERSION=""
readonly MIN_RAM_MB=2048
readonly MIN_DISK_MB=10240
readonly XMLRPC_WHITELIST_FILE="/etc/nginx/conf.d/xmlrpc_whitelist.conf"
readonly LIMITS_FILE="/etc/nginx/conf.d/limits.conf"
readonly CACHE_FILE="/etc/nginx/conf.d/fastcgi_cache.conf"

# Rollback context for safe cleanup on errors
declare -A CTX=()  # keys we use: DOMAIN, SITE_DIR, DB_NAME, DB_USER, PHP

# --------------------------- Helper Functions -------------------------------
need_root(){ [[ $EUID -ne 0 ]] && fail "Please run as root (use: sudo bash woo.sh)"; }

have(){ command -v "$1" &>/dev/null; }

gen_pass(){ openssl rand -base64 "${1:-24}"; }
rand_hex(){ openssl rand -hex "${1:-6}"; }

timestamp(){ date +%Y%m%d_%H%M%S; }

press_any(){ read -n 1 -s -r -p "Press any key to continue..."; echo; }

safe_sed(){ sed -i -- "$@"; }

# --------------------------- Preflight & Detection --------------------------
preflight(){
  log "Running preflight checks..."
  [[ -f /etc/os-release ]] || fail "Unsupported OS (no /etc/os-release)."
  . /etc/os-release
  [[ "${NAME}" =~ Ubuntu ]] || fail "This script supports Ubuntu only."
  [[ "${VERSION_ID}" == "22.04" || "${VERSION_ID}" == "24.04" ]] || warn "Tested on Ubuntu 22.04/24.04. You are ${VERSION_ID}."
  local free_mb; free_mb=$(df -Pm / | awk 'NR==2 {print $4}')
  (( free_mb >= MIN_DISK_MB )) || fail "Low disk space: ${free_mb}MB (< ${MIN_DISK_MB}MB)."
  ok "Preflight OK."
}

ensure_swap(){
  local ram_mb; ram_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
  if (( ram_mb < MIN_RAM_MB )); then
    warn "Low RAM detected (${ram_mb}MB). Creating 2GB swap for stability..."
    if ! swapon --show | grep -q /swapfile; then
      fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
      chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
      grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
      ok "Swap enabled."
    else
      ok "Swap already enabled."
    fi
  fi
}

select_php_version(){
  # Try candidates in order; pick the first that installs/exists.
  for v in "${PHP_CANDIDATES[@]}"; do
    if apt-cache policy "php${v}-fpm" | grep -q Candidate; then
      PHP_VERSION="$v"; break
    fi
  done
  [[ -n "$PHP_VERSION" ]] || PHP_VERSION="8.2"  # safe default
  ok "Using PHP ${PHP_VERSION}."
}

# --------------------------- Stack Install ----------------------------------
install_stack(){
  log "Installing the software stack (latest stable available)..."
  apt-get update -y
  apt-get install -y software-properties-common curl wget unzip git rsync psmisc jq dnsutils ca-certificates

  # Enable trusted PPAs for newer stable Nginx/PHP stacks
  add-apt-repository -y ppa:ondrej/php
  add-apt-repository -y ppa:ondrej/nginx
  apt-get update -y

  select_php_version

  # Core stack
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    nginx mariadb-server redis-server fail2ban ufw \
    certbot python3-certbot-nginx unattended-upgrades haveged \
    php${PHP_VERSION}-fpm php${PHP_VERSION}-mysql php${PHP_VERSION}-curl php${PHP_VERSION}-mbstring php${PHP_VERSION}-xml \
    php${PHP_VERSION}-zip php${PHP_VERSION}-gd php${PHP_VERSION}-opcache php${PHP_VERSION}-redis php${PHP_VERSION}-imagick php${PHP_VERSION}-bcmath

  # WP-CLI
  if ! have wp; then
    curl -fsSL -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
    chmod +x /usr/local/bin/wp
  fi

  ok "Stack installed."
}

secure_mariadb(){
  log "Securing MariaDB..."
  if [[ -f /root/.my.cnf ]]; then
    warn "MariaDB root credentials already configured. Skipping."
    return
  fi
  local pass; pass="$(gen_pass 32)"
  mysql -u root <<SQL
ALTER USER 'root'@'localhost' IDENTIFIED BY '${pass}';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');
DROP DATABASE IF EXISTS test;
FLUSH PRIVILEGES;
SQL
  cat >/root/.my.cnf <<EOF
[client]
user=root
password=${pass}
EOF
  chmod 600 /root/.my.cnf
  ok "MariaDB secured."
}

tune_mariadb(){
  log "Tuning MariaDB for performance..."
  local ram_kb ib_k ib
  ram_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
  ib_k=$(( ram_kb / 4 ))
  if (( ib_k > 4194304 )); then ib="4096M"; else ib="${ib_k}K"; fi
  cat >/etc/mysql/mariadb.conf.d/99-woo-tuned.cnf <<EOF
[mysqld]
innodb_buffer_pool_size=${ib}
innodb_log_file_size=256M
innodb_file_per_table=1
max_allowed_packet=256M
tmp_table_size=128M
max_heap_table_size=128M
innodb_flush_log_at_trx_commit=1
EOF
  systemctl restart mariadb
  ok "MariaDB tuned."
}

harden_php(){
  log "Hardening PHP ${PHP_VERSION}..."
  mkdir -p "/etc/php/${PHP_VERSION}/fpm/conf.d"
  cat >"/etc/php/${PHP_VERSION}/fpm/conf.d/99-woo-opcache.ini" <<EOF
opcache.enable=1
opcache.enable_cli=1
opcache.memory_consumption=256
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=100000
opcache.validate_timestamps=0
opcache.jit=1255
opcache.jit_buffer_size=64M
realpath_cache_size=4096k
realpath_cache_ttl=600
EOF
  safe_sed 's/^expose_php = On/expose_php = Off/' "/etc/php/${PHP_VERSION}/fpm/php.ini" || true
  safe_sed 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/' "/etc/php/${PHP_VERSION}/fpm/php.ini" || true
  systemctl restart "php${PHP_VERSION}-fpm"
  ok "PHP hardened."
}

harden_imagick(){
  log "Applying safe ImageMagick policy..."
  local pol="/etc/ImageMagick-6/policy.xml"; [[ -f "$pol" ]] || pol="/etc/ImageMagick/policy.xml"
  if [[ -f "$pol" ]]; then
    cp "$pol" "${pol}.bak.$(timestamp)" || true
    if ! grep -q 'policy domain="resource" name="memory"' "$pol"; then
      cat >>"$pol" <<'EOF'
<policymap>
  <policy domain="resource" name="memory" value="512MiB"/>
  <policy domain="resource" name="map" value="1GiB"/>
  <policy domain="resource" name="width" value="8000"/>
  <policy domain="resource" name="height" value="8000"/>
  <policy domain="coder" rights="none" pattern="PDF"/>
  <policy domain="coder" rights="none" pattern="PS"/>
</policymap>
EOF
    fi
  fi
}

harden_firewall_fail2ban(){
  log "Configuring UFW and Fail2Ban..."
  ufw default deny incoming || true
  ufw default allow outgoing || true
  ufw allow OpenSSH || true
  ufw allow 'Nginx Full' || true
  echo "y" | ufw enable || true

  cat >/etc/fail2ban/jail.d/wordpress.conf <<EOF
[sshd]
enabled = true
maxretry = 3
bantime = 1d

[nginx-wp-login]
enabled = true
filter = nginx-wp-login
logpath = /var/log/nginx/*access.log
maxretry = 10
findtime = 600
bantime = 1d

[nginx-xmlrpc]
enabled = true
filter = nginx-xmlrpc
logpath = /var/log/nginx/*access.log
maxretry = 20
findtime = 600
bantime = 1d
EOF
  cat >/etc/fail2ban/filter.d/nginx-wp-login.conf <<'EOF'
[Definition]
failregex = <HOST> - .* "(POST|GET) /wp-login.php
ignoreregex =
EOF
  cat >/etc/fail2ban/filter.d/nginx-xmlrpc.conf <<'EOF'
[Definition]
failregex = <HOST> - .* "POST /xmlrpc.php
ignoreregex =
EOF
  systemctl restart fail2ban || true
  ok "Firewall and Fail2Ban ready."
}

nginx_global(){
  log "Writing global Nginx configs (limits, cache, xmlrpc whitelist, default site)..."
  cat >"$LIMITS_FILE" <<'EOF'
limit_req_zone $binary_remote_addr zone=logins:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=xmlrpc:10m rate=10r/m;
limit_conn_zone $binary_remote_addr zone=perip:10m;
EOF

  cat >"$CACHE_FILE" <<'EOF'
fastcgi_cache_path /var/run/nginx-cache levels=1:2 keys_zone=WORDPRESS:100m inactive=60m;
fastcgi_cache_key "$scheme$request_method$host$request_uri";
fastcgi_cache_use_stale error timeout invalid_header http_500;
fastcgi_ignore_headers Cache-Control Expires Set-Cookie;
EOF

  cat >"$XMLRPC_WHITELIST_FILE" <<'EOF'
# Global XML-RPC whitelist for all sites (0 = blocked by default)
geo $xmlrpc_allowed {
    default 0;
    # Add IPs using the WOO menu -> XML-RPC whitelist
    # Example: 203.0.113.10 1;
}
EOF

  cat >/etc/nginx/sites-available/default <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;
}
EOF
  ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

  nginx -t && systemctl reload nginx
  ok "Global Nginx config applied."
}

systemd_logrotate(){
  log "Systemd & logrotate…"
  mkdir -p /etc/systemd/system/nginx.service.d
  cat >/etc/systemd/system/nginx.service.d/override.conf <<'EOF'
[Service]
Restart=always
RestartSec=2
LimitNOFILE=100000
EOF
  systemctl daemon-reload
  systemctl restart nginx

  cat >/etc/logrotate.d/woo-nginx <<'EOF'
/var/log/nginx/*.log {
  daily
  rotate 14
  compress
  missingok
  notifempty
  create 0640 www-data adm
  sharedscripts
  postrotate
    [ -s /run/nginx.pid ] && kill -USR1 `cat /run/nginx.pid`
  endscript
}
EOF

  cat >/etc/logrotate.d/woo-phpfpm <<'EOF'
/var/log/php-fpm/*.log {
  daily
  rotate 14
  compress
  missingok
  notifempty
  create 0640 www-data adm
}
EOF
  ok "Systemd and logrotate configured."
}

# --------------------------- Per-Site Functions -----------------------------
php_pool_create(){
  local domain="$1"
  cat >"/etc/php/${PHP_VERSION}/fpm/pool.d/${domain}.conf" <<EOF
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
  mkdir -p /var/log/php-fpm
  touch "/var/log/php-fpm/${domain}-error.log" "/var/log/php-fpm/${domain}-slow.log"
  chown -R www-data:www-data /var/log/php-fpm
  systemctl restart "php${PHP_VERSION}-fpm"
}

nginx_site_write(){
  local domain="$1" docroot="$2" cache_on="$3" microcache="$4"
  local cache_block=""
  if [[ "$cache_on" == "on" ]]; then
    cache_block=$(cat <<'EOS'
set $skip_cache 0;
if ($request_method = POST) { set $skip_cache 1; }
if ($query_string != "") { set $skip_cache 1; }
if ($request_uri ~* "/wp-admin/|/xmlrpc.php|wp-.*.php|/feed/|index.php|sitemap(_index)?.xml") { set $skip_cache 1; }
if ($http_cookie ~* "comment_author|wordpress_logged_in|wp-postpass") { set $skip_cache 1; }
fastcgi_cache WORDPRESS;
fastcgi_cache_valid 200 60m;
fastcgi_cache_bypass $skip_cache;
fastcgi_no_cache $skip_cache;
EOS
)
  fi
  local micro=""; [[ "$microcache" == "on" ]] && micro='fastcgi_cache_valid 200 5s;'

  cat >"/etc/nginx/sites-available/${domain}" <<EOF
server {
    listen 443 ssl http2;
    server_name ${domain} www.${domain};
    root ${docroot};
    index index.php;

    ssl_certificate     /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers on;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    include ${LIMITS_FILE};

    ${cache_block}
    ${micro}

    location / { try_files \$uri \$uri/ /index.php\$is_args\$args; }

    location = /wp-login.php {
        limit_req zone=logins burst=10 nodelay;
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php${PHP_VERSION}-${domain}.sock;
    }

    location = /xmlrpc.php {
        if (\$xmlrpc_allowed = 0) { return 403; }
        limit_req zone=xmlrpc burst=20 nodelay;
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php${PHP_VERSION}-${domain}.sock;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php${PHP_VERSION}-${domain}.sock;
        limit_conn perip 20;
    }

    location ~* /(?:uploads|files)/.*\.php\$ { deny all; }
    location ~* \.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist)\$ { deny all; }
    location ~ /\. { deny all; }
    location = /readme.html { deny all; }
    location = /license.txt { deny all; }
}
server {
    listen 80;
    server_name ${domain} www.${domain};
    return 301 https://\$host\$request_uri;
}
EOF

  ln -sf "/etc/nginx/sites-available/${domain}" "/etc/nginx/sites-enabled/${domain}"
  nginx -t && systemctl reload nginx
}

create_wp_site(){
  clear; echo -e "${c_green}--- Add New WordPress Site ---${c_nc}\n"
  read -rp "Domain (example.com): " domain
  [[ -n "$domain" ]] || fail "Domain is required."
  read -rp "Admin email: " admin_email
  [[ -n "$admin_email" ]] || fail "Admin email is required."

  # Admin user (avoid 'admin')
  local admin_user=""
  while true; do
    read -rp "Admin username (avoid 'admin'): " admin_user
    [[ -z "$admin_user" ]] && { warn "Username required."; continue; }
    [[ "$admin_user" == "admin" ]] && { warn "Please choose something other than 'admin'."; continue; }
    break
  done

  local admin_pass; admin_pass="$(gen_pass 16)"
  local site_dir="${WEBROOT}/${domain}"
  [[ -d "$site_dir" ]] && fail "A directory for ${domain} already exists. Remove it first or choose another domain."

  CTX[DOMAIN]="$domain"; CTX[SITE_DIR]="$site_dir"

  # Prepare filesystem
  mkdir -p "${site_dir}"
  chown -R www-data:www-data "${site_dir}"

  # DB details
  local db_name="wp_$(echo "$domain" | tr '.' '_' | cut -c1-20)_$(rand_hex 4)"
  local db_user="usr_$(rand_hex 6)"
  local db_pass; db_pass="$(gen_pass 24)"
  CTX[DB_NAME]="$db_name"; CTX[DB_USER]="$db_user"

  # Create DB + User
  log "Creating database and user..."
  mysql --defaults-file=/root/.my.cnf <<SQL
CREATE DATABASE \`${db_name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER '${db_user}'@'localhost' IDENTIFIED BY '${db_pass}';
GRANT ALL PRIVILEGES ON \`${db_name}\`.* TO '${db_user}'@'localhost';
FLUSH PRIVILEGES;
SQL

  # Download WP
  log "Downloading WordPress core..."
  sudo -u www-data WP_CLI_CACHE_DIR='/tmp/wp-cli-cache' wp core download --path="${site_dir}" --locale=en_US

  # wp-config with hardened defaults
  log "Creating wp-config.php..."
  local table_prefix="wp_$(rand_hex 3)_"
  sudo -u www-data wp config create --path="${site_dir}" --dbname="${db_name}" --dbuser="${db_user}" --dbpass="${db_pass}" --dbprefix="${table_prefix}" --extra-php <<PHP
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
define('AUTOSAVE_INTERVAL', 120);
define('WP_POST_REVISIONS', 10);
PHP
  sudo -u www-data wp config set WP_CACHE_KEY_SALT "'${domain}'" --path="${site_dir}" --raw
  sudo -u www-data wp config set DISABLE_WP_CRON true --path="${site_dir}" --raw

  # Install site (single site only)
  log "Installing WordPress (single site)..."
  sudo -u www-data wp core install --path="${site_dir}" --url="https://${domain}" --title="${domain}" --admin_user="${admin_user}" --admin_password="${admin_pass}" --admin_email="${admin_email}"

  # Plugins & Redis
  log "Enabling Redis object cache..."
  sudo -u www-data wp plugin install redis-cache --activate --path="${site_dir}"
  sudo -u www-data wp redis enable --path="${site_dir}"

  # MU-hardening
  mkdir -p "${site_dir}/wp-content/mu-plugins"
  cat >"${site_dir}/wp-content/mu-plugins/woo-hardening.php" <<'PHP'
<?php
/**
 * MU-hardening for WOO
 */
add_filter('admin_init', function(){ remove_action('wp_head', 'wp_generator'); });
add_filter('rest_endpoints', function($endpoints){ unset($endpoints['/wp/v2/users']); return $endpoints; });
if (!defined('DISALLOW_FILE_EDIT')) define('DISALLOW_FILE_EDIT', true);
if (!defined('WP_POST_REVISIONS')) define('WP_POST_REVISIONS', 10);
if (!defined('AUTOSAVE_INTERVAL')) define('AUTOSAVE_INTERVAL', 120);
PHP
  chown -R www-data:www-data "${site_dir}"

  # PHP pool & Nginx vhost
  php_pool_create "$domain"
  nginx_site_write "$domain" "$site_dir" "on" "off"

  # SSL
  log "Requesting Let's Encrypt SSL certificate..."
  if certbot --nginx --hsts --redirect --staple-ocsp -d "$domain" -d "www.${domain}" -m "$admin_email" --agree-tos --non-interactive; then
    ok "SSL issued."
  else
    warn "SSL issuance failed (DNS/ports issue?). You can retry later with: certbot --nginx -d $domain -d www.$domain"
  fi

  # Real cron to drive WP events
  (crontab -l 2>/dev/null | grep -v "wp cron event run --due-now --path=${site_dir}" ; \
   echo "* * * * * sudo -u www-data WP_CLI_CACHE_DIR=/tmp/wp-cli-cache wp cron event run --due-now --path=${site_dir} >/dev/null 2>&1") | crontab -

  # File perms
  find "${site_dir}" -type d -exec chmod 755 {} \;
  find "${site_dir}" -type f -exec chmod 644 {} \;
  chmod 600 "${site_dir}/wp-config.php"

  # Save credentials report
  mkdir -p /root/woo_credentials
  local cred="/root/woo_credentials/${domain}.txt"
  cat >"$cred" <<EOF
========================================
WordPress Credentials for: ${domain}
========================================
Admin URL: https://${domain}/wp-admin
Admin User: ${admin_user}
Admin Pass: ${admin_pass}

Database: ${db_name}
DB User:  ${db_user}
DB Pass:  ${db_pass}
========================================
EOF
  chmod 600 "$cred"

  clear
  echo -e "${c_green}✔ Site installed successfully!${c_nc}"
  echo
  echo "Installation Report:"
  echo " - Domain:        https://${domain}"
  echo " - Admin URL:     https://${domain}/wp-admin"
  echo " - Admin User:    ${admin_user}"
  echo " - Admin Pass:    ${admin_pass}"
  echo " - DB Name:       ${db_name}"
  echo " - DB User:       ${db_user}"
  echo " - SSL:           $( [[ -f /etc/letsencrypt/live/${domain}/fullchain.pem ]] && echo Issued || echo Pending/Failed )"
  echo " - Redis:         Enabled"
  echo " - Cache:         FastCGI (ON)"
  echo " - Cron:          System cron enabled"
  echo
  echo "Credentials saved at: ${cred}"
  press_any
  CTX=()  # reset rollback context after success
}

remove_wp_site(){
  clear; echo -e "${c_red}--- Remove WordPress Site ---${c_nc}\n"
  local domain
  read -rp "Domain to remove (example.com): " domain
  [[ -n "$domain" ]] || { warn "No domain provided."; press_any; return; }

  local site_dir="${WEBROOT}/${domain}"
  if [[ ! -d "$site_dir" ]]; then
    warn "No site found at ${site_dir}."
    press_any; return
  fi

  echo -e "${c_yellow}This will permanently delete files, DB, user, and Nginx/PHP configs for ${domain}.${c_nc}"
  read -rp "Type the domain again to confirm: " confirm_domain
  [[ "$confirm_domain" == "$domain" ]] || { warn "Confirmation mismatch. Aborting."; press_any; return; }

  # Identify DB
  local db_name=""; local db_user=""
  if [[ -f "${site_dir}/wp-config.php" ]]; then
    db_name=$(grep "DB_NAME" "${site_dir}/wp-config.php" | cut -d \' -f 4 || true)
    db_user=$(grep "DB_USER" "${site_dir}/wp-config.php" | cut -d \' -f 4 || true)
  fi

  # Remove Nginx & PHP pool
  rm -f "/etc/nginx/sites-available/${domain}" "/etc/nginx/sites-enabled/${domain}"
  rm -f "/etc/php/${PHP_VERSION}/fpm/pool.d/${domain}.conf"
  systemctl reload nginx "php${PHP_VERSION}-fpm" || true

  # Drop DB
  if [[ -n "$db_name" ]]; then
    mysql --defaults-file=/root/.my.cnf -e "DROP DATABASE IF EXISTS \`${db_name}\`;"
    mysql --defaults-file=/root/.my.cnf -e "DROP USER IF EXISTS '${db_user}'@'localhost';"
  fi

  # Delete files
  rm -rf "${site_dir}"

  ok "Site ${domain} removed."
  press_any
}

list_sites(){
  clear; echo -e "${c_blue}--- Managed Sites ---${c_nc}\n"
  if ls -1 "${WEBROOT}" | grep -v '^html$' 2>/dev/null; then
    :
  else
    echo "No sites found."
  fi
  echo; press_any
}

manage_cache(){
  clear; echo -e "${c_blue}--- Manage Cache ---${c_nc}\n"
  read -rp "Domain: " domain
  local conf="/etc/nginx/sites-available/${domain}"
  [[ -f "$conf" ]] || { warn "Vhost not found."; press_any; return; }

  if grep -q "fastcgi_cache WORDPRESS" "$conf"; then
    echo "Cache is currently: ON"
    read -rp "Turn OFF cache? (y/N): " a
    if [[ "$a" =~ ^[Yy]$ ]]; then
      nginx_site_write "$domain" "${WEBROOT}/${domain}" "off" "off"
      ok "Cache disabled."; press_any; return
    fi
  else
    echo "Cache is currently: OFF"
    read -rp "Turn ON cache? (y/N): " a
    if [[ "$a" =~ ^[Yy]$ ]]; then
      nginx_site_write "$domain" "${WEBROOT}/${domain}" "on" "off"
      ok "Cache enabled."; press_any; return
    fi
  fi
  press_any
}

xmlrpc_whitelist_menu(){
  clear; echo -e "${c_blue}--- XML-RPC Whitelist (Global) ---${c_nc}\n"
  echo "Current entries:"
  grep -E "^\s*([0-9]{1,3}\.){3}[0-9]{1,3}" "$XMLRPC_WHITELIST_FILE" | awk '{print " - " $1}' || echo " - None"
  echo
  echo "1) Add IP to whitelist (e.g., your Odoo server)"
  echo "2) Remove IP from whitelist"
  echo "3) Back"
  read -rp "Choice: " c
  case "$c" in
    1)
      read -rp "Enter IP to ALLOW: " ip
      if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        if grep -q "$ip" "$XMLRPC_WHITELIST_FILE"; then
          warn "IP already present."
        else
          safe_sed "/^geo /a\ \ \ \ ${ip} 1;" "$XMLRPC_WHITELIST_FILE"
          nginx -t && systemctl reload nginx
          ok "Added ${ip}."
        fi
      else
        warn "Invalid IP format."
      fi
      ;;
    2)
      read -rp "Enter IP to REMOVE: " ip
      if grep -q "$ip" "$XMLRPC_WHITELIST_FILE"; then
        safe_sed "/${ip}/d" "$XMLRPC_WHITELIST_FILE"
        nginx -t && systemctl reload nginx
        ok "Removed ${ip}."
      else
        warn "IP not found."
      fi
      ;;
    *);;
  esac
  press_any
}

backups_menu(){
  clear; echo -e "${c_blue}--- Backups (Local Only) ---${c_nc}\n"
  echo "1) Backup a single site now"
  echo "2) Backup ALL sites now"
  echo "3) Schedule daily backups at 02:00"
  echo "4) Disable scheduled backups"
  echo "5) Back"
  read -rp "Choice: " c
  case "$c" in
    1)
      read -rp "Domain: " domain
      backup_site "$domain"
      ;;
    2)
      backup_all_sites
      ;;
    3)
      (crontab -l 2>/dev/null | grep -v "woo.sh backup-all"; echo "0 2 * * * /usr/bin/env bash /root/woo.sh backup-all >> /var/log/woo-toolkit/backup.log 2>&1") | crontab -
      ok "Daily backups scheduled."
      press_any
      ;;
    4)
      (crontab -l 2>/dev/null | grep -v "woo.sh backup-all") | crontab -
      ok "Scheduled backups disabled."
      press_any
      ;;
    *);;
  esac
}

backup_site(){
  local domain="$1"
  local dir="${WEBROOT}/${domain}"
  [[ -d "$dir" ]] || { warn "No site found at ${dir}."; press_any; return; }

  log "Backing up ${domain}..."
  local out="/root/woo_backups/${domain}"; mkdir -p "$out"
  local ts="$(date +%Y%m%d_%H%M%S)"
  local archive="${out}/full_${ts}.tar.gz"
  local db="$(sudo -u www-data wp config get DB_NAME --path="$dir" --quiet || echo)"
  local tmpdb="/tmp/db_${domain}_${ts}.sql"
  if [[ -n "$db" ]]; then
    sudo -u www-data wp db export "$tmpdb" --path="$dir" || true
    tar -czf "$archive" -C "$dir" . -C /tmp "$(basename "$tmpdb")"
    rm -f "$tmpdb"
  else
    tar -czf "$archive" -C "$dir" .
  fi
  ls -tp "${out}"/full_*.tar.gz 2>/dev/null | tail -n +8 | xargs -r -d $'\n' rm -f --
  ok "Backup stored at: ${archive}"
  press_any
}

backup_all_sites(){
  log "--- Backing up all sites ---"
  for s in $(ls -1 "${WEBROOT}" 2>/dev/null | grep -v '^html$' || true); do
    backup_site "$s"
  done
  ok "All backups complete."
}

doctor_report(){
  clear; echo -e "${c_blue}--- System Doctor Report ---${c_nc}\n"
  echo "- OS: $(. /etc/os-release; echo "$PRETTY_NAME")"
  echo "- Nginx: $(nginx -v 2>&1)"
  echo "- PHP-FPM: $(php-fpm${PHP_VERSION} -v 2>/dev/null | head -n1 || echo php${PHP_VERSION})"
  echo "- MariaDB: $(mysql --version)"
  echo "- Redis: $(redis-server --version 2>/dev/null | head -n1 || echo 'installed')"
  echo "- RAM total: $(awk '/MemTotal/ {print int($2/1024) "MB"}' /proc/meminfo)"
  echo "- Free disk (/): $(df -h / | awk 'NR==2{print $4 " free"}')"
  echo "- Nginx config test:"; nginx -t || true
  echo "- SSL certs expiring in <14 days:"
  for d in /etc/letsencrypt/live/*; do
    [[ -d "$d" ]] || continue
    local crt="$d/fullchain.pem"; [[ -f "$crt" ]] || continue
    local exp_ts=$(date -d "$(openssl x509 -enddate -noout -in "$crt" | cut -d= -f2)" +%s)
    local now=$(date +%s); local diff=$(( (exp_ts-now)/86400 ))
    (( diff < 14 )) && echo "  - $(basename "$d"): ${diff}d"
  done
  echo; press_any
}

# --------------------------- Rollback (best effort) -------------------------
rollback_safe(){
  if [[ -n "${CTX[DOMAIN]:-}" ]]; then
    rm -f "/etc/nginx/sites-available/${CTX[DOMAIN]}" "/etc/nginx/sites-enabled/${CTX[DOMAIN]}" || true
    rm -f "/etc/php/${PHP_VERSION}/fpm/pool.d/${CTX[DOMAIN]}.conf" || true
    systemctl reload "php${PHP_VERSION}-fpm" nginx || true
  fi
  [[ -n "${CTX[DB_NAME]:-}" ]] && mysql --defaults-file=/root/.my.cnf -e "DROP DATABASE IF EXISTS \`${CTX[DB_NAME]}\`;" || true
  [[ -n "${CTX[DB_USER]:-}" ]] && mysql --defaults-file=/root/.my.cnf -e "DROP USER IF EXISTS '${CTX[DB_USER]}'@'localhost';" || true
  [[ -n "${CTX[SITE_DIR]:-}" ]] && rm -rf "${CTX[SITE_DIR]}" || true
}

# --------------------------- First-Run Setup --------------------------------
first_run_setup(){
  need_root
  preflight
  ensure_swap
  install_stack
  secure_mariadb
  tune_mariadb
  harden_php
  harden_imagick
  harden_firewall_fail2ban
  nginx_global
  systemd_logrotate
  ok "Base server setup complete."

  # Add 'woo' alias for convenience to both root and current user
  local script_path="$(realpath "$0")"
  for rc in "/root/.bashrc" "${HOME}/.bashrc"; do
    if ! grep -q "alias woo=" "$rc" 2>/dev/null; then
      echo "alias woo='bash ${script_path}'" >> "$rc"
    fi
  done
  ok "Type 'woo' next time to open the menu."
  press_any
}

# --------------------------- Menu -------------------------------------------
main_menu(){
  while true; do
    clear
    echo -e "${c_blue}=====================================================${c_nc}"
    echo -e "${c_blue} WOO — WordPress Operations Orchestrator (v12)      ${c_nc}"
    echo -e "${c_blue}=====================================================${c_nc}\n"
    echo " 1) Add New Site"
    echo " 2) Remove Site"
    echo " 3) List Sites"
    echo " 4) Manage Cache"
    echo " 5) XML-RPC Whitelist"
    echo " 6) Backups"
    echo " 7) Doctor (Report)"
    echo " 8) Exit"
    echo
    read -rp "Choose an option [1-8]: " ans
    case "$ans" in
      1) create_wp_site ;;
      2) remove_wp_site ;;
      3) list_sites ;;
      4) manage_cache ;;
      5) xmlrpc_whitelist_menu ;;
      6) backups_menu ;;
      7) doctor_report ;;
      8) clear; exit 0 ;;
      *) warn "Invalid option." ; press_any ;;
    esac
  done
}

# --------------------------- Entry Point ------------------------------------
if [[ ! -f /root/.woo-first-run-complete ]]; then
  first_run_setup
  touch /root/.woo-first-run-complete
fi
main_menu
