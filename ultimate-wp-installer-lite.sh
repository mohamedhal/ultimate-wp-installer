#!/bin/bash
#
# ##################################################################################
# # WordPress Ultimate Operations (WOO) Toolkit - V8.3 (Socket Fix)                #
# #                                                                                #
# # This script provides a comprehensive, enterprise-grade solution for deploying  #
# # and managing high-performance, secure, and completely isolated WordPress sites.#
# #                                                                                #
# ##################################################################################

# --- Global Configuration & Settings ---
set -eo pipefail
trap 'error_handler $LINENO "$BASH_COMMAND"' ERR

# --- Colors & Logging ---
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'
readonly LOG_DIR="/var/log/woo-toolkit"
readonly LOG_FILE="${LOG_DIR}/woo-run-$(date +%Y%m%d_%H%M%S).log"

# Centralized logging function to handle permissions
_log() {
    local message="$1"
    if [ ! -d "$LOG_DIR" ]; then
        sudo mkdir -p "$LOG_DIR"
        sudo chown "$(whoami)":"$(whoami)" "$LOG_DIR"
    fi
    if [ ! -f "$LOG_FILE" ]; then
        touch "$LOG_FILE"
    fi
    echo -e "$message" >> "$LOG_FILE"
}

log() {
    local formatted_message="${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
    local plain_message="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "$formatted_message"
    _log "$plain_message"
}
success() {
    local formatted_message="${GREEN}✓${NC} $1"
    local plain_message="✓ $1"
    echo -e "$formatted_message"
    _log "$plain_message"
}
warn() {
    local formatted_message="${YELLOW}‼${NC} $1"
    local plain_message="‼ $1"
    echo -e "$formatted_message"
    _log "$plain_message"
}
fail() {
    local formatted_message="${RED}✗${NC} $1"
    local plain_message="✗ $1"
    echo -e "$formatted_message"
    _log "$plain_message"
    exit 1
}

# --- Core Variables ---
readonly PHP_VERSION="8.2"
readonly WEBROOT="/var/www"
readonly MIN_RAM=2048
readonly MIN_DISK=10240
readonly F2B_MAXRETRY=5
readonly F2B_BANTIME="1d"
ADMIN_EMAIL=""
declare -A SITE_DATA=()
readonly SCRIPT_PATH="$(realpath "$0")"
readonly CONFIG_DIR="$HOME/.woo-toolkit"
readonly BACKUP_CONFIG_FILE="$CONFIG_DIR/backup.conf"
readonly XMLRPC_WHITELIST_FILE="/etc/nginx/conf.d/xmlrpc_whitelist.conf"

# --- Error Handler ---
error_handler() {
    local line=$1
    local command=$2
    log "Critical error on line $line: \`$command\`. Initiating rollback..."

    if [[ -n "${SITE_DATA[DB_NAME]}" ]]; then
        log "Attempting to drop database: ${SITE_DATA[DB_NAME]}"
        mysql --defaults-file="$HOME/.my.cnf" -e "DROP DATABASE IF EXISTS \`${SITE_DATA[DB_NAME]}\`;" >/dev/null 2>&1 || true
        log "Attempting to drop user: ${SITE_DATA[DB_USER]}"
        mysql --defaults-file="$HOME/.my.cnf" -e "DROP USER IF EXISTS '${SITE_DATA[DB_USER]}'@'localhost';" >/dev/null 2>&1 || true
    fi

    if [[ -n "${SITE_DATA[SITE_DIR]}" ]]; then
        log "Removing site directory: ${SITE_DATA[SITE_DIR]}"
        sudo rm -rf "${SITE_DATA[SITE_DIR]}" >/dev/null 2>&1 || true
    fi
    
    if [[ -n "${SITE_DATA[DOMAIN]}" ]]; then
        log "Removing Nginx config for ${SITE_DATA[DOMAIN]}"
        sudo rm -f "/etc/nginx/sites-available/${SITE_DATA[DOMAIN]}" "/etc/nginx/sites-enabled/${SITE_DATA[DOMAIN]}" >/dev/null 2>&1 || true
    fi

    log "Restarting services to ensure stable state..."
    sudo systemctl restart nginx mariadb php${PHP_VERSION}-fpm >/dev/null 2>&1 || true

    fail "Installation failed. System has been rolled back. Check log for details: $LOG_FILE"
}

# --- Prerequisite and System Checks ---
check_user() {
    if [ "$(id -u)" -eq 0 ]; then
        warn "Running this script directly as root is not recommended."
        warn "It's safer to run as a regular user with sudo privileges."
        read -p "Press Enter to continue as root, or Ctrl+C to exit."
    elif ! sudo -v >/dev/null 2>&1; then
        fail "This script requires the ability to run commands with sudo. Please enter your password when prompted."
    fi
}

analyze_system() {
    log "Analyzing system environment..."
    if [ ! -f /etc/os-release ] || ! grep -q "Ubuntu" /etc/os-release; then
        fail "This script is optimized for Ubuntu LTS. Aborting."
    fi
    
    local os_version
    os_version=$(. /etc/os-release; echo "$VERSION_ID")
    
    if (( $(echo "$os_version < 22.04" | bc -l) )); then
        warn "This script is tested on Ubuntu 22.04+. You are on ${os_version}. Proceed with caution."
    else
        success "Ubuntu ${os_version} detected."
    fi

    local ram_mb
    ram_mb=$(grep MemTotal /proc/meminfo | awk '{print int($2/1024)}')
    if (( ram_mb < MIN_RAM )); then
        warn "Low RAM detected (${ram_mb}MB). Creating 2GB swap file..."
        sudo fallocate -l 2G /swapfile || sudo dd if=/dev/zero of=/swapfile bs=1M count=2048
        sudo chmod 600 /swapfile
        sudo mkswap /swapfile
        sudo swapon /swapfile
        if ! grep -q "/swapfile" /etc/fstab; then
            echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
        fi
        success "Swap file created and enabled."
    else
        success "Sufficient RAM detected (${ram_mb}MB)."
    fi
}

# --- Initial Server Setup ---
install_dependencies() {
    log "Updating package lists and installing core dependencies..."
    sudo apt-get update -y
    sudo apt-get install -y software-properties-common curl wget unzip git rsync bc psmisc
    
    log "Adding Ondrej PPA for latest PHP and Nginx..."
    sudo add-apt-repository -y ppa:ondrej/php
    sudo add-apt-repository -y ppa:ondrej/nginx
    sudo apt-get update -y

    log "Installing LEMP stack and essential tools..."
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
        nginx mariadb-server \
        php${PHP_VERSION}-fpm php${PHP_VERSION}-mysql php${PHP_VERSION}-curl \
        php${PHP_VERSION}-mbstring php${PHP_VERSION}-xml php${PHP_VERSION}-zip \
        php${PHP_VERSION}-gd php${PHP_VERSION}-opcache php${PHP_VERSION}-redis \
        php${PHP_VERSION}-imagick php${PHP_VERSION}-bcmath \
        redis-server fail2ban certbot python3-certbot-nginx \
        postfix unattended-upgrades haveged
    
    if ! command -v wp &>/dev/null; then
        log "Installing WP-CLI..."
        curl -sS -o /tmp/wp-cli.phar https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
        chmod +x /tmp/wp-cli.phar
        sudo mv /tmp/wp-cli.phar /usr/local/bin/wp
    fi
    
    log "Configuring unattended security upgrades..."
    echo 'APT::Periodic::Update-Package-Lists "1";' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades
    echo 'APT::Periodic::Unattended-Upgrade "1";' | sudo tee -a /etc/apt/apt.conf.d/20auto-upgrades
    
    success "All dependencies installed successfully."
}

configure_tuned_mariadb() {
    log "Tuning MariaDB for performance..."
    local total_ram_kb
    total_ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local innodb_buffer_pool_size=$(( total_ram_kb / 4 )) # 25% of RAM
    
    if (( innodb_buffer_pool_size > 4194304 )); then
        innodb_buffer_pool_size=4194304
    fi
    
    sudo tee /etc/mysql/mariadb.conf.d/99-woo-tuned.cnf >/dev/null <<EOF
[mysqld]
innodb_buffer_pool_size = ${innodb_buffer_pool_size}K
innodb_log_file_size = 256M
innodb_file_per_table = 1
max_allowed_packet = 256M
EOF
    sudo systemctl restart mariadb
    success "MariaDB performance tuning applied."
}

secure_mysql() {
    log "Securing MariaDB installation..."
    if [ -f "$HOME/.my.cnf" ]; then
        warn "MariaDB appears to be already secured. Skipping."
        return
    fi

    local db_root_pass
    db_root_pass=$(openssl rand -base64 32)
    local service_name="mariadb"
    local temp_socket="/tmp/mysql.sock"

    log "Forcefully resetting MariaDB root password..."
    sudo systemctl stop "$service_name" || true
    sudo systemctl disable "$service_name" || true
    sudo pkill -9 mysql || true
    sleep 3

    if pgrep mysqld; then
        fail "Failed to stop the MariaDB/MySQL process. Manual intervention is required."
    fi
    log "Database process successfully terminated."

    log "Cleaning up stale socket and PID files..."
    sudo find /var/run/mysqld/ -name "*.sock" -delete || true
    sudo find /var/run/mysqld/ -name "*.pid" -delete || true
    
    sudo mysqld_safe --skip-grant-tables --skip-networking --socket="$temp_socket" &
    local mysqld_pid=$!
    log "Started mysqld in safe mode with PID $mysqld_pid on socket $temp_socket"
    sleep 5
    
    local sql_file="/tmp/mysql-reset-$$.sql"
    tee "$sql_file" >/dev/null <<EOF
FLUSH PRIVILEGES;
ALTER USER 'root'@'localhost' IDENTIFIED BY '${db_root_pass}';
FLUSH PRIVILEGES;
EOF

    log "Executing password reset on temporary socket..."
    sudo mysql --socket="$temp_socket" -u root < "$sql_file"
    rm -f "$sql_file"
    
    log "Killing safe mode PID $mysqld_pid..."
    sudo kill -9 "$mysqld_pid"
    sleep 3
    
    log "Re-enabling and restarting MariaDB service..."
    sudo systemctl enable "$service_name"
    sudo systemctl start "$service_name"

    log "MariaDB root password has been reset."
    
    echo -e "[client]\nuser=root\npassword=${db_root_pass}" > "$HOME/.my.cnf"
    chmod 600 "$HOME/.my.cnf"
    
    log "Cleaning up anonymous users and test database..."
    mysql --defaults-file="$HOME/.my.cnf" <<EOF
DELETE FROM mysql.global_priv WHERE User='';
DELETE FROM mysql.global_priv WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
FLUSH PRIVILEGES;
EOF

    success "MariaDB secured. Root credentials stored in ~/.my.cnf"
}

harden_server() {
    log "Hardening server security..."
    log "Configuring UFW firewall..."
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow OpenSSH
    sudo ufw allow 'Nginx Full'
    echo "y" | sudo ufw enable
    
    log "Configuring Fail2Ban for SSH and WordPress..."
    sudo tee /etc/fail2ban/jail.d/wordpress.conf >/dev/null <<EOF
[sshd]
enabled = true
maxretry = 3
bantime = 1d

[wordpress-hard]
enabled = true
filter = wordpress-hard
logpath = /var/log/nginx/*access.log
maxretry = ${F2B_MAXRETRY}
bantime = ${F2B_BANTIME}
port = http,https
EOF
    sudo tee /etc/fail2ban/filter.d/wordpress-hard.conf >/dev/null <<EOF
[Definition]
failregex = ^<HOST>.* "POST.*wp-login.php
ignoreregex =
EOF
    sudo systemctl restart fail2ban
    
    log "Hardening PHP configuration..."
    sudo sed -i 's/^expose_php = On/expose_php = Off/' "/etc/php/${PHP_VERSION}/fpm/php.ini"
    sudo sed -i 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/' "/etc/php/${PHP_VERSION}/fpm/php.ini"

    log "Setting up XML-RPC IP Whitelist..."
    if [ ! -f "$XMLRPC_WHITELIST_FILE" ]; then
        sudo tee "$XMLRPC_WHITELIST_FILE" >/dev/null <<EOF
# This file is managed by the WOO Toolkit. Do not edit manually.
# Whitelisted IPs for XML-RPC access.
geo \$xmlrpc_allowed {
    default 0;
}
EOF
    fi
    
    sudo systemctl restart php${PHP_VERSION}-fpm
    success "Server hardening complete."
}

setup_alias() {
    local bash_files=("$HOME/.bashrc")
    if [ -f "/root/.bashrc" ]; then
        bash_files+=("/root/.bashrc")
    fi

    for bash_file in "${bash_files[@]}"; do
        if ! grep -q "alias woo=" "$bash_file"; then
            echo "Adding 'woo' alias to $bash_file..."
            echo "alias woo='bash ${SCRIPT_PATH}'" | sudo tee -a "$bash_file" >/dev/null
        fi
    done
    warn "Alias 'woo' has been set up. Please run 'source ~/.bashrc' or log out and log back in to use it."
}

# --- Site Management Functions ---
add_site() {
    clear; echo -e "${GREEN}--- Add New WordPress Site ---${NC}\n"
    
    local domain admin_user admin_pass site_type
    read -p "Enter domain name (e.g., mydomain.com): " domain
    SITE_DATA[DOMAIN]="$domain"
    
    read -p "Enter a secure admin username (do NOT use 'admin'): " admin_user
    admin_pass=$(openssl rand -base64 16)
    
    read -p "Installation type? (1) Standard (2) Multisite: " site_type
    
    local db_name="wp_$(echo "$domain" | tr '.' '_' | cut -c 1-20)_$(openssl rand -hex 4)"
    local db_user="usr_$(openssl rand -hex 6)"
    local db_pass=$(openssl rand -base64 24)
    local table_prefix="wp_$(openssl rand -hex 3)_"
    local site_dir="${WEBROOT}/${domain}"
    
    SITE_DATA[DB_NAME]="$db_name"; SITE_DATA[DB_USER]="$db_user"; SITE_DATA[SITE_DIR]="$site_dir"
    
    log "Creating database '${db_name}' and user '${db_user}'..."
    mysql --defaults-file="$HOME/.my.cnf" <<EOF
CREATE DATABASE \`${db_name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER '${db_user}'@'localhost' IDENTIFIED BY '${db_pass}';
GRANT ALL PRIVILEGES ON \`${db_name}\`.* TO '${db_user}'@'localhost';
FLUSH PRIVILEGES;
EOF

    log "Setting up site directory: ${site_dir}"
    sudo mkdir -p "$site_dir"
    sudo chown -R www-data:www-data "$site_dir"
    
    log "Downloading WordPress core..."
    sudo -u www-data wp core download --path="$site_dir" --locale=en_US
    
    log "Creating wp-config.php with security enhancements..."
    sudo -u www-data wp config create --path="$site_dir" --dbname="${db_name}" --dbuser="${db_user}" --dbpass="${db_pass}" --dbprefix="${table_prefix}" --extra-php <<PHP
define('WP_REDIS_HOST', '127.0.0.1');
define('WP_REDIS_PORT', 6379);
define('WP_CACHE_KEY_SALT', '${domain}');
define('WP_CACHE', true);
define('FS_METHOD', 'direct');
define('FORCE_SSL_ADMIN', true);
define('DISALLOW_FILE_EDIT', true);
define('WP_AUTO_UPDATE_CORE', 'minor');
define('WP_DEBUG', false);
define('WP_MEMORY_LIMIT', '128M');
define('WP_MAX_MEMORY_LIMIT', '256M');
PHP

    if [[ "$site_type" == "2" ]]; then
        install_multisite "$domain" "$site_dir" "$admin_user" "$admin_pass"
    else
        install_standard_site "$domain" "$site_dir" "$admin_user" "$admin_pass"
    fi
    
    log "Setting secure file permissions..."
    sudo find "$site_dir" -type d -exec chmod 755 {} \;
    sudo find "$site_dir" -type f -exec chmod 644 {} \;
    sudo chmod 600 "${site_dir}/wp-config.php"
    
    create_php_pool "$domain"
    configure_nginx_site "$domain" "false"
    
    log "Requesting Let's Encrypt SSL certificate..."
    if ! sudo certbot --nginx --hsts --uir --staple-ocsp -d "$domain" -d "www.$domain" --non-interactive --agree-tos -m "$ADMIN_EMAIL" --redirect; then
        warn "SSL certificate request failed. Please check DNS records and run Certbot manually."
    fi
    sudo systemctl reload nginx
    
    save_credentials "$domain" "$admin_user" "$admin_pass" "$db_name" "$db_user" "$db_pass"
    success "Site '$domain' installed successfully!"
    SITE_DATA=()
}

install_standard_site() {
    local domain=$1 site_dir=$2 admin_user=$3 admin_pass=$4
    log "Performing standard WordPress installation..."
    sudo -u www-data wp core install --path="$site_dir" --url="https://${domain}" --title="${domain}" --admin_user="${admin_user}" --admin_password="${admin_pass}" --admin_email="${ADMIN_EMAIL}"
    
    log "Installing recommended base plugins..."
    sudo -u www-data wp plugin install redis-cache --activate --path="$site_dir"
    sudo -u www-data wp redis enable --path="$site_dir"
}

install_multisite() {
    local domain=$1 site_dir=$2 admin_user=$3 admin_pass=$4
    log "Performing WordPress Multisite installation..."
    
    sudo -u www-data wp config set WP_ALLOW_MULTISITE true --raw --path="$site_dir"
    
    local network_type
    read -p "Multisite type? (1) Subdomain (e.g., site.domain.com) (2) Subdirectory (e.g., domain.com/site): " network_type
    
    if [[ "$network_type" == "1" ]]; then
        log "Checking for wildcard DNS record for *.$domain..."
        if ! dig +short "random-string-for-test.${domain}" | grep -qE "([0-9]{1,3}\.){3}[0-9]{1,3}"; then
            warn "Wildcard DNS does not appear to be configured. Subdomain creation will likely fail."
            read -p "Continue anyway? (y/n): " -n 1 -r; echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then fail "Aborting Multisite installation."; fi
        fi
        sudo -u www-data wp core multisite-install --path="$site_dir" --url="https://${domain}" --title="${domain}" --admin_user="${admin_user}" --admin_password="${admin_pass}" --admin_email="${ADMIN_EMAIL}" --subdomains
    else
        sudo -u www-data wp core multisite-install --path="$site_dir" --url="https://${domain}" --title="${domain}" --admin_user="${admin_user}" --admin_password="${admin_pass}" --admin_email="${ADMIN_EMAIL}"
    fi
    
    log "Installing recommended base plugins for Multisite..."
    sudo -u www-data wp plugin install redis-cache --activate --network --path="$site_dir"
    sudo -u www-data wp redis enable --path="$site_dir"
    success "Multisite network created. Please log in to complete any additional setup."
}

remove_site() {
    clear; echo -e "${RED}--- Remove WordPress Site ---${NC}\n"
    local domain
    domain=$(select_site)
    [[ -z "$domain" ]] && return
    
    warn "This will PERMANENTLY delete all files, database, and configurations for ${domain}."
    read -p "Are you absolutely sure? (y/n): " -n 1 -r; echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then warn "Removal aborted."; return; fi
    
    local site_dir="${WEBROOT}/${domain}"
    local db_name db_user
    
    if [ -f "${site_dir}/wp-config.php" ]; then
        db_name=$(grep "DB_NAME" "${site_dir}/wp-config.php" | cut -d \' -f 4)
        db_user=$(grep "DB_USER" "${site_dir}/wp-config.php" | cut -d \' -f 4)
    else
        warn "wp-config.php not found for ${domain}. Cannot determine database details to drop."
        db_name=""
    fi
    
    log "Removing Nginx config for ${domain}..."
    sudo rm -f "/etc/nginx/sites-available/${domain}" "/etc/nginx/sites-enabled/${domain}"
    
    log "Removing PHP-FPM pool for ${domain}..."
    sudo rm -f "/etc/php/${PHP_VERSION}/fpm/pool.d/${domain}.conf"
    
    if [[ -n "$db_name" ]]; then
        log "Dropping database '${db_name}' and user '${db_user}'..."
        mysql --defaults-file="$HOME/.my.cnf" -e "DROP DATABASE IF EXISTS \`${db_name}\`; DROP USER IF EXISTS '${db_user}'@'localhost';"
    fi
    
    log "Deleting site files from ${site_dir}..."
    sudo rm -rf "$site_dir"
    
    log "Reloading services..."
    sudo systemctl reload nginx php${PHP_VERSION}-fpm
    
    success "Site ${domain} has been completely removed."
}

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
    sudo chown -R www-data:www-data /var/log/php-fpm
    sudo systemctl restart php${PHP_VERSION}-fpm
    success "PHP-FPM pool created for $domain."
}

configure_nginx_site() {
    local domain="$1" enable_cache="$2"
    local config_file="/etc/nginx/sites-available/${domain}"
    
    local cache_config=""
    if [[ "$enable_cache" == "true" ]]; then
        cache_config=$(cat <<'EOF'
set $skip_cache 0;
if ($request_method = POST) { set $skip_cache 1; }
if ($query_string != "") { set $skip_cache 1; }
if ($request_uri ~* "/wp-admin/|/xmlrpc.php|wp-.*.php|/feed/|index.php|sitemap(_index)?.xml") { set $skip_cache 1; }
if ($http_cookie ~* "comment_author|wordpress_logged_in|wp-postpass") { set $skip_cache 1; }
fastcgi_cache_path /var/run/nginx-cache levels=1:2 keys_zone=WORDPRESS:100m inactive=60m;
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
    if sudo -u www-data wp core is-installed --network --path="${WEBROOT}/${domain}" >/dev/null 2>&1; then
        if sudo -u www-data wp config get SUBDOMAIN_INSTALL --path="${WEBROOT}/${domain}" --quiet; then
            multisite_rules="
if (!-e \$request_filename) {
    rewrite /wp-admin\$ \$scheme://\$host\$uri/ permanent;
    rewrite ^/([_0-9a-zA-Z-]+/)?(wp-(content|admin|includes).*) /\$2 last;
    rewrite ^/([_0-9a-zA-Z-]+/)?(.*\.php)\$ /\$2 last;
    rewrite /. /index.php last;
}"
        else
            multisite_rules="
if (!-e \$request_filename) {
    rewrite /wp-admin\$ \$scheme://\$host\$uri/ permanent;
    rewrite ^/[_0-9a-zA-Z-]+/(wp-(content|admin|includes).*) /\$1 last;
    rewrite ^/[_0-9a-zA-Z-]+/(.*\.php)\$ /\$1 last;
    rewrite /. /index.php last;
}"
        fi
    fi

    sudo tee "$config_file" >/dev/null <<EOF
server {
    listen 443 ssl http2;
    server_name ${domain} www.${domain};
    root ${WEBROOT}/${domain};
    index index.php;
    
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "upgrade-insecure-requests;" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    include ${XMLRPC_WHITELIST_FILE};
    ${cache_config}

    location / {
        try_files \$uri \$uri/ /index.php\$is_args\$args;
    }
    
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
server {
    listen 80;
    server_name ${domain} www.${domain};
    return 301 https://\$host\$request_uri;
}
EOF
    
    if [ ! -L "/etc/nginx/sites-enabled/${domain}" ]; then
        sudo ln -s "$config_file" "/etc/nginx/sites-enabled/${domain}"
    fi
    sudo nginx -t && sudo systemctl reload nginx
}

list_sites() {
    clear; echo -e "${BLUE}--- Managed WordPress Sites ---${NC}\n"
    if ! ls -1 "${WEBROOT}" | grep -v 'html' | sed 's/^/ - /'; then
        warn "No sites found."
    fi
}

select_site() {
    local sites
    sites=($(ls -1 "${WEBROOT}" | grep -v 'html'))
    if [ ${#sites[@]} -eq 0 ]; then
        warn "No sites available to manage."
        return
    fi
    
    echo "Select a site to manage:"
    select domain in "${sites[@]}"; do
        if [[ -n "$domain" ]]; then
            echo "$domain"
            return
        else
            warn "Invalid selection."
        fi
    done
}

manage_caching() {
    clear; echo -e "${BLUE}--- Manage Site Caching ---${NC}\n"
    local domain
    domain=$(select_site)
    [[ -z "$domain" ]] && return
    
    local nginx_conf="/etc/nginx/sites-available/${domain}"
    
    echo "Current Nginx FastCGI Cache status for ${domain}:"
    if grep -q "fastcgi_cache WORDPRESS;" "$nginx_conf"; then
        echo -e "${GREEN}ENABLED${NC}"
        read -p "Do you want to DISABLE caching? (y/n): " -n 1 -r; echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            configure_nginx_site "$domain" "false"
            success "Nginx FastCGI cache DISABLED for ${domain}."
        fi
    else
        echo -e "${RED}DISABLED${NC}"
        read -p "Do you want to ENABLE caching? (y/n): " -n 1 -r; echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            configure_nginx_site "$domain" "true"
            success "Nginx FastCGI cache ENABLED for ${domain}."
        fi
    fi
}

manage_xmlrpc() {
    clear; echo -e "${BLUE}--- Manage XML-RPC IP Whitelist ---${NC}\n"
    echo "This whitelist applies to ALL sites on this server."
    
    while true; do
        echo -e "\nCurrent Whitelisted IPs:"
        grep -E "^\s*([0-9]{1,3}\.){3}[0-9]{1,3}" "$XMLRPC_WHITELIST_FILE" | awk '{print " - " $1}' || echo " - None"
        
        echo -e "\n1) Add IP to Whitelist"
        echo "2) Remove IP from Whitelist"
        echo "3) Return to Main Menu"
        read -p "Enter choice: " choice
        
        case "$choice" in
            1)
                read -p "Enter the IP address to add (e.g., Odoo server IP): " ip_to_add
                if [[ "$ip_to_add" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                    if grep -q "$ip_to_add" "$XMLRPC_WHITELIST_FILE"; then
                        warn "IP address $ip_to_add is already in the whitelist."
                    else
                        sudo sed -i "/^geo /a \ \ \ \ ${ip_to_add} 1;" "$XMLRPC_WHITELIST_FILE"
                        sudo nginx -t && sudo systemctl reload nginx
                        success "IP $ip_to_add added to whitelist and Nginx reloaded."
                    fi
                else
                    warn "Invalid IP address format."
                fi
                ;;
            2)
                read -p "Enter the IP address to remove: " ip_to_remove
                if sudo grep -q "$ip_to_remove" "$XMLRPC_WHITELIST_FILE"; then
                    sudo sed -i "/${ip_to_remove}/d" "$XMLRPC_WHITELIST_FILE"
                    sudo nginx -t && sudo systemctl reload nginx
                    success "IP $ip_to_remove removed from whitelist and Nginx reloaded."
                else
                    warn "IP address $ip_to_remove not found in the whitelist."
                fi
                ;;
            3) break ;;
            *) warn "Invalid choice." ;;
        esac
    done
}

manage_backups() {
    clear; echo -e "${BLUE}--- Backup Management ---${NC}\n"
    echo "1) Create On-Demand Backup"
    echo "2) Configure Scheduled Backups"
    echo "3) Return to Main Menu"
    read -p "Enter choice: " choice
    
    case "$choice" in
        1) create_on_demand_backup ;;
        2) configure_scheduled_backups ;;
        *) return ;;
    esac
}

create_on_demand_backup() {
    local domain
    domain=$(select_site)
    [[ -z "$domain" ]] && return
    
    log "Starting backup for ${domain}..."
    local site_dir="${WEBROOT}/${domain}"
    local backup_dir="$HOME/woo_backups/${domain}"
    mkdir -p "$backup_dir"
    
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local file_backup_path="${backup_dir}/files_${timestamp}.tar.gz"
    local db_backup_path="${backup_dir}/db_${timestamp}.sql"
    
    local db_name
    db_name=$(sudo -u www-data wp config get DB_NAME --path="$site_dir" --quiet)
    
    log "Backing up database '${db_name}'..."
    sudo -u www-data wp db export "$db_backup_path" --path="$site_dir"
    
    log "Backing up files from ${site_dir}..."
    sudo tar -czf "$file_backup_path" -C "$WEBROOT" "$domain"
    
    success "Backup complete for ${domain}!"
    success "Files: ${file_backup_path}"
    success "Database: ${db_backup_path}"
}

configure_scheduled_backups() {
    clear; echo -e "${BLUE}--- Configure Scheduled Backups ---${NC}\n"
    
    read -p "Enable automated daily backups? (y/n): " -n 1 -r; echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        (crontab -l 2>/dev/null | grep -v "${SCRIPT_PATH} backup-all") | crontab -
        success "Scheduled backups disabled."
        return
    fi
    
    mkdir -p "$CONFIG_DIR"
    read -p "Enable remote off-site backups via rsync/scp? (y/n): " -n 1 -r; echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "Enter remote user (e.g., user): " remote_user
        read -p "Enter remote host (e.g., backup.server.com): " remote_host
        read -p "Enter remote path (e.g., /home/user/backups/): " remote_path
        echo "REMOTE_USER=${remote_user}" > "$BACKUP_CONFIG_FILE"
        echo "REMOTE_HOST=${remote_host}" >> "$BACKUP_CONFIG_FILE"
        echo "REMOTE_PATH=${remote_path}" >> "$BACKUP_CONFIG_FILE"
        chmod 600 "$BACKUP_CONFIG_FILE"
        warn "NOTE: You must have passwordless SSH key authentication set up for this to work."
    else
        rm -f "$BACKUP_CONFIG_FILE"
    fi
    
    (crontab -l 2>/dev/null | grep -v "${SCRIPT_PATH} backup-all"; echo "0 2 * * * bash ${SCRIPT_PATH} backup-all") | crontab -
    success "Daily backups scheduled for 2 AM."
}

backup_all_sites() {
    log "--- Starting All-Sites Scheduled Backup ---"
    local sites
    sites=($(ls -1 "${WEBROOT}" | grep -v 'html'))
    for domain in "${sites[@]}"; do
        log "Backing up ${domain}..."
        local site_dir="${WEBROOT}/${domain}"
        local backup_dir="$HOME/woo_backups/${domain}"
        mkdir -p "$backup_dir"
        
        local timestamp
        timestamp=$(date +%Y%m%d)
        local backup_archive="${backup_dir}/full_backup_${timestamp}.tar.gz"
        local db_backup_path="/tmp/db_${domain}_${timestamp}.sql"
        
        local db_name
        db_name=$(sudo -u www-data wp config get DB_NAME --path="$site_dir" --quiet)
        
        sudo -u www-data wp db export "$db_backup_path" --path="$site_dir"
        sudo tar -czf "$backup_archive" -C "$WEBROOT" "$domain" -C /tmp "$(basename "$db_backup_path")"
        sudo rm "$db_backup_path"
        
        log "Backup for ${domain} created at ${backup_archive}"
        
        if [ -f "$BACKUP_CONFIG_FILE" ]; then
            source "$BACKUP_CONFIG_FILE"
            log "Off-loading backup to ${REMOTE_HOST}..."
            rsync -a -e ssh "$backup_archive" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH}"
        fi
        
        log "Cleaning up old local backups for ${domain} (keeping last 7)..."
        ls -tp "${backup_dir}"/full_backup_*.tar.gz | tail -n +8 | xargs -d '\n' rm -f --
    done
    log "--- All-Sites Scheduled Backup Complete ---"
}

clone_to_staging() {
    clear; echo -e "${BLUE}--- Clone Site to Staging ---${NC}\n"
    local domain
    domain=$(select_site)
    [[ -z "$domain" ]] && return
    
    local staging_domain="staging.${domain}"
    local site_dir="${WEBROOT}/${domain}"
    local staging_dir="${WEBROOT}/${staging_domain}"
    
    if [ -d "$staging_dir" ]; then
        warn "Staging site ${staging_domain} already exists."
        read -p "Delete existing staging site and re-clone? (y/n): " -n 1 -r; echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then warn "Cloning aborted."; return; fi
        bash "${SCRIPT_PATH}" remove-site-silent "$staging_domain"
    fi
    
    log "Cloning files from ${domain} to ${staging_domain}..."
    sudo cp -a "$site_dir" "$staging_dir"
    
    log "Cloning database..."
    local db_name
    db_name=$(sudo -u www-data wp config get DB_NAME --path="$site_dir" --quiet)
    local staging_db_name="${db_name}_staging"
    
    mysql --defaults-file="$HOME/.my.cnf" -e "CREATE DATABASE \`${staging_db_name}\`;"
    mysqldump --defaults-file="$HOME/.my.cnf" "${db_name}" | mysql --defaults-file="$HOME/.my.cnf" "${staging_db_name}"
    
    log "Configuring staging site..."
    sudo -u www-data wp config set DB_NAME "$staging_db_name" --path="$staging_dir"
    
    log "Running search-replace on staging database..."
    sudo -u www-data wp search-replace "https://${domain}" "https://${staging_domain}" --all-tables --path="$staging_dir"
    
    log "Setting up server configuration for staging site..."
    create_php_pool "$staging_domain"
    configure_nginx_site "$staging_domain" "false"
    
    log "Requesting SSL for staging site..."
    if ! sudo certbot --nginx --hsts -d "$staging_domain" --non-interactive --agree-tos -m "$ADMIN_EMAIL" --redirect; then
        warn "SSL for staging failed. Check DNS for staging.${domain}."
    fi
    
    log "Adding 'noindex' to staging site..."
    sudo -u www-data wp option update blog_public 0 --path="$staging_dir"
    
    success "Staging site created at https://${staging_domain}"
}

site_toolkit() {
    clear; echo -e "${BLUE}--- Site Toolkit (WP-CLI) ---${NC}\n"
    local domain
    domain=$(select_site)
    [[ -z "$domain" ]] && return
    local site_dir="${WEBROOT}/${domain}"
    
    while true; do
        echo -e "\nToolkit for: ${YELLOW}${domain}${NC}"
        echo "1) User Management (List Users)"
        echo "2) Database Management (Optimize)"
        echo "3) Cron Management (List Events)"
        echo "4) Site Health Check"
        echo "5) Return to Main Menu"
        read -p "Enter choice: " choice
        
        case "$choice" in
            1) sudo -u www-data wp user list --path="$site_dir";;
            2) sudo -u www-data wp db optimize --path="$site_dir";;
            3) sudo -u www-data wp cron event list --path="$site_dir";;
            4) sudo -u www-data wp site health check --format=json --path="$site_dir" | tee /tmp/health.json && cat /tmp/health.json;;
            5) break;;
            *) warn "Invalid choice.";;
        esac
        read -n 1 -s -r -p "Press any key to continue..."
    done
}

manage_debugging() {
    clear; echo -e "${BLUE}--- Debugging Tools ---${NC}\n"
    local domain
    domain=$(select_site)
    [[ -z "$domain" ]] && return
    local site_dir="${WEBROOT}/${domain}"
    
    while true; do
        echo -e "\nDebugging for: ${YELLOW}${domain}${NC}"
        local debug_status
        if sudo -u www-data wp config get WP_DEBUG --path="$site_dir" --quiet; then
            debug_status="ON"
        else
            debug_status="OFF"
        fi
        echo "WP_DEBUG is currently: ${debug_status}"
        echo "1) Toggle WP_DEBUG"
        echo "2) View Debug Log (tail -f)"
        echo "3) Return to Main Menu"
        read -p "Enter choice: " choice
        
        case "$choice" in
            1)
                if [[ "$debug_status" == "ON" ]]; then
                    sudo -u www-data wp config set WP_DEBUG false --raw --path="$site_dir"
                    sudo -u www-data wp config set WP_DEBUG_LOG false --raw --path="$site_dir"
                    sudo -u www-data wp config set WP_DEBUG_DISPLAY false --raw --path="$site_dir"
                else
                    sudo -u www-data wp config set WP_DEBUG true --raw --path="$site_dir"
                    sudo -u www-data wp config set WP_DEBUG_LOG true --raw --path="$site_dir"
                    sudo -u www-data wp config set WP_DEBUG_DISPLAY false --raw --path="$site_dir"
                fi
                success "Debug status toggled."
                ;;
            2)
                log "Tailing ${site_dir}/wp-content/debug.log. Press Ctrl+C to exit."
                sudo tail -f "${site_dir}/wp-content/debug.log"
                ;;
            3) break;;
            *) warn "Invalid choice.";;
        esac
    done
}

save_credentials() {
    local domain=$1 admin_user=$2 admin_pass=$3 db_name=$4 db_user=$5 db_pass=$6
    
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

main_menu() {
    while true; do
        clear
        echo -e "${BLUE}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}"
        echo -e "${BLUE}▓                                                                ▓${NC}"
        echo -e "${BLUE}▓            WordPress Ultimate Operations (WOO) Toolkit           ▓${NC}"
        echo -e "${BLUE}▓                                                                ▓${NC}"
        echo -e "${BLUE}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}\n"
        echo "  1) List Managed Sites"
        echo "  2) Add New Site (Standard or Multisite)"
        echo "  3) Remove Existing Site"
        echo "  4) Manage Site Caching"
        echo "  5) Manage XML-RPC Access (Odoo Whitelist)"
        echo "  6) Backup Management"
        echo "  7) Clone Site to Staging"
        echo "  8) Site Toolkit (WP-CLI)"
        echo "  9) Debugging Tools"
        echo " 10) Setup SSH Multi-Factor Authentication (MFA)"
        echo " 11) Exit"
        
        read -p "Enter your choice: " choice
        
        case "$choice" in
            1) list_sites ;;
            2) add_site ;;
            3) remove_site ;;
            4) manage_caching ;;
            5) manage_xmlrpc ;;
            6) manage_backups ;;
            7) clone_to_staging ;;
            8) site_toolkit ;;
            9) manage_debugging ;;
            10) sudo apt-get install -y libpam-google-authenticator && google-authenticator ;;
            11) echo "Exiting WOO Toolkit. Goodbye!"; exit 0 ;;
            *) warn "Invalid option. Please try again." ;;
        esac
        echo -e "\nPress any key to return to the menu..."
        read -n 1 -s
    done
}

remove_site_silent() {
    local domain="$1"
    local site_dir="${WEBROOT}/${domain}"
    local db_name db_user
    
    if [ -f "${site_dir}/wp-config.php" ]; then
        db_name=$(grep "DB_NAME" "${site_dir}/wp-config.php" | cut -d \' -f 4)
        db_user=$(grep "DB_USER" "${site_dir}/wp-config.php" | cut -d \' -f 4)
    fi
    
    sudo rm -f "/etc/nginx/sites-available/${domain}" "/etc/nginx/sites-enabled/${domain}"
    sudo rm -f "/etc/php/${PHP_VERSION}/fpm/pool.d/${domain}.conf"
    if [[ -n "$db_name" ]]; then
        mysql --defaults-file="$HOME/.my.cnf" -e "DROP DATABASE IF EXISTS \`${db_name}\`; DROP USER IF EXISTS '${db_user}'@'localhost';"
    fi
    sudo rm -rf "$site_dir"
    sudo systemctl reload nginx php${PHP_VERSION}-fpm
}

main() {
    if [[ "$1" == "backup-all" ]]; then
        backup_all_sites
        exit 0
    fi

    if [[ "$1" == "remove-site-silent" && -n "$2" ]]; then
        remove_site_silent "$2"
        exit 0
    fi

    check_user

    if [ ! -f "$HOME/.my.cnf" ]; then
        clear
        echo -e "${GREEN}--- Initial Server Setup for WOO Toolkit ---${NC}\n"
        warn "This appears to be the first run. The script will now set up and secure the server."
        read -p "Press Enter to begin the one-time setup..."
        
        analyze_system
        install_dependencies
        secure_mysql
        configure_tuned_mariadb
        harden_server
        
        echo -e "\n${GREEN}Initial server setup is complete!${NC}"
        read -p "Enter a valid email address for SSL certificates and admin notifications: " ADMIN_EMAIL
        setup_alias
    fi

    main_menu
}

main "$@"
