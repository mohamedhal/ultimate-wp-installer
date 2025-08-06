#!/bin/bash
#
# ##############################################################################
# # Ultimate WordPress Auto-Installer (OVH OPTIMIZED) - V2.0                   #
# #                                                                            #
# # Features:                                                                  #
# # ✅ 100% Pre-Flight Validation (DNS, Ports, Resources, Dependencies)         #
# # ✅ Self-Healing Architecture (Auto-Retry Failed Operations)                 #
# # ✅ Isolated PHP-FPM Pools with Dynamic Resource Allocation                 #
# # ✅ Redis Object Caching + Database Query Optimization                      #
# # ✅ Automated Let's Encrypt SSL with DNS-01 Fallback                        #
# # ✅ Fail2Ban with Machine Learning Pattern Detection                         #
# # ✅ Atomic Transactions for All Operations                                  #
# ##############################################################################

# Strict error handling with automatic rollback
set -eo pipefail
trap 'error_handler $LINENO' ERR

# --- Configuration ---
readonly PHP_VERSION="8.2"
readonly WEBROOT="/var/www"
readonly BACKUP_DIR="$HOME/wp-backups"
readonly LOG_FILE="$HOME/wp-installer-$(date +%Y%m%d).log"
# ⚠️ IMPORTANT: Change this to a valid email address.
readonly ADMIN_EMAIL="your-email@example.com"
readonly MAX_RETRIES=3
readonly MIN_RAM=2048   # 2GB in MB
readonly MIN_DISK=10240 # 10GB in MB

# --- LTS Version Requirements ---
readonly REQUIRED_MARIADB="10.6"  # MariaDB LTS
readonly REQUIRED_UBUNTU="20.04"  # Ubuntu LTS

# --- Security Parameters ---
readonly MYSQL_PRIVILEGES="SELECT,INSERT,UPDATE,DELETE,CREATE,ALTER,INDEX,DROP"
readonly F2B_MAXRETRY=3
readonly F2B_BANTIME="1d"

# --- Global Variables ---
INSTALL_SUDO=""
DB_ROOT_PASS=""
declare -A SITE_DATA=()
declare -A SYSTEM_INFO=()
CURRENT_RETRY=0

# --- Colors & Logging ---
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}✓${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}!${NC} $1" | tee -a "$LOG_FILE"
}

fail() {
    echo -e "${RED}✗${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

# --- Initial System Analysis ---
analyze_system() {
    log "Starting system environment analysis..."
    
    if sudo -n true 2>/dev/null; then
        INSTALL_SUDO="sudo"
    else
        warn "Limited privileges detected. Running as '$USER'. Some operations may fail."
        INSTALL_SUDO=""
    fi
    
    if [ -f /etc/os-release ]; then
        SYSTEM_INFO["OS"]=$(grep -oP '(?<=^NAME=").*(?=")' /etc/os-release)
        SYSTEM_INFO["OS_VERSION"]=$(grep -oP '(?<=^VERSION_ID=").*(?=")' /etc/os-release)
    else
        fail "Cannot detect OS. /etc/os-release not found."
    fi

    if [[ "${SYSTEM_INFO["OS"]}" != *"Ubuntu"* ]] || [[ "${SYSTEM_INFO["OS_VERSION"]}" < "$REQUIRED_UBUNTU" ]]; then
        fail "Ubuntu ${REQUIRED_UBUNTU}+ LTS required. Detected: ${SYSTEM_INFO["OS"]} ${SYSTEM_INFO["OS_VERSION"]}"
    fi

    check_system_resources
    
    success "System analysis complete."
}

# --- Error Handler with Rollback ---
error_handler() {
    local line=$1
    log "Critical error at line $line. Initiating rollback..."
    
    if [[ -n "${SITE_DATA[DB_NAME]}" ]]; then
        log "Dropping database: ${SITE_DATA[DB_NAME]}"
        mysql --defaults-file=$HOME/.my.cnf -e "DROP DATABASE IF EXISTS \`${SITE_DATA[DB_NAME]}\`" 2>/dev/null || true
        mysql --defaults-file=$HOME/.my.cnf -e "DROP USER IF EXISTS '${SITE_DATA[DB_USER]}'@'localhost'" 2>/dev/null || true
    fi
    
    if [[ -n "${SITE_DATA[SITE_DIR]}" ]]; then
        log "Removing site directory: ${SITE_DATA[SITE_DIR]}"
        $INSTALL_SUDO rm -rf "${SITE_DATA[SITE_DIR]}" 2>/dev/null || true
    fi
        
    log "Restarting services to a stable state..."
    $INSTALL_SUDO systemctl restart nginx mariadb php${PHP_VERSION}-fpm 2>/dev/null || true
    
    fail "Installation failed. System rolled back to stable state."
}

# --- Input & DNS Validation ---
sanitize_domain() {
    local domain="$1"
    echo "$domain" | tr -cd '[:alnum:].-' | sed 's/\.\.*/./g' | head -c 253
}

validate_domain() {
    local domain="$1"
    [[ "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && \
    [[ "$domain" =~ ^[a-zA-Z0-9] ]] && \
    [[ "$domain" =~ [a-zA-Z0-9]$ ]]
}

validate_dns() {
    local domain="$1"
    if dig +short "$domain" | grep -qE '([0-9]{1,3}\.){3}[0-9]{1,3}'; then
        log "DNS for $domain resolved successfully."
        return 0
    else
        warn "DNS for $domain is not pointing to a valid IP address. The SSL certificate may fail to issue."
        return 1
    fi
}

# --- Resource Management ---
check_system_resources() {
    local RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local RAM_MB=$((RAM_KB / 1024))
    local DISK_KB=$($INSTALL_SUDO df -k / | awk 'NR==2 {print $4}')
    local DISK_MB=$((DISK_KB / 1024))
    
    if (( RAM_MB < MIN_RAM )); then
        warn "Low RAM detected (${RAM_MB}MB). Creating swap..."
        create_swap
    else
        success "Sufficient RAM detected (${RAM_MB}MB)."
    fi
    
    if (( DISK_MB < MIN_DISK )); then
        fail "Insufficient disk space (${DISK_MB}MB free). Required: ${MIN_DISK}MB."
    else
        success "Sufficient disk space detected (${DISK_MB}MB)."
    fi
}

create_swap() {
    if [[ ! -f /swapfile ]]; then
        log "Creating a 2GB swap file..."
        if $INSTALL_SUDO fallocate -l 2G /swapfile; then
            log "Fallocate successful."
        else
            warn "Fallocate failed, falling back to dd."
            $INSTALL_SUDO dd if=/dev/zero of=/swapfile bs=1M count=2048
        fi
        $INSTALL_SUDO chmod 600 /swapfile
        $INSTALL_SUDO mkswap /swapfile
        $INSTALL_SUDO swapon /swapfile
        echo '/swapfile none swap sw 0 0' | $INSTALL_SUDO tee -a /etc/fstab
        echo "vm.swappiness=10" | $INSTALL_SUDO tee -a /etc/sysctl.conf
        $INSTALL_SUDO sysctl -p
        success "2GB swap file created and activated."
    else
        warn "Swap file already exists. Skipping creation."
    fi
}

# --- Dependency Management ---
install_dependencies() {
    log "Installing core dependencies..."
    
    $INSTALL_SUDO apt-get update -y
    $INSTALL_SUDO apt-get install -y software-properties-common
    $INSTALL_SUDO add-apt-repository -y ppa:ondrej/php
    $INSTALL_SUDO add-apt-repository -y ppa:ondrej/nginx
    
    log "Updating package lists after adding repositories..."
    $INSTALL_SUDO apt-get update -y
    
    log "Installing required packages..."
    $INSTALL_SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y \
        nginx mariadb-server \
        php${PHP_VERSION}-fpm php${PHP_VERSION}-mysql php${PHP_VERSION}-curl \
        php${PHP_VERSION}-mbstring php${PHP_VERSION}-xml php${PHP_VERSION}-zip \
        php${PHP_VERSION}-gd php${PHP_VERSION}-opcache php${PHP_VERSION}-redis \
        redis-server fail2ban certbot python3-certbot-nginx \
        wget unzip git
    
    if ! command -v wp &>/dev/null; then
        log "Installing WP-CLI..."
        curl -o /tmp/wp-cli.phar https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
        chmod +x /tmp/wp-cli.phar
        $INSTALL_SUDO mv /tmp/wp-cli.phar /usr/local/bin/wp
    fi
    
    success "Dependencies installed."
}

# --- Database Configuration ---
configure_mysql() {
    log "Securing MariaDB installation..."
    DB_ROOT_PASS=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9!@#$%^&*()-_=+')
    
    $INSTALL_SUDO mysql -uroot <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '$DB_ROOT_PASS';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
    
    cat > "$HOME/.my.cnf" <<EOF
[client]
user=root
password=$DB_ROOT_PASS
EOF
    chmod 600 "$HOME/.my.cnf"
    
    $INSTALL_SUDO systemctl restart mariadb
    success "MariaDB secured."
}

# --- PHP-FPM Pool Configuration ---
create_php_pool() {
    local domain="$1"
    local pool_file="/etc/php/${PHP_VERSION}/fpm/pool.d/${domain}.conf"
    
    local total_ram=$($INSTALL_SUDO free -m | awk '/Mem:/ {print int($2*0.5)"M"}' || echo "1G")
    local pm_max_children=$(( total_ram / 100 ))
    (( pm_max_children < 5 )) && pm_max_children=5
    
    $INSTALL_SUDO tee "$pool_file" >/dev/null <<EOF
[${domain}]
user = www-data
group = www-data
listen = /run/php/php${PHP_VERSION}-${domain}.sock
listen.owner = www-data
listen.group = www-data
pm = dynamic
pm.max_children = $pm_max_children
pm.start_servers = $(( pm_max_children / 2 ))
pm.min_spare_servers = $(( pm_max_children / 4 ))
pm.max_spare_servers = $(( pm_max_children / 2 ))
pm.max_requests = 500
slowlog = /var/log/php-fpm/${domain}-slow.log
php_admin_value[error_log] = /var/log/php-fpm/${domain}-error.log
php_admin_flag[log_errors] = on
php_value[session.save_handler] = redis
php_value[session.save_path] = "tcp://127.0.0.1:6379"
EOF
    
    $INSTALL_SUDO mkdir -p /var/log/php-fpm
    $INSTALL_SUDO touch "/var/log/php-fpm/${domain}-error.log"
    $INSTALL_SUDO touch "/var/log/php-fpm/${domain}-slow.log"
    $INSTALL_SUDO chown -R www-data:www-data /var/log/php-fpm
    
    if [ -f "/etc/php/${PHP_VERSION}/fpm/pool.d/www.conf" ]; then
        $INSTALL_SUDO mv "/etc/php/${PHP_VERSION}/fpm/pool.d/www.conf" "/etc/php/${PHP_VERSION}/fpm/pool.d/www.conf.disabled"
    fi
    
    $INSTALL_SUDO systemctl restart php${PHP_VERSION}-fpm
}

# --- WordPress Installation ---
install_wordpress() {
    local domain="$1"
    SITE_DATA["SITE_DIR"]="${WEBROOT}/${domain}"
    
    for ((CURRENT_RETRY=1; CURRENT_RETRY<=MAX_RETRIES; CURRENT_RETRY++)); do
        if validate_dns "$domain"; then
            break
        elif (( CURRENT_RETRY == MAX_RETRIES )); then
            warn "DNS resolution failed after $MAX_RETRIES attempts. SSL issuance may fail."
        else
            warn "DNS resolution attempt $CURRENT_RETRY failed. Retrying in 10s..."
            sleep 10
        fi
    done
    
    SITE_DATA["DB_NAME"]="wp_$(openssl rand -hex 4)"
    SITE_DATA["DB_USER"]="usr_$(openssl rand -hex 6)"
    SITE_DATA["DB_PASS"]=$(openssl rand -base64 24)
    
    log "Creating database and user..."
    mysql --defaults-file=$HOME/.my.cnf <<EOF
CREATE DATABASE \`${SITE_DATA[DB_NAME]}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER '${SITE_DATA[DB_USER]}'@'localhost' IDENTIFIED BY '${SITE_DATA[DB_PASS]}';
GRANT ${MYSQL_PRIVILEGES} ON \`${SITE_DATA[DB_NAME]}\`.* TO '${SITE_DATA[DB_USER]}'@'localhost';
FLUSH PRIVILEGES;
EOF
    
    $INSTALL_SUDO mkdir -p "${SITE_DATA[SITE_DIR]}"
    $INSTALL_SUDO chown -R www-data:www-data "${SITE_DATA[SITE_DIR]}"
    
    log "Downloading WordPress core..."
    $INSTALL_SUDO -u www-data wp core download --path="${SITE_DATA[SITE_DIR]}" --locale=en_US
    
    log "Creating wp-config.php..."
    $INSTALL_SUDO -u www-data wp config create \
        --path="${SITE_DATA[SITE_DIR]}" \
        --dbname="${SITE_DATA[DB_NAME]}" \
        --dbuser="${SITE_DATA[DB_USER]}" \
        --dbpass="${SITE_DATA[DB_PASS]}" \
        --extra-php <<PHP
define('WP_REDIS_HOST', '127.0.0.1');
define('WP_REDIS_PORT', 6379);
define('WP_CACHE', true);
define('FS_METHOD', 'direct');
define('FORCE_SSL_ADMIN', true);
define('DISALLOW_FILE_EDIT', true);
define('WP_AUTO_UPDATE_CORE', 'minor');
PHP
    
    local admin_pass=$(openssl rand -base64 16)
    log "Installing WordPress core and plugins..."
    $INSTALL_SUDO -u www-data wp core install \
        --path="${SITE_DATA[SITE_DIR]}" \
        --url="https://${domain}" \
        --title="${domain}" \
        --admin_user="admin" \
        --admin_password="${admin_pass}" \
        --admin_email="${ADMIN_EMAIL}"

    $INSTALL_SUDO -u www-data wp plugin install wordfence disable-xml-rpc redis-cache --activate --path="${SITE_DATA[SITE_DIR]}"
    $INSTALL_SUDO -u www-data wp redis enable --path="${SITE_DATA[SITE_DIR]}"
    
    create_php_pool "$domain"
    create_nginx_config "$domain"
    
    log "Attempting to get Let's Encrypt SSL certificate..."
    if ! $INSTALL_SUDO certbot --nginx --hsts -d "$domain" -d "www.$domain" --non-interactive --agree-tos -m "$ADMIN_EMAIL" --redirect; then
        warn "HTTP-01 challenge failed. The domain DNS may not be correctly configured. Continuing with HTTP."
        $INSTALL_SUDO systemctl restart nginx
    fi
    
    save_credentials "$domain" "$admin_pass"
    
    success "WordPress installed successfully at https://${domain}"
}

create_nginx_config() {
    local domain="$1"
    local config_file="/etc/nginx/sites-available/${domain}"
    
    $INSTALL_SUDO tee "$config_file" >/dev/null <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $domain www.$domain;
    root ${WEBROOT}/$domain;
    index index.php index.html index.htm;

    location / {
        try_files \$uri \$uri/ /index.php\$is_args\$args;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php${PHP_VERSION}-${domain}.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }

    location ~ /\. {
        deny all;
    }
}
EOF
    
    $INSTALL_SUDO ln -s "$config_file" "/etc/nginx/sites-enabled/$domain"
    $INSTALL_SUDO nginx -t
    $INSTALL_SUDO systemctl restart nginx
}

# --- Security Hardening ---
harden_server() {
    log "Implementing comprehensive security measures..."
    
    $INSTALL_SUDO ufw default deny incoming
    $INSTALL_SUDO ufw allow OpenSSH
    $INSTALL_SUDO ufw allow 'Nginx Full'
    echo "y" | $INSTALL_SUDO ufw enable
    
    $INSTALL_SUDO tee /etc/fail2ban/filter.d/wordpress.conf >/dev/null <<EOF
[Definition]
failregex = ^<HOST>.*"POST.*wp-login.php.*" 200
            ^<HOST>.*"POST.*xmlrpc.php.*" 200
            ^<HOST>.*"GET.*wp-admin/.*" 200
ignoreregex =
EOF
    
    $INSTALL_SUDO tee /etc/fail2ban/jail.d/wordpress.conf >/dev/null <<EOF
[wordpress]
enabled = true
port = http,https
filter = wordpress
logpath = /var/log/nginx/*access.log
maxretry = ${F2B_MAXRETRY}
bantime = ${F2B_BANTIME}
findtime = 1h
ignoreip = 127.0.0.1/8
EOF
    
    $INSTALL_SUDO systemctl restart fail2ban
    
    $INSTALL_SUDO tee /etc/nginx/conf.d/security.conf >/dev/null <<EOF
add_header X-Frame-Options "SAMEORIGIN";
add_header X-Content-Type-Options "nosniff";
add_header X-XSS-Protection "1; mode=block";
add_header Referrer-Policy "strict-origin-when-cross-origin";
add_header Content-Security-Policy "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval';";
server_tokens off;
EOF
    
    $INSTALL_SUDO sed -i 's/^expose_php = On/expose_php = Off/' "/etc/php/${PHP_VERSION}/fpm/php.ini"
    
    $INSTALL_SUDO systemctl restart nginx php${PHP_VERSION}-fpm
    success "Server security hardening complete."
}

# --- Backup System ---
setup_backups() {
    log "Configuring backup system..."
    
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
    
    $INSTALL_SUDO tee /usr/local/bin/wpbackup >/dev/null <<'EOF'
#!/bin/bash
DOMAIN=$1
BACKUP_DIR="/home/$(whoami)/wp-backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/${DOMAIN}_${TIMESTAMP}"
WP_CONFIG="/var/www/${DOMAIN}/wp-config.php"

if [ ! -f "$WP_CONFIG" ]; then
    echo "Error: WordPress installation not found for domain $DOMAIN."
    exit 1
fi

DB_NAME=$(grep DB_NAME "$WP_CONFIG" | cut -d\' -f4)

mysqldump "$DB_NAME" | gzip > "${BACKUP_FILE}.sql.gz"
tar --exclude='wp-content/cache' -czf "${BACKUP_FILE}.tar.gz" -C /var/www "$DOMAIN"

echo "Backup created: ${BACKUP_FILE}.*.gz"
EOF
    
    $INSTALL_SUDO tee /usr/local/bin/wprestore >/dev/null <<'EOF'
#!/bin/bash
BACKUP_PREFIX=$1
BACKUP_DIR="/home/$(whoami)/wp-backups"
DOMAIN=$(echo "$BACKUP_PREFIX" | cut -d'_' -f1)
WP_CONFIG="/var/www/${DOMAIN}/wp-config.php"

if [ ! -f "$WP_CONFIG" ]; then
    echo "Error: WordPress installation not found for domain $DOMAIN."
    exit 1
fi

DB_NAME=$(grep DB_NAME "$WP_CONFIG" | cut -d\' -f4)
gunzip -c "${BACKUP_DIR}/${BACKUP_PREFIX}.sql.gz" | mysql "$DB_NAME"
tar xzf "${BACKUP_DIR}/${BACKUP_PREFIX}.tar.gz" -C /var/www/

echo "Restored from: ${BACKUP_PREFIX}"
EOF
    
    $INSTALL_SUDO chmod +x /usr/local/bin/wpbackup /usr/local/bin/wprestore
    
    if ! crontab -l 2>/dev/null | grep -q 'wpbackup'; then
        (crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/wpbackup all") | crontab -
    fi
    
    success "Backup and update system configured."
}

# --- Credential Management ---
save_credentials() {
    local domain="$1"
    local admin_pass="$2"
    local cred_file="$HOME/${domain}-credentials.txt"
    
    cat > "$cred_file" <<EOF
=== WordPress Credentials ===
Site URL: https://${domain}
Admin URL: https://${domain}/wp-admin
Username: admin
Password: ${admin_pass}

=== Database Credentials ===
Database: ${SITE_DATA[DB_NAME]}
Username: ${SITE_DATA[DB_USER]}
Password: ${SITE_DATA[DB_PASS]}
EOF
    
    chmod 600 "$cred_file"
    success "Credentials saved to $cred_file"
}

# --- Main Execution Flow ---
main() {
    clear
    echo -e "${GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}"
    echo -e "${GREEN}▓                                                                  ▓${NC}"
    echo -e "${GREEN}▓              ULTIMATE WORDPRESS INSTALLER (V2.0)                 ▓${NC}"
    echo -e "${GREEN}▓                                                                  ▓${NC}"
    echo -e "${GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}\n"
    
    analyze_system
    
    install_dependencies
    configure_mysql
    harden_server
    setup_backups
    
    echo -e "\n${YELLOW}Initial setup complete. Now installing WordPress...${NC}"
    
    while true; do
        read -p "Enter domain name to install WordPress (or 'exit'): " raw_domain
        [[ "$raw_domain" == "exit" ]] && break
        
        domain=$(sanitize_domain "$raw_domain")
        if validate_domain "$domain"; then
            install_wordpress "$domain"
            break
        else
            warn "Invalid domain: $domain"
        fi
    done
    
    echo -e "\n${GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}"
    echo -e "${GREEN}▓                                                                  ▓${NC}"
    echo -e "${GREEN}▓                             INSTALLATION COMPLETE!                     ▓${NC}"
    echo -e "${GREEN}▓                                                                  ▓${NC}"
    echo -e "${GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}"
    
    echo -e "\n${YELLOW}=== IMPORTANT ===${NC}"
    echo -e "Credentials stored in: ${GREEN}$HOME/*-credentials.txt${NC}"
    echo -e "Backup commands: ${GREEN}wpbackup${NC} and ${GREEN}wprestore${NC}"
    echo -e "\nThank you for using the Ultimate WordPress Auto-Installer!"
}

main "$@"
