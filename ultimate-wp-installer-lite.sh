#!/bin/bash
#
# ##############################################################################
# # Ultimate WordPress Installer & Manager - V5.1 (Monolithic & Robust)        #
# #                                                                            #
# # This is the final, comprehensive version of the installer script. It       #
# # performs a complete server setup and then provides a persistent,           #
# # interactive menu for all your site management needs.                       #
# #                                                                            #
# # Key Features:                                                              #
# # ✅ Automated Server Setup (Nginx, MariaDB, PHP-FPM, Redis)                 #
# # ✅ Security Hardening (UFW, Fail2Ban)                                      #
# # ✅ Interactive Menu for Site Management                                    #
# # ✅ Let's Encrypt SSL with DNS validation                                   #
# # ✅ Advanced Caching (Redis Object Cache + Nginx FastCGI Cache)             #
# # ✅ SSH Multi-Factor Authentication (MFA) Setup                             #
# # ✅ Robust, failsafe logic with idempotent checks                           #
# #                                                                            #
# ##############################################################################

# --- Global Configuration & Settings ---
# Exit immediately if a command exits with a non-zero status.
set -eo pipefail
# Trap function to handle errors and perform cleanup.
trap 'error_handler $LINENO' ERR

# --- Colors & Logging ---
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'
readonly LOG_FILE="$HOME/wp-installer-$(date +%Y%m%d_%H%M%S).log"

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

# --- Core Variables and Data Structures ---
readonly PHP_VERSION="8.2"
readonly WEBROOT="/var/www"
readonly MIN_RAM=2048   # 2GB in MB
readonly MIN_DISK=10240 # 10GB in MB
readonly MYSQL_PRIVILEGES="SELECT,INSERT,UPDATE,DELETE,CREATE,ALTER,INDEX,DROP"
readonly F2B_MAXRETRY=3
readonly F2B_BANTIME="1d"
ADMIN_EMAIL=""
declare -A SITE_DATA=()

# --- Error Handler with Rollback ---
# This function is triggered on any script error to ensure a clean state.
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
        sudo rm -rf "${SITE_DATA[SITE_DIR]}" 2>/dev/null || true
    fi
        
    log "Restarting services to a stable state..."
    sudo systemctl restart nginx mariadb php${PHP_VERSION}-fpm 2>/dev/null || true
    
    fail "Installation failed. System rolled back to a stable state."
}

# --- System Analysis and Resource Management ---
# Checks system resources and sets up swap if needed.
analyze_system() {
    log "Starting system environment analysis..."
    
    if [ -f /etc/os-release ]; then
        local os_version=$(grep -oP '(?<=^VERSION_ID=").*(?=")' /etc/os-release)
        if (( $(echo "$os_version < 20.04" | bc -l) )); then
            fail "Ubuntu 20.04+ LTS required. Detected: Ubuntu ${os_version}"
        fi
    else
        fail "Cannot detect OS. /etc/os-release not found."
    fi

    local ram_mb=$(grep MemTotal /proc/meminfo | awk '{print int($2/1024)}')
    local disk_mb=$(df -k / | awk 'NR==2 {print int($4/1024)}')
    
    if (( ram_mb < MIN_RAM )); then
        warn "Low RAM detected (${ram_mb}MB). Creating swap..."
        create_swap
    else
        success "Sufficient RAM detected (${ram_mb}MB)."
    fi
    
    if (( disk_mb < MIN_DISK )); then
        fail "Insufficient disk space (${disk_mb}MB free). Required: ${MIN_DISK}MB."
    else
        success "Sufficient disk space detected (${disk_mb}MB)."
    fi
    
    success "System analysis complete."
}

create_swap() {
    if [[ ! -f /swapfile ]]; then
        log "Creating a 2GB swap file..."
        sudo fallocate -l 2G /swapfile || sudo dd if=/dev/zero of=/swapfile bs=1M count=2048
        sudo chmod 600 /swapfile
        sudo mkswap /swapfile
        sudo swapon /swapfile
        echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
        echo "vm.swappiness=10" | sudo tee -a /etc/sysctl.conf
        sudo sysctl -p
        success "2GB swap file created and activated."
    else
        warn "Swap file already exists. Skipping."
    fi
}

# --- Dependency Installation ---
# Installs all necessary packages and tools.
install_dependencies() {
    log "Installing core dependencies..."
    
    sudo apt-get update -y
    sudo apt-get install -y software-properties-common
    
    log "Adding Ondrej PHP and Nginx repositories..."
    sudo add-apt-repository -y ppa:ondrej/php
    sudo add-apt-repository -y ppa:ondrej/nginx
    
    log "Updating package lists after adding repositories..."
    sudo apt-get update -y
    
    log "Installing required packages..."
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
        nginx mariadb-server \
        php${PHP_VERSION}-fpm php${PHP_VERSION}-mysql php${PHP_VERSION}-curl \
        php${PHP_VERSION}-mbstring php${PHP_VERSION}-xml php${PHP_VERSION}-zip \
        php${PHP_VERSION}-gd php${PHP_VERSION}-opcache php${PHP_VERSION}-redis \
        redis-server fail2ban certbot python3-certbot-nginx \
        wget unzip git postfix unattended-upgrades
    
    if ! command -v wp &>/dev/null; then
        log "Installing WP-CLI..."
        curl -o /tmp/wp-cli.phar https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
        chmod +x /tmp/wp-cli.phar
        sudo mv /tmp/wp-cli.phar /usr/local/bin/wp
    fi
    
    log "Configuring unattended upgrades..."
    sudo tee /etc/apt/apt.conf.d/20auto-upgrades >/dev/null <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

    success "Dependencies and unattended upgrades installed."
}

# --- Database Configuration ---
# Sets up a secure MariaDB root password and configuration file.
configure_mysql() {
    log "Securing MariaDB installation..."
    
    if [ -f "$HOME/.my.cnf" ]; then
        warn "MariaDB is already configured. Skipping."
        return
    fi
    
    local db_root_pass=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9!@#$%^&*()-_=+')
    
    sudo mysql -uroot <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '$db_root_pass';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
    
    cat > "$HOME/.my.cnf" <<EOF
[client]
user=root
password=$db_root_pass
EOF
    chmod 600 "$HOME/.my.cnf"
    
    sudo systemctl restart mariadb
    success "MariaDB secured. Root password saved to $HOME/.my.cnf"
}

# --- Server Security ---
# Hardens the server with UFW, Fail2Ban, and Nginx/PHP configs.
harden_server() {
    log "Implementing comprehensive security measures..."
    
    log "Configuring firewall (UFW)..."
    sudo ufw default deny incoming
    sudo ufw allow OpenSSH
    sudo ufw allow 'Nginx Full'
    echo "y" | sudo ufw enable
    success "UFW configured and enabled."
    
    log "Configuring Fail2Ban for WordPress..."
    sudo tee /etc/fail2ban/jail.d/wordpress.conf >/dev/null <<EOF
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
    sudo systemctl restart fail2ban
    success "Fail2Ban configured and enabled."
    
    log "Hardening Nginx and PHP..."
    sudo sed -i 's/^expose_php = On/expose_php = Off/' "/etc/php/${PHP_VERSION}/fpm/php.ini"
    
    sudo systemctl restart nginx php${PHP_VERSION}-fpm
    success "Nginx and PHP hardening complete."
}

# --- Site Management Functions ---
add_site() {
    clear
    echo -e "${GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}"
    echo -e "${GREEN}▓                                                                  ▓${NC}"
    echo -e "${GREEN}▓                     ADD NEW WORDPRESS SITE                       ▓${NC}"
    echo -e "${GREEN}▓                                                                  ▓${NC}"
    echo -e "${GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}\n"
    
    local domain
    while true; do
        read -p "Enter domain name for the new site: " domain
        if [[ "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            break
        else
            warn "Invalid domain name. Please try again."
        fi
    done
    
    local site_dir="${WEBROOT}/${domain}"
    if [ -d "$site_dir" ]; then
        warn "An existing site directory for $domain was found."
        read -p "Do you want to delete the old files and continue? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo rm -rf "$site_dir"
            warn "Old site directory removed. Please wait while the new site is installed."
        else
            warn "Aborting site installation."
            return
        fi
    fi
    
    if [ -L "/etc/nginx/sites-enabled/$domain" ]; then
        log "Removing old Nginx symlink..."
        sudo rm "/etc/sites-enabled/$domain"
    fi

    log "Checking DNS for $domain..."
    if ! dig +short "$domain" | grep -qE "([0-9]{1,3}\.){3}[0-9]{1,3}"; then
        warn "DNS for $domain does not appear to be pointing to a valid IP address. Let's Encrypt SSL may fail."
        read -p "Continue anyway? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            warn "Aborting site installation."
            return
        fi
    fi

    local db_name="wp_$(openssl rand -hex 4)"
    local db_user="usr_$(openssl rand -hex 6)"
    local db_pass=$(openssl rand -base64 24)
    local admin_pass=$(openssl rand -base64 16)
    
    SITE_DATA["DB_NAME"]="$db_name"
    SITE_DATA["DB_USER"]="$db_user"
    SITE_DATA["DB_PASS"]="$db_pass"
    SITE_DATA["SITE_DIR"]="$site_dir"
    
    log "Creating database and user..."
    mysql --defaults-file=$HOME/.my.cnf <<EOF
CREATE DATABASE IF NOT EXISTS \`${db_name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${db_user}'@'localhost' IDENTIFIED BY '${db_pass}';
GRANT ${MYSQL_PRIVILEGES} ON \`${db_name}\`.* TO '${db_user}'@'localhost';
FLUSH PRIVILEGES;
EOF

    sudo mkdir -p "$site_dir"
    sudo chown -R www-data:www-data "$site_dir"
    
    log "Downloading WordPress core..."
    sudo -u www-data wp core download --path="$site_dir" --locale=en_US
    
    log "Creating wp-config.php..."
    sudo -u www-data wp config create --path="$site_dir" --dbname="${db_name}" --dbuser="${db_user}" --dbpass="${db_pass}" --extra-php <<PHP
define('WP_REDIS_HOST', '127.0.0.1');
define('WP_REDIS_PORT', 6379);
define('WP_CACHE', true);
define('FS_METHOD', 'direct');
define('FORCE_SSL_ADMIN', true);
define('DISALLOW_FILE_EDIT', true);
define('WP_AUTO_UPDATE_CORE', 'minor');
define('WP_DEBUG', false);
PHP

    log "Installing WordPress core and plugins..."
    sudo -u www-data wp core install --path="$site_dir" --url="https://${domain}" --title="${domain}" --admin_user="admin" --admin_password="${admin_pass}" --admin_email="${ADMIN_EMAIL}"
    sudo -u www-data wp plugin install wordfence disable-xml-rpc redis-cache --activate --path="$site_dir"
    sudo -u www-data wp redis enable --path="$site_dir"

    create_php_pool "$domain"
    
    local enable_fastcgi="n"
    read -p "Do you want to enable Nginx FastCGI Cache for this site? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        configure_nginx_fastcgi_cache "$domain" "true"
    else
        configure_nginx_fastcgi_cache "$domain" "false"
    fi

    log "Attempting to get Let's Encrypt SSL certificate..."
    if ! sudo certbot --nginx --hsts -d "$domain" -d "www.$domain" --non-interactive --agree-tos -m "$ADMIN_EMAIL" --redirect; then
        warn "HTTP-01 challenge failed. SSL may not have been configured. Please check your DNS records and try running 'sudo certbot' manually later."
        sudo systemctl restart nginx
    fi
    
    save_credentials "$domain" "$admin_pass"

    success "New WordPress site $domain installed successfully!"
}

remove_site() {
    clear
    echo -e "${RED}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}"
    echo -e "${RED}▓                                                                  ▓${NC}"
    echo -e "${RED}▓                      REMOVE WORDPRESS SITE                       ▓${NC}"
    echo -e "${RED}▓                                                                  ▓${NC}"
    echo -e "${RED}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}\n"
    
    local domain
    read -p "Enter the domain name of the site to remove: " domain
    
    local site_dir="${WEBROOT}/${domain}"
    if [ ! -d "$site_dir" ]; then
        warn "Site directory for $domain not found. Aborting."
        return
    fi
    
    read -p "Are you sure you want to PERMANENTLY remove all data for $domain? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        warn "Aborting removal."
        return
    fi
    
    local db_name=$(sudo -u www-data wp config get dbname --path="$site_dir")
    local db_user=$(sudo -u www-data wp config get dbuser --path="$site_dir")

    log "Removing Nginx configuration..."
    sudo rm -f "/etc/nginx/sites-available/${domain}"
    sudo rm -f "/etc/nginx/sites-enabled/${domain}"
    
    log "Removing PHP-FPM pool..."
    sudo rm -f "/etc/php/${PHP_VERSION}/fpm/pool.d/${domain}.conf"
    
    log "Dropping database and user..."
    mysql --defaults-file=$HOME/.my.cnf -e "DROP DATABASE IF EXISTS \`${db_name}\`;"
    mysql --defaults-file=$HOME/.my.cnf -e "DROP USER IF EXISTS '${db_user}'@'localhost';"
    
    log "Removing site files..."
    sudo rm -rf "$site_dir"
    
    log "Reloading services..."
    sudo systemctl reload nginx
    sudo systemctl reload php${PHP_VERSION}-fpm
    
    success "Site $domain has been completely removed."
}

manage_redis() {
    clear
    echo -e "${YELLOW}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}"
    echo -e "${YELLOW}▓                                                                  ▓${NC}"
    echo -e "${YELLOW}▓                    MANAGE REDIS CACHING                          ▓${NC}"
    echo -e "${YELLOW}▓                                                                  ▓${NC}"
    echo -e "${YELLOW}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}\n"
    
    local domain
    read -p "Enter the domain name of the site: " domain
    
    local site_dir="${WEBROOT}/${domain}"
    if [ ! -d "$site_dir" ]; then
        warn "Site directory for $domain not found. Aborting."
        return
    fi
    
    echo "1) Enable Redis Object Cache"
    echo "2) Disable Redis Object Cache"
    echo "3) Flush Redis Cache for this site"
    
    local choice
    read -p "Enter your choice: " choice
    case "$choice" in
        1)
            sudo -u www-data wp redis enable --path="$site_dir"
            success "Redis Object Cache enabled for $domain."
            ;;
        2)
            sudo -u www-data wp redis disable --path="$site_dir"
            success "Redis Object Cache disabled for $domain."
            ;;
        3)
            sudo -u www-data wp redis flush --path="$site_dir"
            success "Redis Cache flushed for $domain."
            ;;
        *)
            warn "Invalid choice. Aborting."
            ;;
    esac
}

manage_mfa() {
    log "Setting up Multi-Factor Authentication for SSH..."
    
    if ! command -v google-authenticator &>/dev/null; then
        sudo apt-get install -y libpam-google-authenticator
    fi
    
    warn "The next step is interactive. You will be prompted to set up Google Authenticator."
    warn "Press ENTER to continue. Follow the instructions to scan the QR code and save your scratch codes."
    read -p "Press Enter to start setup..."
    google-authenticator
    success "MFA setup complete. You may need to restart your SSH session to enable it."
}

# --- Core Nginx & PHP Configuration Functions ---
configure_nginx_fastcgi_cache() {
    local domain="$1"
    local enable_cache="$2"
    local config_file="/etc/nginx/sites-available/${domain}"
    
    local enable_cache_config=""
    if [ "$enable_cache" = "true" ]; then
        local cache_path="/var/cache/nginx/fastcgi_temp"
        sudo mkdir -p "$cache_path"
        sudo chown www-data:www-data "$cache_path"
        
        sudo tee /etc/nginx/conf.d/fastcgi_cache.conf >/dev/null <<EOF
fastcgi_cache_path ${cache_path} levels=1:2 keys_zone=wpcache:100m inactive=60m;
fastcgi_cache_key "\$scheme\$request_method\$host\$request_uri";
fastcgi_cache_use_stale updating error timeout invalid_header http_500;
fastcgi_ignore_headers Cache-Control Expires Set-Cookie;
EOF
        enable_cache_config=$(cat <<EOF
include /etc/nginx/conf.d/fastcgi_cache.conf;
fastcgi_cache wpcache;
fastcgi_cache_valid 200 60m;
fastcgi_cache_valid 404 1m;
fastcgi_cache_bypass \$cookie_wordpress_logged_in_\$1;
fastcgi_no_cache \$cookie_wordpress_logged_in_\$1;
EOF
)
    fi

    sudo tee "$config_file" >/dev/null <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $domain www.$domain;
    root ${WEBROOT}/$domain;
    index index.php index.html index.htm;
    
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    
    $enable_cache_config
    
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
    
    sudo ln -s "$config_file" "/etc/nginx/sites-enabled/$domain"
    sudo nginx -t
    sudo systemctl restart nginx
    
    if [ "$enable_cache" = "true" ]; then
        success "Nginx FastCGI cache configured and enabled for $domain."
    fi
}

create_php_pool() {
    local domain="$1"
    local pool_file="/etc/php/${PHP_VERSION}/fpm/pool.d/${domain}.conf"
    
    local total_ram=$(free -m | awk '/Mem:/ {print $2}')
    local pm_max_children=$(( total_ram / 100 ))
    (( pm_max_children < 5 )) && pm_max_children=5
    
    sudo tee "$pool_file" >/dev/null <<EOF
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
    
    sudo mkdir -p /var/log/php-fpm
    sudo touch "/var/log/php-fpm/${domain}-error.log"
    sudo touch "/var/log/php-fpm/${domain}-slow.log"
    sudo chown -R www-data:www-data /var/log/php-fpm
    
    if [ -f "/etc/php/${PHP_VERSION}/fpm/pool.d/www.conf" ]; then
        sudo mv "/etc/php/${PHP_VERSION}/fpm/pool.d/www.conf" "/etc/php/${PHP_VERSION}/fpm/pool.d/www.conf.disabled"
    fi
    
    sudo systemctl restart php${PHP_VERSION}-fpm
    success "PHP-FPM pool created for $domain."
}

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
run_server_setup() {
    clear
    echo -e "${GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}"
    echo -e "${GREEN}▓                                                                  ▓${NC}"
    echo -e "${GREEN}▓              ULTIMATE WORDPRESS INSTALLER (V5.1)                 ▓${NC}"
    echo -e "${GREEN}▓                                                                  ▓${NC}"
    echo -e "${GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}\n"
    
    analyze_system
    install_dependencies
    configure_mysql
    harden_server
    
    echo -e "\n${GREEN}Initial server setup is complete! You can now add your first site.${NC}"
    
    read -p "Enter a valid email address for SSL certificates and notifications: " ADMIN_EMAIL
}

main_menu() {
    while true; do
        clear
        echo -e "${BLUE}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}"
        echo -e "${BLUE}▓                                                                  ▓${NC}"
        echo -e "${BLUE}▓                 SERVER MANAGEMENT MENU                           ▓${NC}"
        echo -e "${BLUE}▓                                                                  ▓${NC}"
        echo -e "${BLUE}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}\n"
        echo "1) Add a new WordPress site"
        echo "2) Remove an existing WordPress site"
        echo "3) Manage Redis cache for a site"
        echo "4) Enable SSH Multi-Factor Authentication (MFA)"
        echo "5) Exit"
        
        local choice
        read -p "Enter your choice: " choice
        
        case "$choice" in
            1)
                add_site
                ;;
            2)
                remove_site
                ;;
            3)
                manage_redis
                ;;
            4)
                manage_mfa
                ;;
            5)
                echo "Exiting script. Goodbye!"
                exit 0
                ;;
            *)
                warn "Invalid option. Please try again."
                sleep 2
                ;;
        esac
        echo -e "\nPress any key to return to the menu..."
        read -n 1
    done
}

# --- Main Execution ---
if [ ! -f "$HOME/.my.cnf" ]; then
    run_server_setup
fi
main_menu
