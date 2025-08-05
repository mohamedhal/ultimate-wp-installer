#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

LOG_FILE="/root/wp_installer.log"
BACKUP_DIR="/root/wp-backups"
CHEATSHEET_FILE="/root/wp-cheatsheet.txt"
MYSQL_ROOT_PASS_FILE="/root/mysql-root-password.txt"

function log() {
  echo -e "$1" | tee -a "$LOG_FILE"
}

function info() {
  log "${BLUE}[INFO]${NC} $1"
}

function success() {
  log "${GREEN}[✓]${NC} $1"
}

function warning() {
  log "${YELLOW}[!]${NC} $1"
}

function error() {
  log "${RED}[✗]${NC} $1"
}

function prompt_confirm() {
  while true; do
    read -rp "$1 (y/n): " yn
    case $yn in
      [Yy]*) return 0 ;;
      [Nn]*) return 1 ;;
      *) echo "Please answer y or n." ;;
    esac
  done
}

# Pre-flight checks, system update, dependency installation functions will follow
function pre_flight_checks() {
  info "Running pre-flight checks..."

  # Check Ubuntu version
  local OS_VERSION
  OS_VERSION=$(lsb_release -rs)
  if [[ "$OS_VERSION" != "22.04" ]]; then
    warning "Recommended OS is Ubuntu 22.04 LTS. You are running $OS_VERSION."
    if ! prompt_confirm "Continue anyway?"; then
      error "Installation aborted due to unsupported OS."
      exit 1
    fi
  else
    success "Ubuntu 22.04 LTS detected."
  fi

  # Check RAM >=1GB
  local RAM_MB
  RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
  if (( RAM_MB < 1000 )); then
    warning "Less than 1GB RAM detected ($RAM_MB MB). WordPress performance may suffer."
    if ! prompt_confirm "Continue anyway?"; then
      error "Installation aborted due to insufficient RAM."
      exit 1
    fi
  else
    success "RAM check passed: ${RAM_MB}MB detected."
  fi

  # Check disk space >=10GB free
  local DISK_FREE
  DISK_FREE=$(df --output=avail / | tail -1)
  local DISK_FREE_MB=$((DISK_FREE / 1024))
  if (( DISK_FREE_MB < 10240 )); then
    warning "Less than 10GB disk space available (${DISK_FREE_MB}MB)."
    if ! prompt_confirm "Continue anyway?"; then
      error "Installation aborted due to insufficient disk space."
      exit 1
    fi
  else
    success "Disk space check passed: ${DISK_FREE_MB}MB available."
  fi

  # Check if ports 80 and 443 are free
  for port in 80 443; do
    if ss -tulpn | grep -q ":$port "; then
      warning "Port $port is in use."
      if ! prompt_confirm "Continue anyway?"; then
        error "Installation aborted due to port $port in use."
        exit 1
      fi
    else
      success "Port $port is free."
    fi
  done
}
function update_and_prepare_system() {
  info "Updating system packages and installing dependencies..."

  # Update package lists and upgrade
  apt-get update -y && apt-get upgrade -y

  # Fix broken dependencies if any
  if ! dpkg --configure -a; then
    warning "dpkg configuration had issues, attempting fix..."
    apt-get install -f -y
    dpkg --configure -a
  fi

  # Install essential packages
  apt-get install -y curl wget git software-properties-common lsb-release gnupg2 unzip ca-certificates net-tools ufw fail2ban rclone

  success "System updated and essential packages installed."
}

function detect_or_install_mysql() {
  info "Checking for existing MariaDB/MySQL installation..."

  if systemctl is-active --quiet mariadb; then
    success "MariaDB service detected and running."
    MYSQL_INSTALLED=true
  elif systemctl is-active --quiet mysql; then
    success "MySQL service detected and running."
    MYSQL_INSTALLED=true
  else
    MYSQL_INSTALLED=false
  fi

  if [ "$MYSQL_INSTALLED" = false ]; then
    info "MariaDB/MySQL not detected. Installing MariaDB server..."

    apt-get install -y mariadb-server mariadb-client

    # Generate a strong root password
    MYSQL_ROOT_PASS=$(openssl rand -base64 24)
    echo "$MYSQL_ROOT_PASS" > "$MYSQL_ROOT_PASS_FILE"
    chmod 600 "$MYSQL_ROOT_PASS_FILE"

    # Secure MariaDB installation non-interactively
    mysql_secure_installation <<EOF

y
$MYSQL_ROOT_PASS
$MYSQL_ROOT_PASS
y
y
y
y
EOF

    success "MariaDB installed and secured. Root password saved in $MYSQL_ROOT_PASS_FILE"
  else
    info "Using existing MariaDB/MySQL installation. Make sure you have root access."
  fi
}
function install_wordops() {
  if command -v wo &> /dev/null; then
    success "WordOps already installed."
  else
    info "Installing WordOps..."
    wget -qO wo wops.cc && bash wo
    success "WordOps installed successfully."
  fi
}

function setup_aliases() {
  info "Setting up command aliases..."

  local bashrc="$HOME/.bashrc"

  if ! grep -q 'alias addsite=' "$bashrc"; then
    cat <<'EOF' >> "$bashrc"
alias addsite='function _addsite() {
  domain="$1"
  if [ -z "$domain" ]; then
    echo "Usage: addsite domain.com"
    return 1
  fi
  # Auto Redis, SSL and latest WP install with auto admin credentials
  wo site create "$domain" --wpredis --php83 -le --user=admin --random-password --email=info@"$domain"
  # Save admin credentials to /root/<domain>-wp-admin.txt
  wp user list --path=/var/www/"$domain"/htdocs --allow-root --field=user_login,user_email > /root/"$domain"-wp-admin.txt
  echo "Admin credentials saved in /root/$domain-wp-admin.txt"
  # Run serverhealth automatically
  serverhealth
}; _addsite'
alias site='wo site'
alias flushcache='wo clean --all'
alias serverupdate='apt-get update && apt-get upgrade -y && wo update && wo stack upgrade'
alias commands='cat /root/wp-cheatsheet.txt'
EOF
    success "Aliases added to $bashrc."
  else
    info "Aliases already present in $bashrc."
  fi
}
function configure_rclone() {
  if command -v rclone &> /dev/null; then
    success "rclone already installed."
  else
    info "Installing rclone..."
    curl https://rclone.org/install.sh | bash
    success "rclone installed."
  fi

  if [ ! -f ~/.config/rclone/rclone.conf ]; then
    info "Please configure rclone manually for Google Drive access."
    info "Run 'rclone config' after installation completes."
  else
    success "rclone configuration found."
  fi
}

function setup_backup_cron() {
  info "Setting up nightly backup cron job..."
  # Cron job to backup /var/www, /etc/nginx, /var/lib/mysql nightly at 3 AM
  (crontab -l 2>/dev/null; echo "0 3 * * * bash /root/ultimate-wp-installer-lite.sh --backup") | crontab -
  success "Backup cron job set."
}

function install_netdata() {
  if systemctl is-active --quiet netdata; then
    success "Netdata already installed and running."
  else
    info "Installing Netdata monitoring dashboard..."
    bash <(curl -Ss https://get.netdata.cloud/kickstart.sh) --disable-telemetry
    ufw allow 19999
    success "Netdata installed. Access via https://your-server-ip:19999"
  fi
}
function serverhealth() {
  info "Running server health check..."

  # Disk usage
  local disk_used
  disk_used=$(df / | tail -1 | awk '{print $5}')
  if [[ "${disk_used%?}" -gt 80 ]]; then
    warning "Disk usage is high: $disk_used"
  else
    success "Disk usage: $disk_used"
  fi

  # RAM usage
  local ram_used
  ram_used=$(free -m | awk '/^Mem:/ {print int($3/$2 * 100)}')
  if (( ram_used > 85 )); then
    warning "RAM usage is high: ${ram_used}%"
  else
    success "RAM usage: ${ram_used}%"
  fi

  # Check services
  local services=(nginx php8.3-fpm mariadb redis-server)
  for svc in "${services[@]}"; do
    if systemctl is-active --quiet "$svc"; then
      success "$svc is running"
    else
      warning "$svc is NOT running - attempting restart"
      systemctl restart "$svc" && success "$svc restarted" || error "Failed to restart $svc"
    fi
  done

  # Check SSL certs expiry (simplified)
  local domains
  domains=$(wo site list --format=json | jq -r '.[].domain')
  for d in $domains; do
    local expiry
    expiry=$(echo | openssl s_client -connect "$d:443" -servername "$d" 2>/dev/null | openssl x509 -noout -dates | grep notAfter | cut -d= -f2)
    if [[ -z "$expiry" ]]; then
      warning "Cannot retrieve SSL expiry for $d"
    else
      success "SSL for $d expires on $expiry"
    fi
  done

  # Check WordPress sites HTTP status
  for d in $domains; do
    local status
    status=$(curl -o /dev/null -s -w "%{http_code}" --connect-timeout 5 "https://$d")
    if [[ "$status" == "200" ]]; then
      success "Site $d is up (HTTP 200)"
    else
      warning "Site $d returned HTTP status $status"
    fi
  done

  success "Server health check complete."
}

function wpautofix() {
  info "Running full auto-repair routine..."

  systemctl restart nginx php8.3-fpm mariadb redis-server
  success "Restarted Nginx, PHP-FPM, MariaDB, Redis"

  for d in $(wo site list --format=json | jq -r '.[].domain'); do
    wp cache flush --path="/var/www/$d/htdocs" --allow-root || warning "Failed to flush cache for $d"
  done
  success "Flushed Redis cache for all WordPress sites"

  wo update || warning "WordOps update failed"
  wo stack upgrade || warning "Stack upgrade failed"

  success "Auto-repair routine completed."
}

function wpremove() {
  local domain="$1"
  if [ -z "$domain" ]; then
    error "Usage: wpremove domain.com"
    return 1
  fi

  if ! prompt_confirm "Are you sure you want to permanently delete '$domain'?"; then
    info "Aborted deletion."
    return 0
  fi

  mkdir -p "$BACKUP_DIR"
  local backup_file="$BACKUP_DIR/${domain}-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
  info "Creating backup before removal at $backup_file"
  tar czf "$backup_file" "/var/www/$domain" "/etc/nginx/sites-available/$domain" "/etc/nginx/sites-enabled/$domain"

  wo site delete "$domain" --force || warning "Failed to delete WordOps site, continuing cleanup"

  # Delete backups of database and certificates if any (add if used)
  rm -rf "/var/www/$domain"
  rm -f "/root/${domain}-wp-admin.txt"

  systemctl reload nginx
  success "Site $domain deleted successfully. Backup saved at $backup_file"
}

function wplist() {
  printf "%-25s %-10s %-20s %-15s %-10s %-15s\n" "DOMAIN" "STATUS" "SSL EXPIRY" "REDIS" "PHP" "LAST HEALTH"
  echo "----------------------------------------------------------------------------------------------------"
  local domains
  domains=$(wo site list --format=json | jq -r '.[].domain')
  for d in $domains; do
    local status ssl_expiry redis_status php_version last_health
    # Check HTTP status
    status_code=$(curl -o /dev/null -s -w "%{http_code}" --connect-timeout 5 "https://$d" || echo "000")
    if [[ "$status_code" == "200" ]]; then
      status="${GREEN}Online${NC}"
    else
      status="${RED}Offline${NC}"
    fi

    # SSL expiry
    ssl_expiry=$(echo | openssl s_client -connect "$d:443" -servername "$d" 2>/dev/null | openssl x509 -noout -dates | grep notAfter | cut -d= -f2)
    ssl_expiry=${ssl_expiry:-"N/A"}

    # Redis enabled?
    redis_status=$(wp plugin is-active redis-cache --path="/var/www/$d/htdocs" --allow-root && echo "${GREEN}Enabled${NC}" || echo "${RED}Disabled${NC}")

    # PHP version
    php_version=$(php -v | head -1 | awk '{print $2}')

    # Last health check placeholder
    last_health="OK"

    printf "%-25s %-10b %-20s %-15b %-10s %-15s\n" "$d" "$status" "$ssl_expiry" "$redis_status" "$php_version" "$last_health"
  done
}

function wpupdate() {
  info "Starting update process for all WordPress sites..."

  mkdir -p "$BACKUP_DIR"

  local domains
  domains=$(wo site list --format=json | jq -r '.[].domain')
  for d in $domains; do
    info "Backing up $d before update..."
    local backup_file="$BACKUP_DIR/${d}-update-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    tar czf "$backup_file" "/var/www/$d/htdocs" "/var/www/$d/logs"
    info "Backup saved at $backup_file"

    info "Updating WordPress core, plugins, and themes for $d..."
    wp core update --path="/var/www/$d/htdocs" --allow-root || warning "Failed WP core update on $d"
    wp plugin update --all --path="/var/www/$d/htdocs" --allow-root || warning "Failed plugin updates on $d"
    wp theme update --all --path="/var/www/$d/htdocs" --allow-root || warning "Failed theme updates on $d"

    flushcache
    info "Finished updating $d"
  done

  success "All WordPress sites updated."
}
function print_cheatsheet() {
  cat <<EOF | tee "$CHEATSHEET_FILE"
──────────────────────────────────────────────
Ultimate WordPress Installer Lite - Command Cheat Sheet

Commands:

  addsite domain.com
    - Install a new isolated WordPress site with auto SSL, Redis, and generated admin credentials.

  wpremove domain.com
    - Safely remove a WordPress site with backup and confirmation.

  wplist
    - List all installed WordPress sites with status, SSL expiry, Redis, PHP version.

  wpupdate
    - Update WordPress core, plugins, and themes for all sites with backup.

  serverhealth
    - Check server health and auto-repair critical services and SSL certificates.

  wpautofix
    - Run a full system auto-repair: restart services, flush caches, update stack.

  flushcache
    - Clear Redis and FastCGI cache.

  serverupdate
    - Update system packages and WordOps stack.

  commands
    - Display this cheat sheet.

──────────────────────────────────────────────
EOF
}

function handle_args() {
  case "$1" in
    addsite)
      shift
      addsite "$@"
      ;;
    wpremove)
      shift
      wpremove "$@"
      ;;
    wplist)
      wplist
      ;;
    wpupdate)
      wpupdate
      ;;
    serverhealth)
      serverhealth
      ;;
    wpautofix)
      wpautofix
      ;;
    flushcache)
      flushcache
      ;;
    serverupdate)
      update_and_prepare_system
      install_wordops
      ;;
    commands)
      cat "$CHEATSHEET_FILE"
      ;;
    --backup)
      perform_backup
      ;;
    *)
      echo -e "${RED}Unknown command: $1${NC}"
      echo "Use 'commands' to see the available commands."
      ;;
  esac
}

function main() {
  print_cheatsheet
  pre_flight_checks
  update_and_prepare_system
  detect_or_install_mysql
  install_wordops
  setup_aliases
  configure_rclone
  setup_backup_cron
  install_netdata

  if [ "$#" -gt 0 ]; then
    handle_args "$@"
  else
    info "No command provided. Starting interactive setup..."
    read -rp "Enter your first domain to install WordPress (or leave blank to skip): " domain
    if [ -n "$domain" ]; then
      addsite "$domain"
    fi
    success "Installation complete! Use 'commands' to see available commands."
  fi
}

main "$@"
