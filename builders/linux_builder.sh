#!/bin/bash

# Advanced Linux Builder Script
# Features: Cross-compilation, Obfuscation, Anti-analysis, Packing

# Configuration
CONFIG_FILE="linux_build.conf"
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    # Default configuration
    SRC_DIR="src"
    OUT_DIR="dist"
    MAIN_EXECUTABLE="app"
    TARGET_ARCH="x86_64"  # Options: x86_64, i686, arm, aarch64
    OBFUSCATION_LEVEL="high"  # low, medium, high
    ENABLE_ANTI_ANALYSIS=1
    PACK_EXECUTABLE=1
    RESOURCES=("data.bin" "config.json")
    POST_BUILD_COMMANDS=()
fi

# Tools
CC=""
STRIP="strip"
OBFUSCATOR=""
PACKER="custom_packer.py"
CLANG_FLAGS=""
LDFLAGS="-s -Wl,--gc-sections -Wl,-z,relro,-z,now"

# Setup environment
setup_environment() {
    echo "[+] Setting up build environment"
    
    case "$TARGET_ARCH" in
        x86_64)
            CC="gcc"
            ;;
        i686)
            CC="gcc -m32"
            ;;
        arm)
            CC="arm-linux-gnueabi-gcc"
            ;;
        aarch64)
            CC="aarch64-linux-gnu-gcc"
            ;;
        *)
            echo "[-] Unsupported architecture: $TARGET_ARCH"
            exit 1
            ;;
    esac
    
    # Check for obfuscator
    if command -v ollvm &> /dev/null && [ "$OBFUSCATION_LEVEL" != "low" ]; then
        OBFUSCATOR="ollvm"
        CLANG_FLAGS="-mllvm -fla -mllvm -sub -mllvm -bcf"
        if [ "$OBFUSCATION_LEVEL" = "high" ]; then
            CLANG_FLAGS="$CLANG_FLAGS -mllvm -sobf"
        fi
    fi
    
    # Create directories
    mkdir -p "$OUT_DIR"
    BUILD_DIR="$(mktemp -d)"
    mkdir -p "$BUILD_DIR/obj" "$BUILD_DIR/resources"
}

cleanup() {
    echo "[+] Cleaning up"
    rm -rf "$BUILD_DIR"
}

preprocess_resources() {
    echo "[+] Processing resources"
    for res in "${RESOURCES[@]}"; do
        if [ -f "$res" ]; then
            # Simple XOR encryption
            KEY=$(openssl rand -hex 16)
            openssl enc -aes-256-cbc -pbkdf2 -in "$res" -out "$BUILD_DIR/resources/${res}.enc" -pass pass:"$KEY" -salt
            
            # Generate C header
            xxd -i "$BUILD_DIR/resources/${res}.enc" > "$BUILD_DIR/resources/${res}_enc.h"
            echo "const char *${res//./_}_key = \"$KEY\";" >> "$BUILD_DIR/resources/${res}_enc.h"
        fi
    done
}

compile_sources() {
    echo "[+] Compiling sources"
    
    for src_file in $(find "$SRC_DIR" -name '*.c'); do
        obj_file="$BUILD_DIR/obj/$(basename "${src_file%.*}").o"
        
        # Apply string obfuscation
        if [ "$OBFUSCATION_LEVEL" != "low" ]; then
            python3 -c "
import sys
from obfuscation.string_obfuscator import StringObfuscator
obf = StringObfuscator()
with open('$src_file', 'r') as f:
    content = f.read()
    # Simple string obfuscation (in real use, we'd parse properly)
    obf_content = content.replace('\"secret\"', obf.obfuscate('secret', '${KEY}'))
with open('$src_file.tmp', 'w') as f:
    f.write(obf_content)
"
            SRC_FILE="$src_file.tmp"
        else
            SRC_FILE="$src_file"
        fi
        
        # Compile with obfuscation if available
        if [ -n "$OBFUSCATOR" ]; then
            clang $CLANG_FLAGS -c -o "$obj_file" "$SRC_FILE"
        else
            $CC -c -o "$obj_file" "$SRC_FILE" -fPIC -O2 -fno-stack-protector
        fi
        
        [ "$OBFUSCATION_LEVEL" != "low" ] && rm "$SRC_FILE.tmp"
    done
}

link_executable() {
    echo "[+] Linking executable"
    OBJ_FILES=$(find "$BUILD_DIR/obj" -name '*.o')
    $CC $OBJ_FILES -o "$BUILD_DIR/$MAIN_EXECUTABLE" $LDFLAGS
    
    # Strip symbols
    $STRIP --strip-all "$BUILD_DIR/$MAIN_EXECUTABLE"
}

apply_anti_analysis() {
    if [ "$ENABLE_ANTI_ANALYSIS" -eq 0 ]; then
        return
    fi
    
    echo "[+] Applying anti-analysis techniques"
    BINARY="$BUILD_DIR/$MAIN_EXECUTABLE"
    
    # Inject anti-debugging code
    nasm -f bin -o anti_debug.bin << 'EOF'
section .text
    global _start

_start:
    ; Check debugger via ptrace
    xor eax, eax
    mov al, 101     ; ptrace syscall
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    int 0x80
    test eax, eax
    js no_debugger
    
    ; Debugger detected - exit
    mov eax, 1
    mov ebx, 1
    int 0x80
    
no_debugger:
    ; Continue execution
    jmp original_entry
EOF

    # Get original entry point
    ENTRY_POINT=$(readelf -h "$BINARY" | grep "Entry point" | awk '{print $4}')
    ENTRY_OFFSET=$(printf "%d" "0x$ENTRY_POINT")
    
    # Inject code
    dd if=anti_debug.bin of="$BINARY" seek=$ENTRY_OFFSET conv=notrunc
    rm anti_debug.bin
    
    # Add fake section headers
    objcopy --add-section .fake_section=/dev/urandom "$BINARY"
}

pack_executable() {
    if [ "$PACK_EXECUTABLE" -eq 0 ]; then
        cp "$BUILD_DIR/$MAIN_EXECUTABLE" "$OUT_DIR/"
        return
    fi
    
    echo "[+] Packing executable"
    python3 "$PACKER" "$BUILD_DIR/$MAIN_EXECUTABLE" "$OUT_DIR/$MAIN_EXECUTABLE"
}

run_post_build() {
    for cmd in "${POST_BUILD_COMMANDS[@]}"; do
        echo "[+] Running post-build command: $cmd"
        eval "$cmd"
    done
}

# Main build process
setup_environment
preprocess_resources
compile_sources
link_executable

if [ "$ENABLE_ANTI_ANALYSIS" -eq 1 ]; then
    apply_anti_analysis
fi

pack_executable
run_post_build
cleanup

echo "[+] Build completed successfully!"