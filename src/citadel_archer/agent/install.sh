#!/bin/bash
# Citadel Shield — systemd Service Installer
# Deployed to /opt/citadel-shield/ alongside shield.py
#
# Usage: bash /opt/citadel-shield/install.sh

set -e

AGENT_DIR="/opt/citadel-shield"
SERVICE_NAME="citadel-shield"
SHIELD_PY="$AGENT_DIR/shield.py"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

echo "=== Citadel Shield Installer ==="

# Verify shield.py exists
if [ ! -f "$SHIELD_PY" ]; then
    echo "ERROR: $SHIELD_PY not found"
    exit 1
fi

# Make executable
chmod +x "$SHIELD_PY"

# Create data directory
mkdir -p "$AGENT_DIR"

# Check Python version
PYTHON=""
for p in python3.12 python3.11 python3.10 python3.9 python3.8 python3; do
    if command -v "$p" &>/dev/null; then
        PYTHON="$p"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "ERROR: Python 3.8+ not found"
    exit 1
fi

echo "Using Python: $PYTHON ($($PYTHON --version 2>&1))"

# Create systemd service
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Citadel Shield - VPS Protection Agent
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=$PYTHON $SHIELD_PY daemon
WorkingDirectory=$AGENT_DIR
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=citadel-shield

# Security hardening
NoNewPrivileges=no
ProtectSystem=false

[Install]
WantedBy=multi-user.target
EOF

echo "Created $SERVICE_FILE"

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

# Wait a moment and check status
sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "=== Citadel Shield is running ==="
    $PYTHON "$SHIELD_PY" status
else
    echo "WARNING: Service may not have started. Check with:"
    echo "  systemctl status $SERVICE_NAME"
    echo "  journalctl -u $SERVICE_NAME -n 20"
fi
