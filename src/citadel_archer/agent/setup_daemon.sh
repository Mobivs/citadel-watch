#!/bin/bash
# Citadel Daemon — One-Liner Setup for Linux VPS
#
# Usage:
#   curl -fsSL http://coordinator/api/ext-agents/setup.sh | sudo bash -s -- <invitation> <server_url>
#
# Example:
#   curl -fsSL http://100.68.75.8:8000/api/ext-agents/setup.sh | sudo bash -s -- CITADEL-1:abc:xyz http://100.68.75.8:8000
#
# What this does:
#   1. Installs Python 3 if not present
#   2. Downloads the Citadel Daemon script
#   3. Enrolls this machine with your Citadel coordinator
#   4. Installs and starts a systemd service for continuous monitoring

set -euo pipefail

INVITATION="${1:-}"
SERVER_URL="${2:-}"
INSTALL_DIR="/opt/citadel-daemon"

# -- Validation --------------------------------------------------------------

if [ -z "$INVITATION" ] || [ -z "$SERVER_URL" ]; then
    echo "Citadel Daemon Setup"
    echo ""
    echo "Usage: curl -fsSL <server>/api/ext-agents/setup.sh | sudo bash -s -- <invitation> <server_url>"
    echo ""
    echo "Arguments:"
    echo "  invitation    The CITADEL-1:... invitation string from your dashboard"
    echo "  server_url    Your Citadel coordinator URL (e.g. http://100.68.75.8:8000)"
    exit 1
fi

echo "=== Citadel Daemon Setup ==="
echo ""

# -- Root check --------------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root."
    echo "Try: curl ... | sudo bash -s -- ..."
    exit 1
fi

# -- Python ------------------------------------------------------------------

PYTHON=""
for p in python3.12 python3.11 python3.10 python3.9 python3.8 python3; do
    if command -v "$p" &>/dev/null; then
        PYTHON="$p"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "[1/5] Installing Python 3..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq python3 >/dev/null 2>&1
    elif command -v dnf &>/dev/null; then
        dnf install -y -q python3 >/dev/null 2>&1
    elif command -v yum &>/dev/null; then
        yum install -y -q python3 >/dev/null 2>&1
    else
        echo "ERROR: No package manager found. Install Python 3.8+ manually."
        exit 1
    fi
    PYTHON="python3"
else
    echo "[1/5] Python found: $PYTHON ($($PYTHON --version 2>&1))"
fi

# -- Download ----------------------------------------------------------------

mkdir -p "$INSTALL_DIR"
echo "[2/5] Downloading daemon to $INSTALL_DIR..."

# Strip trailing slash from server URL
SERVER_URL="${SERVER_URL%/}"

curl -fsSL "$SERVER_URL/api/ext-agents/daemon.py" -o "$INSTALL_DIR/citadel_daemon.py"
chmod +x "$INSTALL_DIR/citadel_daemon.py"

# -- Enroll ------------------------------------------------------------------

echo "[3/5] Enrolling with coordinator..."
$PYTHON "$INSTALL_DIR/citadel_daemon.py" enroll "$SERVER_URL" "$INVITATION"

# -- Install service ---------------------------------------------------------

echo "[4/5] Installing systemd service..."
$PYTHON "$INSTALL_DIR/citadel_daemon.py" install

# -- Start -------------------------------------------------------------------

echo "[5/5] Starting daemon..."
systemctl start citadel-daemon

sleep 2
echo ""

if systemctl is-active --quiet citadel-daemon; then
    echo "=== Citadel Daemon is running ==="
    echo ""
    $PYTHON "$INSTALL_DIR/citadel_daemon.py" status
    echo ""
    echo "Useful commands:"
    echo "  systemctl status citadel-daemon     Check service status"
    echo "  journalctl -u citadel-daemon -f     Follow live logs"
    echo "  $PYTHON $INSTALL_DIR/citadel_daemon.py status   Agent status"
else
    echo "WARNING: Service may not have started."
    echo "Check: systemctl status citadel-daemon"
    echo "Logs:  journalctl -u citadel-daemon -n 20"
fi
