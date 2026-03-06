#!/bin/bash
# Citadel Daemon — One-Liner Setup for Linux VPS
#
# Usage (interactive Tailscale auth — browser approval required):
#   curl -fsSL http://coordinator/api/ext-agents/setup.sh | sudo bash -s -- <invitation> <server_url>
#
# Usage (non-interactive with Tailscale pre-auth key):
#   curl -fsSL http://coordinator/api/ext-agents/setup.sh | sudo bash -s -- <invitation> <server_url> --tailscale-key=tskey-auth-xxx
#
# Usage (skip Tailscale — machine is already on your tailnet):
#   curl -fsSL http://coordinator/api/ext-agents/setup.sh | sudo bash -s -- <invitation> <server_url> --skip-tailscale
#
# What this does:
#   1. Installs Python 3 if not present
#   2. Installs Tailscale and joins your tailnet
#   3. Locks down SSH + UFW to Tailscale-only
#   4. Downloads the Citadel Daemon script
#   5. Enrolls this machine with your Citadel coordinator
#   6. Installs and starts a systemd service for continuous monitoring

set -euo pipefail

INVITATION="${1:-}"
SERVER_URL="${2:-}"
INSTALL_DIR="/opt/citadel-daemon"
TAILSCALE_KEY=""
SKIP_TAILSCALE=0

# Parse optional flags (position 3+)
for arg in "${@:3}"; do
    case "$arg" in
        --tailscale-key=*) TAILSCALE_KEY="${arg#--tailscale-key=}" ;;
        --skip-tailscale)  SKIP_TAILSCALE=1 ;;
    esac
done

# -- Validation --------------------------------------------------------------

if [ -z "$INVITATION" ] || [ -z "$SERVER_URL" ]; then
    echo "Citadel Daemon Setup"
    echo ""
    echo "Usage: curl -fsSL <server>/api/ext-agents/setup.sh | sudo bash -s -- <invitation> <server_url> [options]"
    echo ""
    echo "Arguments:"
    echo "  invitation    The CITADEL-1:... invitation string from your dashboard"
    echo "  server_url    Your Citadel coordinator URL (e.g. http://100.68.75.8:8000)"
    echo ""
    echo "Options:"
    echo "  --tailscale-key=KEY    Pre-auth key for non-interactive Tailscale enrollment"
    echo "  --skip-tailscale       Skip Tailscale setup (machine already on tailnet)"
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

# -- Step 1: Python ----------------------------------------------------------

PYTHON=""
for p in python3.12 python3.11 python3.10 python3.9 python3.8 python3; do
    if command -v "$p" &>/dev/null; then
        PYTHON="$p"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "[1/7] Installing Python 3..."
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
    echo "[1/7] Python found: $PYTHON ($($PYTHON --version 2>&1))"
fi

# -- Step 2: Tailscale -------------------------------------------------------

if [ "$SKIP_TAILSCALE" -eq 1 ]; then
    echo "[2/7] Tailscale: skipped (already installed via Step 1)"
    # Still lock down SSH + UFW using the already-running Tailscale IP
    TS_IP=$(tailscale ip -4 2>/dev/null || true)
    if [ -n "$TS_IP" ]; then
        echo "[3/7] Locking down SSH and firewall to Tailscale ($TS_IP)..."
        if [ -f /etc/ssh/sshd_config ]; then
            if grep -q "^ListenAddress $TS_IP" /etc/ssh/sshd_config 2>/dev/null; then
                echo "       SSH already restricted to $TS_IP"
            else
                cp /etc/ssh/sshd_config /etc/ssh/sshd_config.citadel.bak
                sed -i '/^ListenAddress/d' /etc/ssh/sshd_config
                echo "ListenAddress $TS_IP" >> /etc/ssh/sshd_config
                systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
                echo "       SSH restricted to $TS_IP"
            fi
        fi
        if command -v ufw &>/dev/null; then
            ufw default deny incoming >/dev/null 2>&1
            ufw default allow outgoing >/dev/null 2>&1
            ufw status | grep -q "tailscale0" || ufw allow in on tailscale0 >/dev/null 2>&1
            ufw status | grep -q "41641/udp" || ufw allow 41641/udp >/dev/null 2>&1
            ufw --force enable >/dev/null 2>&1
            echo "       UFW enabled: public internet blocked, Tailscale allowed"
        fi
    else
        echo "[3/7] SSH/UFW lockdown: skipped (Tailscale not connected)"
    fi
else
    # Install Tailscale if missing
    if ! command -v tailscale &>/dev/null; then
        echo "[2/7] Installing Tailscale..."
        curl -fsSL https://tailscale.com/install.sh | sh >/dev/null 2>&1
        systemctl enable --now tailscaled >/dev/null 2>&1
        sleep 2
    else
        echo "[2/7] Tailscale already installed"
    fi

    # Check if already connected
    TS_IP=$(tailscale ip -4 2>/dev/null || true)

    if [ -n "$TS_IP" ]; then
        echo "       Already connected — Tailscale IP: $TS_IP"

    elif [ -n "$TAILSCALE_KEY" ]; then
        # Non-interactive: use pre-auth key
        echo "       Connecting with pre-auth key..."
        tailscale up --authkey="$TAILSCALE_KEY" 2>&1
        sleep 3
        TS_IP=$(tailscale ip -4 2>/dev/null || true)
        if [ -z "$TS_IP" ]; then
            echo "ERROR: Tailscale did not connect after auth key. Check the key and try again."
            exit 1
        fi
        echo "       Connected — Tailscale IP: $TS_IP"

    else
        # Interactive: display auth URL and wait for browser approval
        echo "       Connecting to your Tailscale network..."
        echo ""
        echo "  A browser authorization URL will appear below."
        echo "  Visit it to add this server to your tailnet, then return here."
        echo ""
        tailscale up 2>&1
        echo ""
        TS_IP=$(tailscale ip -4 2>/dev/null || true)
        if [ -z "$TS_IP" ]; then
            echo "ERROR: Tailscale connected but could not get IP."
            echo "Run 'tailscale ip -4' to check, then re-run with --skip-tailscale."
            exit 1
        fi
        echo "  Connected — Tailscale IP: $TS_IP"
        echo ""
    fi

    # -- Step 3: SSH + UFW lockdown ------------------------------------------

    echo "[3/7] Locking down SSH and firewall to Tailscale..."

    # SSH: restrict sshd to Tailscale interface only
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "^ListenAddress $TS_IP" /etc/ssh/sshd_config 2>/dev/null; then
            echo "       SSH already restricted to $TS_IP"
        else
            cp /etc/ssh/sshd_config /etc/ssh/sshd_config.citadel.bak
            # Remove any existing ListenAddress directives, add ours
            sed -i '/^ListenAddress/d' /etc/ssh/sshd_config
            echo "ListenAddress $TS_IP" >> /etc/ssh/sshd_config
            # Reload sshd (service name varies by distro)
            systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
            echo "       SSH restricted to $TS_IP (backup: /etc/ssh/sshd_config.citadel.bak)"
        fi
    fi

    # UFW: block public internet, allow Tailscale
    if command -v ufw &>/dev/null; then
        ufw default deny incoming >/dev/null 2>&1
        ufw default allow outgoing >/dev/null 2>&1
        # Allow all traffic on the Tailscale interface
        ufw status | grep -q "tailscale0" || ufw allow in on tailscale0 >/dev/null 2>&1
        # Allow Tailscale's own UDP port for NAT traversal
        ufw status | grep -q "41641/udp" || ufw allow 41641/udp >/dev/null 2>&1
        ufw --force enable >/dev/null 2>&1
        echo "       UFW enabled: public internet blocked, Tailscale allowed"
    else
        echo "       UFW not found — skipping firewall setup"
    fi
fi

# -- Step 3b: SSH hardening --------------------------------------------------
# Safe to apply unconditionally — disables password auth (key-based only),
# prohibits password-based root login, installs fail2ban + auto-updates.

echo "[3b] Hardening SSH and installing security services..."

if [ -f /etc/ssh/sshd_config ]; then
    # Disable password authentication entirely (SSH keys only)
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    grep -q "^PasswordAuthentication" /etc/ssh/sshd_config || echo "PasswordAuthentication no" >> /etc/ssh/sshd_config

    # Prohibit password-based root login; key-based root still allowed
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    grep -q "^PermitRootLogin" /etc/ssh/sshd_config || echo "PermitRootLogin prohibit-password" >> /etc/ssh/sshd_config

    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
    echo "       PasswordAuthentication no, PermitRootLogin prohibit-password"
fi

# Install fail2ban (brute-force protection)
if command -v apt-get &>/dev/null; then
    if ! command -v fail2ban-server &>/dev/null; then
        apt-get install -y -qq fail2ban >/dev/null 2>&1
    fi
    systemctl enable --now fail2ban >/dev/null 2>&1
    echo "       fail2ban enabled"
fi

# Enable unattended security updates
if command -v apt-get &>/dev/null && command -v unattended-upgrades &>/dev/null; then
    systemctl enable --now unattended-upgrades >/dev/null 2>&1
    echo "       unattended-upgrades enabled"
fi

# -- Step 4: Download --------------------------------------------------------

SERVER_URL="${SERVER_URL%/}"
mkdir -p "$INSTALL_DIR"
echo "[4/7] Downloading daemon to $INSTALL_DIR..."
curl -fsSL "$SERVER_URL/api/ext-agents/daemon.py" -o "$INSTALL_DIR/citadel_daemon.py"
chmod +x "$INSTALL_DIR/citadel_daemon.py"

# -- Step 5: Enroll ----------------------------------------------------------

echo "[5/7] Enrolling with coordinator..."
$PYTHON "$INSTALL_DIR/citadel_daemon.py" enroll "$SERVER_URL" "$INVITATION"

# -- Step 6: Install service -------------------------------------------------

echo "[6/7] Installing systemd service..."
$PYTHON "$INSTALL_DIR/citadel_daemon.py" install

# -- Step 7: Start -----------------------------------------------------------

echo "[7/7] Starting daemon..."
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
