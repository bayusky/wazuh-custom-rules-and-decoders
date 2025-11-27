#!/bin/bash

# Configuration
SOURCE_URL="https://raw.githubusercontent.com/bayusky/wazuh-custom-rules-and-decoders/refs/heads/main/browser-monitoring/browser-history-monitor.py"
INSTALL_DIR="$HOME/.browser-monitor"
SCRIPT_NAME="browser-history-monitor.py"
DEST_PATH="$INSTALL_DIR/$SCRIPT_NAME"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}   Browser History Monitor Installer     ${NC}"
echo -e "${BLUE}=========================================${NC}"

# --- 1. Check & Install Python 3 ---
echo -e "${YELLOW}[*] Checking for Python 3...${NC}"

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[-] Python 3 is not installed.${NC}"
    echo -e "${YELLOW}[*] Attempting automatic installation...${NC}"
    
    OS="$(uname -s)"
    if [ "$OS" = "Linux" ]; then
        if command -v apt-get &> /dev/null; then
            echo -e "${YELLOW}[*] Detected Debian/Ubuntu. Requesting sudo to install python3...${NC}"
            sudo apt-get update && sudo apt-get install -y python3
        elif command -v dnf &> /dev/null; then
            echo -e "${YELLOW}[*] Detected RHEL/Fedora. Requesting sudo to install python3...${NC}"
            sudo dnf install -y python3
        elif command -v yum &> /dev/null; then
             echo -e "${YELLOW}[*] Detected CentOS/RHEL. Requesting sudo to install python3...${NC}"
            sudo yum install -y python3
        elif command -v pacman &> /dev/null; then
             echo -e "${YELLOW}[*] Detected Arch. Requesting sudo to install python3...${NC}"
            sudo pacman -S --noconfirm python
        else
            echo -e "${RED}[!] Could not detect package manager. Please install Python 3 manually.${NC}"
            exit 1
        fi
    elif [ "$OS" = "Darwin" ]; then
        if command -v brew &> /dev/null; then
            echo -e "${YELLOW}[*] Detected Homebrew. Installing python...${NC}"
            brew install python
        else
             echo -e "${RED}[!] Homebrew not found. Please install Python 3 manually or install Homebrew.${NC}"
             exit 1
        fi
    fi
    
    # Re-verify
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}[!] Python 3 installation failed or not found. Exiting.${NC}"
        exit 1
    fi
    echo -e "${GREEN}[+] Python 3 installed successfully.${NC}"
else
    echo -e "${GREEN}[+] Python 3 is already installed: $(python3 --version)${NC}"
fi

# --- 2. Create Directory ---
if [ ! -d "$INSTALL_DIR" ]; then
    mkdir -p "$INSTALL_DIR"
    echo -e "${GREEN}[+] Created directory: $INSTALL_DIR${NC}"
fi

# --- 3. Download Script ---
echo -e "${YELLOW}[*] Downloading monitor script...${NC}"
if command -v curl &> /dev/null; then
    curl -s -o "$DEST_PATH" "$SOURCE_URL"
elif command -v wget &> /dev/null; then
    wget -q -O "$DEST_PATH" "$SOURCE_URL"
else
    echo -e "${RED}[-] Neither curl nor wget found. Cannot download script.${NC}"
    exit 1
fi

if [ -f "$DEST_PATH" ]; then
    echo -e "${GREEN}[+] Download complete: $DEST_PATH${NC}"
    chmod +x "$DEST_PATH"
else
    echo -e "${RED}[-] Download failed.${NC}"
    exit 1
fi

# --- 4. OS Persistence Setup ---
OS="$(uname -s)"
echo -e "${YELLOW}[*] Setting up background persistence for OS: $OS${NC}"

if [ "$OS" = "Linux" ]; then
    # --- LINUX SYSTEMD USER SERVICE ---
    # Does not require root; runs when user logs in
    SERVICE_DIR="$HOME/.config/systemd/user"
    SERVICE_FILE="$SERVICE_DIR/browser-monitor.service"
    
    mkdir -p "$SERVICE_DIR"
    
    # StandardOutput=null hides terminal output (background mode)
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Browser History Monitor for Wazuh
After=network.target

[Service]
ExecStart=$(which python3) $DEST_PATH
Restart=always
WorkingDirectory=$INSTALL_DIR
StandardOutput=null
StandardError=journal

[Install]
WantedBy=default.target
EOF
    
    echo -e "${GREEN}[+] Created Systemd service file: $SERVICE_FILE${NC}"
    
    # Reload and Enable
    systemctl --user daemon-reload
    systemctl --user enable browser-monitor
    
    # Start Immediately
    echo -e "${YELLOW}[*] Starting service immediately...${NC}"
    systemctl --user restart browser-monitor
    
    # Enable lingering (allows service to run even if user isn't logged in via SSH/GUI)
    if command -v loginctl &> /dev/null; then
        loginctl enable-linger $USER 2>/dev/null
        echo -e "${GREEN}[+] Enabled loginctl linger for $USER (persistence).${NC}"
    fi
    
    echo -e "${GREEN}[+] Service active. Logs accessible via Wazuh agent.${NC}"

elif [ "$OS" = "Darwin" ]; then
    # --- MACOS LAUNCH AGENT ---
    PLIST_DIR="$HOME/Library/LaunchAgents"
    LABEL="com.bayusky.browsermonitor"
    PLIST_FILE="$PLIST_DIR/$LABEL.plist"
    
    mkdir -p "$PLIST_DIR"
    
    cat > "$PLIST_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$(which python3)</string>
        <string>$DEST_PATH</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>$INSTALL_DIR/error.log</string>
</dict>
</plist>
EOF
    
    echo -e "${GREEN}[+] Created LaunchAgent plist: $PLIST_FILE${NC}"
    
    # Unload if exists, then load (Start Immediately)
    launchctl unload "$PLIST_FILE" 2>/dev/null
    launchctl load "$PLIST_FILE"
    
    echo -e "${GREEN}[+] LaunchAgent loaded and started.${NC}"

    # IMPORTANT WARNING FOR SAFARI
    echo -e "${YELLOW}[!] IMPORTANT: SAFARI MONITORING REQUIRES PERMISSIONS${NC}"
    echo -e "${YELLOW}    To monitor Safari, you must grant 'Full Disk Access' to:${NC}"
    echo -e "${YELLOW}    1. The Python executable: $(which python3)${NC}"
    echo -e "${YELLOW}    2. Or the Terminal application.${NC}"
    echo -e "${YELLOW}    Go to System Settings > Privacy & Security > Full Disk Access.${NC}"

else
    echo -e "${RED}[-] Unsupported Operating System for automatic persistence.${NC}"
    echo "    Script downloaded to $DEST_PATH. Please run manually."
fi
