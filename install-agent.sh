#!/bin/bash

# Prompt for interactive variables
read -p "Enter Wazuh Agent version (e.g., 4.12.0-1): " AGENT_VERSION
read -p "Enter Wazuh Manager IP address: " MANAGER_IP
read -s -p "Enter Wazuh Auth Key: " AUTH_KEY
echo

# Define filenames and paths
DEB_FILE="wazuh-agent_${AGENT_VERSION}_amd64.deb"
DEB_URL="https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/${DEB_FILE}"
AUTHD_PASS_PATH="/var/ossec/etc/authd.pass"
QUARANTINE_SCRIPT_URL="https://raw.githubusercontent.com/bayusky/wazuh-custom-rules-and-decoders/main/active-response/quarantine-malware.sh"
QUARANTINE_SCRIPT_PATH="/var/ossec/active-response/bin/quarantine-malware.sh"

# Download and install Wazuh agent
echo "[+] Downloading Wazuh agent package..."
wget "$DEB_URL" -O "$DEB_FILE" || { echo "Download failed."; exit 1; }

echo "[+] Installing Wazuh agent..."
sudo WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_GROUP="server" dpkg -i "./$DEB_FILE" || { echo "Installation failed."; exit 1; }

# Configure authd.pass
echo "[+] Configuring authentication key..."
echo "$AUTH_KEY" | sudo tee "$AUTHD_PASS_PATH" > /dev/null
sudo chmod 640 "$AUTHD_PASS_PATH"
sudo chown root:wazuh "$AUTHD_PASS_PATH"

# Install quarantine-malware.sh script
echo "[+] Installing quarantine-malware.sh active response script..."
sudo mkdir -p "$(dirname "$QUARANTINE_SCRIPT_PATH")"
sudo curl -sSL "$QUARANTINE_SCRIPT_URL" -o "$QUARANTINE_SCRIPT_PATH"
sudo chown root:wazuh "$QUARANTINE_SCRIPT_PATH"
sudo chmod 750 "$QUARANTINE_SCRIPT_PATH"

# Enable and start Wazuh agent
echo "[+] Enabling and starting Wazuh agent service..."
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

echo "[✔] Wazuh agent installation and configuration completed."
