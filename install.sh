#!/bin/bash
# CrowdSec to AbuseIPDB Reporter Installation Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/crowdsec-reporter"
SERVICE_USER="crowdsec-reporter"
REPO_URL="https://github.com/memedevorg/abuseipdb-crowdsec"

echo -e "${BLUE}CrowdSec to AbuseIPDB Reporter Installation${NC}"
echo "=============================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root (use sudo)${NC}"
   exit 1
fi

# Check if CrowdSec is installed
if ! command -v cscli &> /dev/null; then
    echo -e "${RED}Error: CrowdSec not found. Please install CrowdSec first.${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} CrowdSec found"

# Install dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
apt update
apt install -y python3 python3-yaml python3-pip sqlite3 curl

echo -e "${GREEN}✓${NC} Dependencies installed"

# Create user
if ! id "$SERVICE_USER" &>/dev/null; then
    echo -e "${YELLOW}Creating service user...${NC}"
    useradd -r -s /bin/false "$SERVICE_USER"
    echo -e "${GREEN}✓${NC} Service user created"
else
    echo -e "${GREEN}✓${NC} Service user already exists"
fi

# Create installation directory
echo -e "${YELLOW}Setting up installation directory...${NC}"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Download files
echo -e "${YELLOW}Downloading application files...${NC}"
curl -sL "$REPO_URL/raw/main/crowdsec_reporter.py" -o crowdsec_reporter.py
curl -sL "$REPO_URL/raw/main/config.example.yml" -o config.yml
curl -sL "$REPO_URL/raw/main/crowdsec-reporter.service" -o crowdsec-reporter.service

echo -e "${GREEN}✓${NC} Application files downloaded"

# Set permissions
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chmod 755 crowdsec_reporter.py

# Setup machine credentials
echo -e "${YELLOW}Setting up CrowdSec machine credentials...${NC}"
if cscli machines add abuseipdb-reporter --auto 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Machine credentials created"
else
    echo -e "${YELLOW}⚠${NC} Machine credentials already exist, copying existing ones"
fi

cp /etc/crowdsec/local_api_credentials.yaml "$INSTALL_DIR/" 2>/dev/null || true
chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/local_api_credentials.yaml" 2>/dev/null || true

# Install systemd service
echo -e "${YELLOW}Installing systemd service...${NC}"
cp crowdsec-reporter.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable crowdsec-reporter

echo -e "${GREEN}✓${NC} Systemd service installed"

echo ""
echo -e "${GREEN}Installation completed!${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Edit the configuration file:"
echo "   nano $INSTALL_DIR/config.yml"
echo ""
echo "2. Add your API keys:"
echo "   - Get CrowdSec bouncer key: sudo cscli bouncers add abuseipdb-reporter"
echo "   - Get AbuseIPDB key from: https://www.abuseipdb.com/account/api"
echo ""
echo "3. Start the service:"
echo "   sudo systemctl start crowdsec-reporter"
echo ""
echo "4. Monitor the service:"
echo "   sudo systemctl status crowdsec-reporter"
echo "   sudo journalctl -u crowdsec-reporter -f"
echo ""
echo -e "${BLUE}Installation directory: $INSTALL_DIR${NC}"
