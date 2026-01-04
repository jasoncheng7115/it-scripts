#!/bin/bash
#
# JT Wazuh Agent Manager - Installation Script
# https://github.com/jasoncheng7115/it-scripts/tree/master/jt_wazuh_agent_mgr
#

set -e

INSTALL_DIR="/opt/jt_wazuh_agent_mgr"
BASE_URL="https://raw.githubusercontent.com/jasoncheng7115/it-scripts/master/jt_wazuh_agent_mgr"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} JT Wazuh Agent Manager Installer${NC}"
echo -e "${GREEN}========================================${NC}"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Check if this is an update
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}Existing installation detected. Updating...${NC}"
    UPDATE_MODE=true
else
    echo -e "${GREEN}Installing to $INSTALL_DIR ...${NC}"
    UPDATE_MODE=false
    mkdir -p "$INSTALL_DIR"
fi

# Create lib directory
mkdir -p "$INSTALL_DIR/lib"
mkdir -p "$INSTALL_DIR/images"

# Download main files
echo -e "${GREEN}Downloading files...${NC}"

curl -sf "$BASE_URL/wazuh_agent_mgr.py" -o "$INSTALL_DIR/wazuh_agent_mgr.py"
echo "  - wazuh_agent_mgr.py"

curl -sf "$BASE_URL/create_api_user.py" -o "$INSTALL_DIR/create_api_user.py"
echo "  - create_api_user.py"

curl -sf "$BASE_URL/requirements.txt" -o "$INSTALL_DIR/requirements.txt"
echo "  - requirements.txt"

# Download config.yaml only if it doesn't exist (don't overwrite user config)
if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
    curl -sf "$BASE_URL/config.yaml" -o "$INSTALL_DIR/config.yaml"
    echo "  - config.yaml (new)"
else
    echo -e "  - config.yaml ${YELLOW}(skipped, keeping existing)${NC}"
fi

# Download lib files
LIB_FILES="__init__.py config.py wazuh_cli.py wazuh_api.py agent_ops.py group_ops.py node_ops.py stats.py output.py web_ui.py"

for file in $LIB_FILES; do
    curl -sf "$BASE_URL/lib/$file" -o "$INSTALL_DIR/lib/$file"
    echo "  - lib/$file"
done

# Download favicon
curl -sf "$BASE_URL/images/favicon.ico" -o "$INSTALL_DIR/images/favicon.ico" 2>/dev/null || true
echo "  - images/favicon.ico"

# Set permissions
chmod +x "$INSTALL_DIR/wazuh_agent_mgr.py"
chmod +x "$INSTALL_DIR/create_api_user.py"

# Install Python dependencies
echo
echo -e "${GREEN}Installing Python dependencies...${NC}"
pip install -q -r "$INSTALL_DIR/requirements.txt"

# Get version
VERSION=$(grep -o '__version__ = "[^"]*"' "$INSTALL_DIR/lib/__init__.py" | cut -d'"' -f2)

echo
echo -e "${GREEN}========================================${NC}"
if [ "$UPDATE_MODE" = true ]; then
    echo -e "${GREEN} Update complete! (v$VERSION)${NC}"
else
    echo -e "${GREEN} Installation complete! (v$VERSION)${NC}"
fi
echo -e "${GREEN}========================================${NC}"
echo
echo -e "Run with: ${YELLOW}cd $INSTALL_DIR && ./wazuh_agent_mgr.py --web --ssl-auto${NC}"
echo
