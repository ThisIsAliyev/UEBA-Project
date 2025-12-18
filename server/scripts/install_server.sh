#!/bin/bash
# UEBA Server Installation Script
# Installs Python dependencies, creates directories, and sets up systemd service

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get script directory and project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

echo -e "${GREEN}UEBA Server Installation${NC}"
echo "=========================="
echo "Project root: $PROJECT_ROOT"
echo ""

# Check Python version
echo -e "${YELLOW}Checking Python version...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: python3 not found. Please install Python 3.10 or higher.${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
    echo -e "${RED}Error: Python 3.10 or higher required. Found: $PYTHON_VERSION${NC}"
    exit 1
fi

echo -e "${GREEN}Python $PYTHON_VERSION found${NC}"
echo ""

# Create virtual environment
echo -e "${YELLOW}Creating virtual environment...${NC}"
if [ -d "$PROJECT_ROOT/venv" ]; then
    echo "Virtual environment already exists, skipping..."
else
    python3 -m venv "$PROJECT_ROOT/venv"
    echo -e "${GREEN}Virtual environment created${NC}"
fi
echo ""

# Activate virtual environment and install dependencies
echo -e "${YELLOW}Installing Python dependencies...${NC}"
source "$PROJECT_ROOT/venv/bin/activate"
pip install --upgrade pip
pip install -r "$PROJECT_ROOT/requirements.txt"
echo -e "${GREEN}Dependencies installed${NC}"
echo ""

# Create required directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p "$PROJECT_ROOT/data"
mkdir -p "$PROJECT_ROOT/logs"
mkdir -p "$PROJECT_ROOT/config"
echo -e "${GREEN}Directories created${NC}"
echo ""

# Generate default config if missing
CONFIG_FILE="$PROJECT_ROOT/config/server_config.yaml"
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${YELLOW}Creating default configuration...${NC}"
    cat > "$CONFIG_FILE" << 'EOF'
# UEBA Server Configuration
# =========================

# TCP port for receiving events from Windows agents
ingest_port: 9000

# HTTP port for the web dashboard
web_port: 8080

# Database configuration
database:
  # Path to SQLite database file (relative to project root)
  path: "data/events.db"
  # Maximum events to keep (0 = unlimited)
  max_events: 100000

# Logging configuration
logging:
  level: "INFO"
  # Log file path (relative to project root, or null for stdout only)
  file: "logs/server.log"

# Web UI settings
web_ui:
  # Number of events to show per page
  events_per_page: 100
  # Auto-refresh interval in milliseconds (for polling fallback)
  refresh_interval_ms: 2000
EOF
    echo -e "${GREEN}Default configuration created at $CONFIG_FILE${NC}"
else
    echo "Configuration file already exists: $CONFIG_FILE"
fi
echo ""

# Set permissions
echo -e "${YELLOW}Setting permissions...${NC}"
chmod 755 "$PROJECT_ROOT/data"
chmod 755 "$PROJECT_ROOT/logs"
chmod 644 "$CONFIG_FILE"
echo -e "${GREEN}Permissions set${NC}"
echo ""

# Create systemd service file
echo -e "${YELLOW}Creating systemd service file...${NC}"
SERVICE_FILE="/etc/systemd/system/ueba-server.service"
SERVICE_USER="${SUDO_USER:-$USER}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Note: Run with sudo to install systemd service${NC}"
    echo "Creating service file template at $PROJECT_ROOT/scripts/ueba-server.service"
    cat > "$PROJECT_ROOT/scripts/ueba-server.service" << EOF
[Unit]
Description=UEBA Event Viewer Server
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$PROJECT_ROOT
Environment="PATH=$PROJECT_ROOT/venv/bin"
ExecStart=$PROJECT_ROOT/venv/bin/python -m src.server.main
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$PROJECT_ROOT/scripts/ueba-server.service"
    echo -e "${GREEN}Service file template created${NC}"
    echo ""
    echo -e "${YELLOW}To install the service, run:${NC}"
    echo "  sudo cp $PROJECT_ROOT/scripts/ueba-server.service $SERVICE_FILE"
    echo "  sudo systemctl daemon-reload"
    echo "  sudo systemctl enable ueba-server"
    echo "  sudo systemctl start ueba-server"
else
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=UEBA Event Viewer Server
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$PROJECT_ROOT
Environment="PATH=$PROJECT_ROOT/venv/bin"
ExecStart=$PROJECT_ROOT/venv/bin/python -m src.server.main
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    echo -e "${GREEN}Systemd service installed${NC}"
    echo ""
    echo -e "${YELLOW}To enable and start the service:${NC}"
    echo "  sudo systemctl enable ueba-server"
    echo "  sudo systemctl start ueba-server"
fi
echo ""

# Summary
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Next steps:"
echo "1. Review configuration: $CONFIG_FILE"
echo "2. Start the server:"
echo "   cd $PROJECT_ROOT"
echo "   source venv/bin/activate"
echo "   python -m src.server.main"
echo ""
echo "Or if systemd service is installed:"
echo "   sudo systemctl start ueba-server"
echo "   sudo systemctl status ueba-server"
echo ""

