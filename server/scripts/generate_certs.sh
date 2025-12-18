#!/bin/bash
# Generate self-signed TLS certificates for UEBA server (demo/dev use only)
# For production, use CA-signed certificates

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Get script directory and project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
CONFIG_DIR="$PROJECT_ROOT/config"

echo -e "${GREEN}Generating self-signed TLS certificates${NC}"
echo "=========================================="
echo "Project root: $PROJECT_ROOT"
echo "Config directory: $CONFIG_DIR"
echo ""

# Check if openssl is available
if ! command -v openssl &> /dev/null; then
    echo -e "${RED}Error: openssl not found. Please install OpenSSL.${NC}"
    exit 1
fi

# Create config directory if it doesn't exist
mkdir -p "$CONFIG_DIR"

# Get server hostname or IP (for certificate)
read -p "Enter server hostname or IP (default: localhost): " SERVER_HOST
SERVER_HOST=${SERVER_HOST:-localhost}

CERT_FILE="$CONFIG_DIR/server.crt"
KEY_FILE="$CONFIG_DIR/server.key"

# Check if certificates already exist
if [ -f "$CERT_FILE" ] || [ -f "$KEY_FILE" ]; then
    echo -e "${YELLOW}Certificates already exist:${NC}"
    echo "  Certificate: $CERT_FILE"
    echo "  Private Key: $KEY_FILE"
    read -p "Overwrite? (y/N): " OVERWRITE
    if [ "$OVERWRITE" != "y" ] && [ "$OVERWRITE" != "Y" ]; then
        echo "Aborted."
        exit 0
    fi
    rm -f "$CERT_FILE" "$KEY_FILE"
fi

echo -e "${YELLOW}Generating private key...${NC}"
openssl genrsa -out "$KEY_FILE" 2048

echo -e "${YELLOW}Generating certificate...${NC}"
openssl req -new -x509 -key "$KEY_FILE" -out "$CERT_FILE" -days 365 \
    -subj "/C=US/ST=State/L=City/O=UEBA/CN=$SERVER_HOST" \
    -addext "subjectAltName=DNS:$SERVER_HOST,DNS:localhost,IP:127.0.0.1"

# Set permissions
chmod 600 "$KEY_FILE"  # Private key: read/write for owner only
chmod 644 "$CERT_FILE"  # Certificate: readable by all

echo ""
echo -e "${GREEN}Certificates generated successfully!${NC}"
echo ""
echo "Certificate: $CERT_FILE"
echo "Private Key: $KEY_FILE"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Update server config (config/server_config.yaml):"
echo "   tls:"
echo "     enabled: true"
echo "     cert_path: \"config/server.crt\""
echo "     key_path: \"config/server.key\""
echo ""
echo "2. Copy server.crt to agent machine and update agent config:"
echo "   server:"
echo "     tls_enabled: true"
echo "     tls_cert_path: \"path/to/server.crt\""
echo "     tls_verify: false  # Set to false for self-signed certs in dev"
echo ""
echo -e "${RED}⚠️  WARNING: These are self-signed certificates for demo/dev only!${NC}"
echo "For production, use CA-signed certificates."

