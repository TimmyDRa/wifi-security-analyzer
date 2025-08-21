#!/usr/bin/env bash
set -e

echo "🚀 WiFi Security Analyzer - Setup Script"
echo "========================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root (for informational purposes)
if [[ $EUID -eq 0 ]]; then
   echo -e "${YELLOW}2. Start Application:${NC}"
echo "   source venv/bin/activate"
echo "   python app.py"
echo ""
echo -e "${YELLOW}3. Access Web Interface:${NC}"
echo "   http://localhost:5000"
echo ""
echo -e "${YELLOW}4. For Packet Sniffing:${NC}"
echo "   sudo python app.py  # Requires root privileges"
echo ""
echo -e "${BLUE}Quick Test Commands:${NC}"
echo "   # Test email system:"
echo "   python -c \"from emailer import send_test_email; print(send_test_email())\""
echo ""
echo "   # Test WiFi scanning:"
echo "   python analyzer.py --scan"
echo ""
echo "   # Test vulnerability scanning:"
echo "   python analyzer.py --vuln 127.0.0.1"
echo ""
echo -e "${RED}⚠️  Important Security Notes:${NC}"
echo "   • Never commit .env file to version control"
echo "   • Use Gmail App Passwords (not regular passwords)"  
echo "   • Only scan networks you own or have permission to test"
echo "   • Run as root only when packet sniffing is needed"
echo ""
echo -e "${GREEN}📚 For detailed setup instructions, see README.md${NC}"

deactivate 2>/dev/null || truee "${YELLOW}⚠️  Running as root. Consider running as regular user for setup.${NC}"
fi

echo -e "${BLUE}[1/6]${NC} Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python3 not found. Please install Python 3.7+${NC}"
    exit 1
fi
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo -e "${GREEN}✅ Python ${PYTHON_VERSION} found${NC}"

echo -e "${BLUE}[2/6]${NC} Creating virtual environment..."
if [ -d "venv" ]; then
    echo -e "${YELLOW}⚠️  Virtual environment already exists. Skipping creation.${NC}"
else
    python3 -m venv venv
    echo -e "${GREEN}✅ Virtual environment created${NC}"
fi

echo -e "${BLUE}[3/6]${NC} Activating virtual environment and installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo -e "${GREEN}✅ Python dependencies installed${NC}"

echo -e "${BLUE}[4/6]${NC} Installing system packages..."
# Check if we can use sudo
if command -v sudo &> /dev/null; then
    echo "Installing system packages (requires sudo)..."
    sudo apt update
    sudo apt install -y nmap aircrack-ng wireless-tools
    echo -e "${GREEN}✅ System packages installed${NC}"
else
    echo -e "${YELLOW}⚠️  sudo not available. Please install manually:${NC}"
    echo "   apt install nmap aircrack-ng wireless-tools"
fi

echo -e "${BLUE}[5/6]${NC} Creating configuration files..."

# Create logs directory
mkdir -p logs
touch logs/alerts.log
echo -e "${GREEN}✅ Logs directory created${NC}"

# Create secure config file if it doesn't exist
if [ ! -f "config_email.json" ]; then
    cat > config_email.json << 'EOF'
{
  "enabled": false,
  "smtp_host": "smtp.gmail.com",
  "smtp_port": 587,
  "use_tls": true,
  "username": "",
  "password": "",
  "from_addr": "",
  "to_addrs": []
}
EOF
    echo -e "${GREEN}✅ Secure config_email.json created${NC}"
else
    echo -e "${YELLOW}⚠️  config_email.json exists. Checking for security issues...${NC}"
    if grep -q '"password":\s*"[^"]\+[^"]"' config_email.json; then
        echo -e "${RED}🚨 SECURITY WARNING: Passwords found in config file!${NC}"
        echo "   Backing up existing config and creating secure version..."
        cp config_email.json config_email.json.backup
        cat > config_email.json << 'EOF'
{
  "enabled": false,
  "smtp_host": "smtp.gmail.com",
  "smtp_port": 587,
  "use_tls": true,
  "username": "",
  "password": "",
  "from_addr": "",
  "to_addrs": []
}
EOF
        echo -e "${GREEN}✅ Secure config created. Original backed up as config_email.json.backup${NC}"
    fi
fi

# Create .env template if it doesn't exist
if [ ! -f ".env" ]; then
    cat > .env.template << 'EOF'
# WiFi Security Analyzer - Environment Configuration
# Copy this file to .env and fill in your actual values

# Email Configuration
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-gmail-app-password-here
EMAIL_FROM=your-email@gmail.com
EMAIL_TO=recipient@example.com

# SMTP Settings (Gmail defaults)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=true

# Optional: Custom rate limiting (seconds between emails)
EMAIL_RATE_LIMIT=60
EOF
    echo -e "${GREEN}✅ .env.template created${NC}"
    echo -e "${YELLOW}📝 To enable email alerts: cp .env.template .env && edit .env${NC}"
else
    echo -e "${YELLOW}⚠️  .env file already exists${NC}"
fi

# Create/update .gitignore
cat > .gitignore << 'EOF'
# Security - Never commit these files
.env
config_email.json

# Logs and data
logs/
*.log
dump.txt

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
venv/
env/
.venv/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Temporary files
*.tmp
*.temp
EOF
echo -e "${GREEN}✅ .gitignore updated${NC}"

echo -e "${BLUE}[6/6]${NC} Running system tests..."

# Test Python dependencies
echo "Testing Python imports..."
python3 -c "
try:
    import flask, scapy
    print('✅ Core dependencies working')
except ImportError as e:
    print(f'❌ Import error: {e}')
"

# Test email system
echo "Testing email system..."
python3 -c "
try:
    from emailer import get_email_status
    status = get_email_status()
    if status['has_env_config']:
        print('✅ Email configured via environment variables')
    elif status['has_config']:
        print('✅ Email configured via config file')
    else:
        print('⚠️  Email not configured (optional)')
    print(f'   SMTP Host: {status[\"smtp_host\"]}')
    print(f'   Can connect: {status[\"can_connect\"]}')
    if not status['can_connect']:
        print(f'   Issue: {status[\"connection_message\"]}')
except Exception as e:
    print(f'❌ Email test failed: {e}')
"

# Check for wireless interface
echo "Checking wireless interfaces..."
if command -v iwconfig &> /dev/null; then
    WIRELESS_INTERFACES=$(iwconfig 2>/dev/null | grep -E '^[a-z]' | cut -d' ' -f1 | tr '\n' ' ')
    if [ -n "$WIRELESS_INTERFACES" ]; then
        echo -e "${GREEN}✅ Wireless interfaces found: ${WIRELESS_INTERFACES}${NC}"
    else
        echo -e "${YELLOW}⚠️  No wireless interfaces detected${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  iwconfig not available - cannot check wireless interfaces${NC}"
fi

# Check nmap
if command -v nmap &> /dev/null; then
    NMAP_VERSION=$(nmap --version | head -1)
    echo -e "${GREEN}✅ ${NMAP_VERSION}${NC}"
else
    echo -e "${YELLOW}⚠️  nmap not installed - vulnerability scanning will not work${NC}"
fi

echo ""
echo -e "${GREEN}🎉 Setup Complete!${NC}"
echo "========================================"
echo -e "${BLUE}Next Steps:${NC}"
echo ""
echo -e "${YELLOW}1. Email Setup (Optional):${NC}"
echo "   cp .env.template .env"
echo "   nano .env  # Add your Gmail App Password"
echo ""
echo -