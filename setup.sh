#!/usr/bin/env bash
set -e

echo "[*] Creating virtual environment..."
python3 -m venv venv

echo "[*] Activating virtual environment and installing Python deps..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "[*] Installing required system packages (you may be asked for sudo)..."
# These are optional but recommended for functionality
sudo apt update
sudo apt install -y nmap aircrack-ng

echo "[*] Creating logs directory..."
mkdir -p logs
touch logs/alerts.log

echo "[*] Setup complete. Activate venv with: source venv/bin/activate"
