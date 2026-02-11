#!/bin/bash
# ============================================================
# Quick Docker installer script for Ubuntu VM
# Uses the GELF logging driver to send logs directly to Graylog
# Run: chmod +x setup_vm.sh && sudo ./setup_vm.sh
# ============================================================

set -e

echo "=========================================="
echo "  SETUP VM CHO LOG SYSTEM (GELF)"
echo "=========================================="

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo: sudo ./setup_vm.sh"
    exit 1
fi

# ---- Step 1: Update system ----
echo "[1/3] Updating system..."
apt update && apt upgrade -y

# ---- Step 2: Install Docker ----
echo "[2/3] Installing Docker..."
apt install -y ca-certificates curl gnupg lsb-release git

# Cài Docker qua script chính thức
curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
sh /tmp/get-docker.sh

# Allow the current user to run Docker without sudo
ACTUAL_USER=${SUDO_USER:-$USER}
usermod -aG docker $ACTUAL_USER

echo "Docker đã cài: $(docker --version)"

# ---- Step 3: Configure firewall (if present) ----
echo "[3/3] Configuring firewall..."
if command -v ufw &> /dev/null; then
    ufw allow 8080/tcp   # Bootstrap Landing Page (VM1)
    ufw allow 3000/tcp   # React Landing Page (VM2)
    echo "Firewall rules added"
else
    echo "ufw not found, skipping firewall configuration"
fi

echo ""
echo "=========================================="
echo "  SETUP HOÀN TẤT!"
echo "=========================================="
echo ""
echo "Hostname : $(hostname)"
echo "IP       : $(hostname -I | awk '{print $1}')"
echo ""
echo "QUAN TRỌNG: Log out và log in lại để chạy docker không cần sudo!"
echo ""
echo "Bước tiếp theo:"
echo "  1) Log out: exit"
echo "  2) SSH lại vào VM"
echo "  3) Kiểm tra: docker --version"
echo ""
echo "  Nếu đây là VM1 (Prod-BootstrapLP):"
echo "    mkdir -p ~/app && cd ~/app"
echo "    # Tạo Dockerfile, docker-compose.yml, .env (xem hướng dẫn)"
echo "    docker compose up -d --build"
echo "    Truy cập: http://$(hostname -I | awk '{print $1}'):8080"
echo ""
echo "  Nếu đây là VM2 (Prod-ReactLP):"
echo "    mkdir -p ~/app && cd ~/app"
echo "    # Tạo Dockerfile, docker-compose.yml, .env (xem hướng dẫn)"
echo "    docker compose up -d --build"
echo "    Truy cập: http://$(hostname -I | awk '{print $1}'):3000"
echo ""
