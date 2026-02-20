#!/bin/bash
# =====================================================
#   CIDR Network Scanner — Installation Script
# =====================================================

set -e  # Exit on any error

echo ""
echo "========================================"
echo "  CIDR Network Scanner — Setup Script"
echo "========================================"
echo ""

# ── Check Python version ──
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] Python3 is not installed. Please install Python 3.8+ first."
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "[✓] Python $PYTHON_VERSION found"

# ── Check pip ──
if ! command -v pip3 &>/dev/null; then
    echo "[ERROR] pip3 not found. Installing..."
    python3 -m ensurepip --upgrade
fi
echo "[✓] pip found"

# ── Create output directory ──
mkdir -p output
echo "[✓] Output directory created"

# ── Make scanner executable ──
chmod +x scanner.py
echo "[✓] scanner.py is now executable"

# ── Done ──
echo ""
echo "========================================"
echo "  Installation Complete!"
echo "========================================"
echo ""
echo "  Usage:"
echo "    python3 scanner.py 192.168.1.0/24"
echo ""
echo "  With Docker:"
echo "    docker build -t cidr-scanner ."
echo "    docker run --rm -v \$(pwd)/output:/app/output cidr-scanner 192.168.1.0/24"
echo ""
