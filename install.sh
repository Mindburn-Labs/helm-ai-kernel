#!/bin/bash
set -e
set -o pipefail

# HELM Installer
# Installs the latest release of the HELM CLI.

REPO="Mindburn-Labs/helm-oss"
BIN_NAME="helm"
INSTALL_DIR="/usr/local/bin"

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${BOLD}HELM Installer${NC}"
echo -e "${BLUE}Models propose. The kernel disposes.${NC}"
echo ""

# 1. Detect OS & Arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

if [ "$ARCH" == "x86_64" ]; then
    ARCH="amd64"
elif [ "$ARCH" == "aarch64" ]; then
    ARCH="arm64"
fi

echo -e "  • Detected OS:   ${BOLD}${OS}${NC}"
echo -e "  • Detected Arch: ${BOLD}${ARCH}${NC}"

# 2. Find Latest Release
echo -e "  • Finding latest release..."
LATEST_RELEASE=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_RELEASE" ]; then
    echo -e "${RED}❌ Error: Could not find latest release.${NC}"
    exit 1
fi

echo -e "  • Version:       ${GREEN}${LATEST_RELEASE}${NC}"

# 3. Download Binary
BINARY_URL="https://github.com/$REPO/releases/download/$LATEST_RELEASE/${BIN_NAME}-${OS}-${ARCH}"
DOWNLOAD_PATH="/tmp/${BIN_NAME}"

echo -e "  • Downloading... (${BINARY_URL})"
curl -L -o "$DOWNLOAD_PATH" "$BINARY_URL" --progress-bar

# 4. Verify Checksum
CHECKSUM_URL="https://github.com/$REPO/releases/download/$LATEST_RELEASE/SHA256SUMS.txt"
CHECKSUM_PATH="${DOWNLOAD_PATH}.sha256"

echo -e "  • Verifying checksum..."
if ! curl -fsSL -o "$CHECKSUM_PATH" "$CHECKSUM_URL" 2>/dev/null; then
	echo -e "${RED}❌ Checksum file not found at ${CHECKSUM_URL}${NC}"
    echo -e "   HELM enforces supply-chain trust. Cannot install without checksum verification."
    echo -e "   If this is a pre-release or local build, use: HELM_SKIP_VERIFY=1"
    rm -f "$DOWNLOAD_PATH"
    if [ "${HELM_SKIP_VERIFY:-0}" != "1" ]; then
        exit 1
    fi
    echo -e "${BLUE}  ⚠️  HELM_SKIP_VERIFY set — proceeding without verification.${NC}"
else
	EXPECTED=$(grep " ${BIN_NAME}-${OS}-${ARCH}\$" "$CHECKSUM_PATH" | awk '{print $1}')
	if [ -z "$EXPECTED" ]; then
		echo -e "${RED}❌ No checksum entry found for ${BIN_NAME}-${OS}-${ARCH}.${NC}"
		rm -f "$DOWNLOAD_PATH" "$CHECKSUM_PATH"
		exit 1
	fi
	ACTUAL=$(shasum -a 256 "$DOWNLOAD_PATH" | awk '{print $1}')
	if [ "$EXPECTED" != "$ACTUAL" ]; then
        echo -e "${RED}❌ Checksum verification FAILED.${NC}"
        echo -e "   Expected: $EXPECTED"
        echo -e "   Got:      $ACTUAL"
        echo -e "   The downloaded binary may have been tampered with."
        rm -f "$DOWNLOAD_PATH" "$CHECKSUM_PATH"
        exit 1
    fi
    echo -e "  • Checksum: ${GREEN}✔ verified${NC}"
    rm -f "$CHECKSUM_PATH"
fi

# 5. Install
echo -e "  • Installing to ${BOLD}${INSTALL_DIR}${NC}..."
chmod +x "$DOWNLOAD_PATH"

if [ -w "$INSTALL_DIR" ]; then
    mv "$DOWNLOAD_PATH" "$INSTALL_DIR/$BIN_NAME"
else
    echo -e "${BLUE}  ℹ️  Sudo required for installation.${NC}"
    sudo mv "$DOWNLOAD_PATH" "$INSTALL_DIR/$BIN_NAME"
fi

# 6. Verify Installation
INSTALLED_VERSION=$($BIN_NAME version 2>/dev/null || echo "unknown")
echo ""
echo -e "${GREEN}✅ HELM Installed Successfully!${NC}"
echo -e "   Location: $(which $BIN_NAME)"
# echo -e "   Version:  $INSTALLED_VERSION"
echo ""
echo -e "Try it now:"
echo -e "   ${BOLD}helm help${NC}"
