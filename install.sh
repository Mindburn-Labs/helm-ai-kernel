#!/bin/bash
set -e
set -o pipefail

# HELM Installer
# Installs the latest release of the HELM CLI.

REPO="Mindburn-Labs/helm-ai-kernel"
BIN_NAME="helm-ai-kernel"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# sha256 helper: prefer coreutils sha256sum (Linux), fall back to shasum (macOS)
sha256_of() {
    if   command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    elif command -v shasum    >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
    else echo "__NO_SHA_TOOL__"; fi
}

echo -e "${BOLD}HELM Installer${NC}"
echo -e "${BLUE}Fail-closed execution controls for AI agents.${NC}"
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

# 2. Resolve download source (API-free: latest/download redirect, or HELM_VERSION pin)
if [ -n "${HELM_VERSION:-}" ]; then
    BASE="https://github.com/$REPO/releases/download/${HELM_VERSION}"
    echo -e "  • Version:       ${GREEN}${HELM_VERSION}${NC} (pinned)"
else
    BASE="https://github.com/$REPO/releases/latest/download"
    echo -e "  • Version:       ${GREEN}latest${NC}"
fi

# 3. Download Binary
BINARY_URL="${BASE}/${BIN_NAME}-${OS}-${ARCH}"
DOWNLOAD_PATH="/tmp/${BIN_NAME}"

echo -e "  • Downloading... (${BINARY_URL})"
curl -fL --retry 3 --retry-delay 2 --retry-all-errors -o "$DOWNLOAD_PATH" "$BINARY_URL" --progress-bar

# 4. Verify Checksum
CHECKSUM_URL="${BASE}/SHA256SUMS.txt"
CHECKSUM_PATH="${DOWNLOAD_PATH}.sha256"

echo -e "  • Verifying checksum..."
if ! curl -fsSL --retry 3 --retry-delay 2 --retry-all-errors -o "$CHECKSUM_PATH" "$CHECKSUM_URL" 2>/dev/null; then
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
	ACTUAL=$(sha256_of "$DOWNLOAD_PATH")
	if [ "$ACTUAL" = "__NO_SHA_TOOL__" ]; then
		if [ "${HELM_SKIP_VERIFY:-0}" = "1" ]; then
			echo -e "${BLUE}  ⚠️  No sha256 tool found — HELM_SKIP_VERIFY set, skipping checksum.${NC}"
		else
			echo -e "${RED}❌ No sha256 tool (sha256sum or shasum) found to verify the download.${NC}"
			echo -e "   Install coreutils (Linux) or set HELM_SKIP_VERIFY=1 to bypass."
			rm -f "$DOWNLOAD_PATH" "$CHECKSUM_PATH"
			exit 1
		fi
	elif [ "$EXPECTED" != "$ACTUAL" ]; then
        echo -e "${RED}❌ Checksum verification FAILED.${NC}"
        echo -e "   Expected: $EXPECTED"
        echo -e "   Got:      $ACTUAL"
        echo -e "   The downloaded binary may have been tampered with."
        rm -f "$DOWNLOAD_PATH" "$CHECKSUM_PATH"
        exit 1
    else
        echo -e "  • Checksum: ${GREEN}✔ verified${NC}"
    fi
    rm -f "$CHECKSUM_PATH"
fi

# 5. Install
echo -e "  • Installing to ${BOLD}${INSTALL_DIR}${NC}..."
chmod +x "$DOWNLOAD_PATH"

if [ ! -d "$INSTALL_DIR" ]; then
    if ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
        echo -e "${BLUE}  ℹ️  Sudo required to create install directory.${NC}"
        sudo mkdir -p "$INSTALL_DIR"
    fi
fi

if [ -w "$INSTALL_DIR" ]; then
    mv "$DOWNLOAD_PATH" "$INSTALL_DIR/$BIN_NAME"
else
    echo -e "${BLUE}  ℹ️  Sudo required for installation.${NC}"
    sudo mv "$DOWNLOAD_PATH" "$INSTALL_DIR/$BIN_NAME"
fi

# 6. Verify Installation
INSTALLED_BIN="$INSTALL_DIR/$BIN_NAME"
INSTALLED_VERSION=$("$INSTALLED_BIN" version 2>/dev/null || echo "unknown")
echo ""
echo -e "${GREEN}✅ HELM Installed Successfully!${NC}"
echo -e "   Location: $INSTALLED_BIN"
echo -e "   Version:  $INSTALLED_VERSION"
echo ""
echo -e "Try it now:"
echo -e "   ${BOLD}helm-ai-kernel help${NC}"
