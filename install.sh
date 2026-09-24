#!/bin/bash
# quantum_posture: this installer checks an existing classical Sigstore/cosign
# signature on the release checksum file; it implements no cryptographic
# control and makes no post-quantum claim.
set -e
set -o pipefail

# HELM Installer
# Installs a published release of the HELM CLI after verifying that
# SHA256SUMS.txt was signed by the tag release workflow for that exact tag, and
# that the downloaded binary matches its entry in that file.

REPO="Mindburn-Labs/helm-ai-kernel"
BIN_NAME="helm-ai-kernel"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
RELEASE_IDENTITY_PREFIX="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/"
OIDC_ISSUER="https://token.actions.githubusercontent.com"
CURL=(curl --proto '=https' --proto-redir '=https' -fL --retry 3 --retry-delay 2 --retry-all-errors)

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

fail() {
    echo -e "${RED}❌ $1${NC}"
    shift
    for line in "$@"; do echo -e "   $line"; done
    exit 1
}

# HELM_SKIP_VERIFY=1 only allows installing when verification cannot run
# (no cosign, no checksum material, no sha256 tool). A verification that runs
# and fails is always fatal.
skip_or_fail() {
    if [ "${HELM_SKIP_VERIFY:-0}" = "1" ]; then
        echo -e "${BLUE}  ⚠️  $1 HELM_SKIP_VERIFY set: continuing WITHOUT this check.${NC}"
        return 0
    fi
    fail "$@"
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
ASSET="${BIN_NAME}-${OS}-${ARCH}"

echo -e "  • Detected OS:   ${BOLD}${OS}${NC}"
echo -e "  • Detected Arch: ${BOLD}${ARCH}${NC}"

# 2. Resolve the exact release tag (API-free: follow the latest redirect, or
# use the HELM_VERSION pin). The signature check below is bound to this tag.
if [ -n "${HELM_VERSION:-}" ]; then
    TAG="${HELM_VERSION}"
    echo -e "  • Version:       ${GREEN}${TAG}${NC} (pinned)"
else
    LATEST_URL=$("${CURL[@]}" -sS -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest")
    TAG="${LATEST_URL##*/}"
    echo -e "  • Version:       ${GREEN}${TAG}${NC} (latest)"
fi
if ! [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    fail "Could not resolve a release tag (got '${TAG}')." "Set HELM_VERSION=vX.Y.Z to pin a release."
fi
BASE="https://github.com/${REPO}/releases/download/${TAG}"

# 3. Download into a private directory (mktemp -d is mode 0700), so nothing can
# swap the files between verification and installation.
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/${BIN_NAME}-install.XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT
DOWNLOAD_PATH="${WORK_DIR}/${ASSET}"
SUMS_PATH="${WORK_DIR}/SHA256SUMS.txt"
SUMS_BUNDLE_PATH="${SUMS_PATH}.cosign.bundle"

echo -e "  • Downloading... (${BASE}/${ASSET})"
"${CURL[@]}" --progress-bar -o "$DOWNLOAD_PATH" "${BASE}/${ASSET}"

HAVE_SUMS=1
if ! "${CURL[@]}" -sS -o "$SUMS_PATH" "${BASE}/SHA256SUMS.txt" 2>/dev/null ||
   ! "${CURL[@]}" -sS -o "$SUMS_BUNDLE_PATH" "${BASE}/SHA256SUMS.txt.cosign.bundle" 2>/dev/null; then
    HAVE_SUMS=0
    skip_or_fail "SHA256SUMS.txt or its cosign bundle is missing from ${BASE}." \
        "HELM enforces supply-chain trust. Cannot install without signature and checksum verification." \
        "If this is a pre-release or local build, use: HELM_SKIP_VERIFY=1"
fi

# 4. Verify the release signature on SHA256SUMS.txt
if [ "$HAVE_SUMS" = "1" ]; then
    echo -e "  • Verifying release signature..."
    if ! command -v cosign >/dev/null 2>&1; then
        skip_or_fail "cosign is required to verify the release signature." \
            "Install it from https://docs.sigstore.dev/cosign/system_config/installation/" \
            "or set HELM_SKIP_VERIFY=1 to install an UNVERIFIED binary."
    elif cosign verify-blob \
        --bundle "$SUMS_BUNDLE_PATH" \
        --certificate-identity "${RELEASE_IDENTITY_PREFIX}${TAG}" \
        --certificate-oidc-issuer "$OIDC_ISSUER" \
        "$SUMS_PATH" >/dev/null 2>&1; then
        echo -e "  • Signature: ${GREEN}✔ signed by release.yml@refs/tags/${TAG}${NC}"
    else
        fail "Release signature verification FAILED for SHA256SUMS.txt." \
            "Expected signer: ${RELEASE_IDENTITY_PREFIX}${TAG}" \
            "The release files may have been tampered with."
    fi
fi

# 5. Verify the binary against the signed checksum file
if [ "$HAVE_SUMS" = "1" ]; then
    echo -e "  • Verifying checksum..."
    EXPECTED=$(awk -v name="$ASSET" '$2 == name || $2 == "*" name { print $1; exit }' "$SUMS_PATH")
    if [ -z "$EXPECTED" ]; then
        fail "No checksum entry found for ${ASSET}."
    fi
    ACTUAL=$(sha256_of "$DOWNLOAD_PATH")
    if [ "$ACTUAL" = "__NO_SHA_TOOL__" ]; then
        skip_or_fail "No sha256 tool (sha256sum or shasum) found to verify the download." \
            "Install coreutils (Linux) or set HELM_SKIP_VERIFY=1 to bypass."
    elif [ "$EXPECTED" != "$ACTUAL" ]; then
        fail "Checksum verification FAILED." \
            "Expected: $EXPECTED" \
            "Got:      $ACTUAL" \
            "The downloaded binary may have been tampered with."
    else
        echo -e "  • Checksum: ${GREEN}✔ verified${NC}"
    fi
fi

# 6. Install
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

# 7. Verify Installation
INSTALLED_BIN="$INSTALL_DIR/$BIN_NAME"
INSTALLED_VERSION=$("$INSTALLED_BIN" version 2>/dev/null || echo "unknown")
echo ""
echo -e "${GREEN}✅ HELM Installed Successfully!${NC}"
echo -e "   Location: $INSTALLED_BIN"
echo -e "   Version:  $INSTALLED_VERSION"
echo ""
echo -e "Try it now:"
echo -e "   ${BOLD}helm-ai-kernel help${NC}"
