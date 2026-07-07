#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE_DIR="${ROOT_DIR}/.cache/tlc"
DEFAULT_TLA_TOOLS_VERSION="v1.8.0"
DEFAULT_TLA_TOOLS_JAR_URL="https://github.com/Mindburn-Labs/helm-ai-kernel/releases/download/deps-tla2tools-v1.8.0/tla2tools-v1.8.0.jar"
# tlaplus v1.8.0 is a rolling pre-release upstream, so CI defaults to the
# org-controlled mirror above and keeps the digest check as the immutable gate.
DEFAULT_TLA_TOOLS_SHA256="9e27b5e19a69ae1f56aabf8403a6ed5598dbfa6e638908e5278ac39736c1543d"
VERSION="${TLA_TOOLS_VERSION:-$DEFAULT_TLA_TOOLS_VERSION}"
EXPECTED_SHA256="${TLA_TOOLS_SHA256:-}"
JAR_URL="${TLA_TOOLS_JAR_URL:-}"

mkdir -p "${CACHE_DIR}"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
    return
  fi
  echo "sha256sum or shasum is required to verify tla2tools.jar" >&2
  exit 1
}

if [[ -z "${VERSION}" || "${VERSION}" == "latest" ]]; then
  echo "TLA_TOOLS_VERSION must be an immutable release tag, not 'latest'" >&2
  exit 1
fi

if [[ -z "${JAR_URL}" ]]; then
  if [[ "${VERSION}" == "${DEFAULT_TLA_TOOLS_VERSION}" ]]; then
    JAR_URL="${DEFAULT_TLA_TOOLS_JAR_URL}"
  else
    JAR_URL="https://github.com/tlaplus/tlaplus/releases/download/${VERSION}/tla2tools.jar"
  fi
fi

if [[ "${JAR_URL}" != https://* ]]; then
  echo "TLA_TOOLS_JAR_URL must use HTTPS" >&2
  exit 1
fi

if [[ -z "${EXPECTED_SHA256}" && "${VERSION}" == "${DEFAULT_TLA_TOOLS_VERSION}" && "${JAR_URL}" == "${DEFAULT_TLA_TOOLS_JAR_URL}" ]]; then
  EXPECTED_SHA256="${DEFAULT_TLA_TOOLS_SHA256}"
fi

if [[ ! "${EXPECTED_SHA256}" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "TLA_TOOLS_SHA256 must be a 64-character SHA-256 digest for ${JAR_URL}" >&2
  exit 1
fi

JAR_PATH="${CACHE_DIR}/tlc-${VERSION//[^A-Za-z0-9._-]/_}-${EXPECTED_SHA256:0:12}.jar"

verify_jar() {
  actual="$(sha256_file "$1")"
  actual_lower="$(printf '%s' "${actual}" | tr '[:upper:]' '[:lower:]')"
  expected_lower="$(printf '%s' "${EXPECTED_SHA256}" | tr '[:upper:]' '[:lower:]')"
  if [[ "${actual_lower}" != "${expected_lower}" ]]; then
    echo "tla2tools.jar SHA-256 mismatch: got ${actual}, want ${EXPECTED_SHA256}" >&2
    return 1
  fi
}

if [[ -s "${JAR_PATH}" ]]; then
  if ! verify_jar "${JAR_PATH}"; then
    rm -f "${JAR_PATH}"
  fi
fi

if [[ ! -s "${JAR_PATH}" ]]; then
  tmp="${JAR_PATH}.tmp"
  rm -f "${tmp}"
  curl -fsSL "${JAR_URL}" -o "${tmp}"
  verify_jar "${tmp}"
  mv "${tmp}" "${JAR_PATH}"
fi

echo "${JAR_PATH}"
