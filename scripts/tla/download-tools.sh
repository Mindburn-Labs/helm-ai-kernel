#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE_DIR="${ROOT_DIR}/.cache/tlc"
VERSION="${TLA_TOOLS_VERSION:-latest}"
JAR_URL="${TLA_TOOLS_JAR_URL:-}"

mkdir -p "${CACHE_DIR}"

if [[ -z "${JAR_URL}" ]]; then
  if [[ "${VERSION}" == "latest" ]]; then
    JAR_URL="https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar"
  else
    JAR_URL="https://github.com/tlaplus/tlaplus/releases/download/${VERSION}/tla2tools.jar"
  fi
fi

JAR_PATH="${CACHE_DIR}/tlc-${VERSION//[^A-Za-z0-9._-]/_}.jar"

if [[ ! -s "${JAR_PATH}" ]]; then
  tmp="${JAR_PATH}.tmp"
  curl -fsSL "${JAR_URL}" -o "${tmp}"
  mv "${tmp}" "${JAR_PATH}"
fi

echo "${JAR_PATH}"
