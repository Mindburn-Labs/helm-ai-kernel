#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE_DIR="${ROOT_DIR}/.cache/tlc"
ARTIFACT=${TLA_ARTIFACT:-"tla2""tools"}
VERSION="${TLA_TOOLS_VERSION:-}"

mkdir -p "${CACHE_DIR}"

if [[ -z "${VERSION}" ]]; then
  META_URL="https://repo1.maven.org/maven2/org/lamport/${ARTIFACT}/maven-metadata.xml"
  VERSION="$(curl -fsSL "${META_URL}" | sed -n 's:.*<latest>\\(.*\\)</latest>.*:\\1:p' | head -n 1)"
fi

if [[ -z "${VERSION}" ]]; then
  echo "Unable to resolve TLC tools version" >&2
  exit 1
fi

JAR_PATH="${CACHE_DIR}/tlc.jar"
JAR_URL="https://repo1.maven.org/maven2/org/lamport/${ARTIFACT}/${VERSION}/${ARTIFACT}-${VERSION}.jar"

if [[ ! -s "${JAR_PATH}" ]]; then
  tmp="${JAR_PATH}.tmp"
  curl -fsSL "${JAR_URL}" -o "${tmp}"
  mv "${tmp}" "${JAR_PATH}"
fi

echo "${JAR_PATH}"
