#!/usr/bin/env bash
set -euo pipefail

version="34.1"
sha256="af27ea66cd26938fe48587804ca7d4817457a08350021a1c6e23a27ccc8c6904"

if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
    echo "::error::install_protoc.sh supports the Linux x86_64 GitHub runner only"
    exit 1
fi
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_PATH:?GITHUB_PATH is required}"

download_dir="$(mktemp -d "${RUNNER_TEMP}/protoc-download.XXXXXX")"
archive="${download_dir}/protoc-${version}-linux-x86_64.zip"
install_dir="${RUNNER_TEMP}/protoc-${version}"
trap 'rm -rf "$download_dir"' EXIT

curl -fsSL --retry 5 --retry-all-errors \
    -o "$archive" \
    "https://github.com/protocolbuffers/protobuf/releases/download/v${version}/protoc-${version}-linux-x86_64.zip"
printf '%s  %s\n' "$sha256" "$archive" | sha256sum --check --strict -
mkdir -p "$install_dir"
unzip -oq "$archive" -d "$install_dir"
printf '%s\n' "$install_dir/bin" >>"$GITHUB_PATH"
"$install_dir/bin/protoc" --version
