#!/usr/bin/env bash
set -euo pipefail
ver=1.23.0
tmp="$(mktemp -d)"
archive="$tmp/oasdiff_${ver}_linux_amd64.tar.gz"
sha256='972b10535c3db4366b9dc3ebc11ca021279af3095267c3cffdca854a3a3c4f89'
curl -fsSL -o "$archive" "https://github.com/oasdiff/oasdiff/releases/download/v${ver}/oasdiff_${ver}_linux_amd64.tar.gz"
printf '%s  %s\n' "$sha256" "$archive" | sha256sum --check --strict -
tar -xzf "$archive" -C "$tmp"
mkdir -p "$HOME/.local/bin"
install -m 0755 "$tmp/oasdiff" "$HOME/.local/bin/oasdiff"
echo "$HOME/.local/bin" >> "$GITHUB_PATH"
