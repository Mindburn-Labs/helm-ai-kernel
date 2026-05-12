#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="$ROOT/examples/launch/assets"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$OUT_DIR"

sanitize() {
  python3 -c '
import re
import sys

text = sys.stdin.read()
text = re.sub(r"\x1b\[[0-9;]*m", "", text)
text = re.sub(r"127\.0\.0\.1:[0-9]+", "127.0.0.1:<port>", text)
text = re.sub(r": [0-9]{4,5}", ": <port>", text)
text = re.sub(r"rcpt_[A-Za-z0-9_.:-]+", "rcpt_<id>", text)
text = re.sub(r"dec_[A-Za-z0-9_.:-]+", "dec_<id>", text)
text = re.sub(r"mcp-boundary-[0-9]+", "mcp-boundary-<id>", text)
text = re.sub(r"sha256:[0-9a-f]{64}", "sha256:<hash>", text)
text = re.sub(r"\"signature\":\s*\"[^\"]+\"", "\"signature\":\"<signature>\"", text)
text = re.sub(r"\"timestamp\":\s*\"[^\"]+\"", "\"timestamp\":\"<timestamp>\"", text)
text = re.sub(r"\"created_at\":\s*\"[^\"]+\"", "\"created_at\":\"<timestamp>\"", text)
text = re.sub(r"\"checked_at\":\s*\"[^\"]+\"", "\"checked_at\":\"<timestamp>\"", text)
text = re.sub(r"\"discovered_at\":\s*\"[^\"]+\"", "\"discovered_at\":\"<timestamp>\"", text)
text = re.sub(r"\"approved_at\":\s*\"[^\"]+\"", "\"approved_at\":\"<timestamp>\"", text)
text = re.sub(r"/var/folders/[^ \n\"]+", "/tmp/<temp>", text)
text = re.sub(r"/tmp/helm-[^ \n\"]+", "/tmp/<temp>", text)
sys.stdout.write(text)
'
}

record() {
  local name="$1"
  shift
  local raw="$TMP/${name}.raw.txt"
  local out="$OUT_DIR/${name}.transcript.txt"
  echo "==> Recording ${name}"
  (
    cd "$ROOT"
    "$@"
  ) >"$raw" 2>&1
  sanitize <"$raw" >"$out"
}

record local-demo bash scripts/launch/demo-local.sh
record mcp-quarantine bash scripts/launch/demo-mcp.sh

echo "Recorded sanitized launch transcripts under $OUT_DIR"
