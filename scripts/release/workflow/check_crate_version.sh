#!/usr/bin/env bash
set -e

CARGO_VERSION=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
echo "version=$CARGO_VERSION" >> "$GITHUB_OUTPUT"
status=$(python - "$CARGO_VERSION" <<'PY'
import json
import sys
import urllib.error
import urllib.request

expected = sys.argv[1]
req = urllib.request.Request(
    f"https://crates.io/api/v1/crates/helm-sdk/{expected}",
    headers={"User-Agent": "MindburnLabs-VersionDriftGuard/1.0"},
)
try:
    with urllib.request.urlopen(req, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))
except urllib.error.HTTPError as exc:
    if exc.code == 404:
        print("missing")
        raise SystemExit(0)
    raise

actual = payload.get("version", {}).get("num")
if actual != expected:
    print(f"mismatch:{actual}")
    raise SystemExit(1)
print("published")
PY
)
if [ "$status" = "published" ]; then
  echo "published=true" >> "$GITHUB_OUTPUT"
else
  echo "published=false" >> "$GITHUB_OUTPUT"
fi
