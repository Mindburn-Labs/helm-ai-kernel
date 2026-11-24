#!/usr/bin/env bash
set -e

PACKAGE_VERSION=$(python - <<'PY'
from pathlib import Path
import tomllib
data = tomllib.loads(Path("pyproject.toml").read_text())
print(data["project"]["version"])
PY
)
python - "$PACKAGE_VERSION" <<'PY'
import json
import sys
import urllib.error
import urllib.request

expected = sys.argv[1]
url = f"https://pypi.org/pypi/helm-sdk/{expected}/json"
try:
    with urllib.request.urlopen(url, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))
except urllib.error.HTTPError as exc:
    if exc.code == 404:
        print("missing")
        raise SystemExit(0)
    raise

actual = payload.get("info", {}).get("version")
if actual != expected:
    print(f"mismatch:{actual}")
    raise SystemExit(1)
raise SystemExit(f"Refusing to publish existing helm-sdk version {expected}; choose a fresh version")
PY
