#!/usr/bin/env bash
# Mirror a signed app-helm-console web bundle into the kernel release asset set.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ASSETS_DIR="${1:-${RELEASE_ASSETS_DIR:-$ROOT/dist/release-assets}}"
BUNDLE="${HELM_CONSOLE_BUNDLE:-}"
LOCK="${HELM_CONSOLE_BUNDLE_LOCK:-$ROOT/release/console-bundle.lock.json}"
STRICT="${REQUIRE_HELM_CONSOLE_BUNDLE:-0}"

if [ -z "$BUNDLE" ]; then
    if [ "$STRICT" = "1" ]; then
        echo "::error file=scripts/release/stage_console_bundle.sh::HELM_CONSOLE_BUNDLE is required when REQUIRE_HELM_CONSOLE_BUNDLE=1" >&2
        exit 1
    fi
    echo "console bundle: HELM_CONSOLE_BUNDLE not set; skipping"
    exit 0
fi

if [ ! -f "$BUNDLE" ]; then
    echo "::error file=scripts/release/stage_console_bundle.sh::missing console bundle: $BUNDLE" >&2
    exit 1
fi
if [ ! -f "$LOCK" ]; then
    echo "::error file=scripts/release/stage_console_bundle.sh::missing console bundle lock: $LOCK" >&2
    exit 1
fi

mkdir -p "$ASSETS_DIR"

python3 - "$BUNDLE" "$LOCK" <<'PY'
import hashlib
import json
import pathlib
import sys

bundle = pathlib.Path(sys.argv[1])
lock = pathlib.Path(sys.argv[2])
metadata = json.loads(lock.read_text(encoding="utf-8"))
expected_name = metadata.get("bundle_name")
expected_sha = metadata.get("sha256")
if metadata.get("schema_version") != "helm.console.web_bundle.lock.v1":
    raise SystemExit("invalid console bundle lock schema_version")
if bundle.name != expected_name:
    raise SystemExit(f"bundle name {bundle.name!r} does not match lock {expected_name!r}")
digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
if digest != expected_sha:
    raise SystemExit(f"bundle sha256 {digest} does not match lock {expected_sha}")
print(json.dumps(metadata, sort_keys=True))
PY

copy_sidecar() {
    local rel="$1"
    local required="$2"
    if [ -z "$rel" ]; then
        return
    fi
    local path
    path="$(dirname "$BUNDLE")/$rel"
    if [ -f "$path" ]; then
        cp "$path" "$ASSETS_DIR/"
        return
    fi
    if [ "$required" = "1" ]; then
        echo "::error file=scripts/release/stage_console_bundle.sh::missing required console bundle sidecar: $path" >&2
        exit 1
    fi
}

cp "$BUNDLE" "$ASSETS_DIR/"
cp "$LOCK" "$ASSETS_DIR/"

checksum="$(python3 - "$LOCK" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")).get("checksum", ""))
PY
)"
sbom="$(python3 - "$LOCK" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")).get("sbom", ""))
PY
)"
provenance="$(python3 - "$LOCK" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")).get("provenance", ""))
PY
)"
cosign_bundle="$(python3 - "$LOCK" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")).get("cosign_bundle", ""))
PY
)"
manifest="$(python3 - "$LOCK" <<'PY'
import json, pathlib, sys
metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(metadata.get("manifest", metadata.get("bundle_name", "") + ".manifest.json"))
PY
)"

copy_sidecar "$checksum" "$STRICT"
copy_sidecar "$sbom" "$STRICT"
copy_sidecar "$provenance" "$STRICT"
copy_sidecar "$manifest" "$STRICT"
copy_sidecar "$cosign_bundle" "$STRICT"

echo "console bundle: staged $(basename "$BUNDLE") into $ASSETS_DIR"
