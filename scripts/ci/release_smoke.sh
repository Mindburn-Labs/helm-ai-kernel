#!/usr/bin/env bash
# Release-surface smoke: reproducible binaries, SBOM, OpenVEX, and optional
# cosign bundle verification for a local artifact tree.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1714000000}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/helm-oss-release-smoke.XXXXXX")"
COSIGN_DIR="${COSIGN_ARTIFACT_DIR:-dist}"
REQUIRE_COSIGN="${REQUIRE_COSIGN_BUNDLES:-0}"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "::error::$1 is required for release smoke"
        exit 1
    }
}

require shasum
require python3

cd "$ROOT"

echo "release smoke: first reproducible build"
SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" make release-binaries-reproducible >/dev/null
mkdir -p "$TMP_DIR/build1"
cp bin/helm-* bin/SHA256SUMS.txt "$TMP_DIR/build1/"
shasum -a 256 "$TMP_DIR"/build1/helm-* | sed 's#.*/##' >"$TMP_DIR/build1.sha256"

echo "release smoke: second reproducible build"
rm -f bin/helm-* bin/SHA256SUMS.txt
SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" make release-binaries-reproducible >/dev/null
shasum -a 256 bin/helm-* | sed 's#.*/##' >"$TMP_DIR/build2.sha256"
diff "$TMP_DIR/build1.sha256" "$TMP_DIR/build2.sha256" >/dev/null || {
    echo "::error::reproducible binary hashes differ"
    diff -u "$TMP_DIR/build1.sha256" "$TMP_DIR/build2.sha256" || true
    exit 1
}

echo "release smoke: SBOM and VEX"
make sbom >/dev/null
make vex >/dev/null
python3 - "$ROOT/sbom.json" <<'PY'
import json, sys
payload = json.load(open(sys.argv[1]))
if payload.get("bomFormat") != "CycloneDX":
    raise SystemExit(f"expected CycloneDX SBOM: {payload.get('bomFormat')}")
if not payload.get("components"):
    raise SystemExit("expected SBOM components")
PY
python3 - <<'PY'
import glob, json
paths = glob.glob("release/vex/v*.openvex.json")
if not paths:
    raise SystemExit("expected generated OpenVEX document")
for path in paths:
    payload = json.load(open(path))
    if payload.get("@context") != "https://openvex.dev/ns/v0.2.0":
        raise SystemExit(f"{path} has unexpected OpenVEX context")
PY

if find "$COSIGN_DIR" -name '*.cosign.bundle' -type f 2>/dev/null | grep -q .; then
    bash scripts/release/verify_cosign.sh "$COSIGN_DIR"
elif [ "$REQUIRE_COSIGN" = "1" ]; then
    echo "::error::cosign bundles are required but none were found under $COSIGN_DIR"
    exit 1
else
    echo "::warning::no cosign bundles found under $COSIGN_DIR; set REQUIRE_COSIGN_BUNDLES=1 in release artifact jobs"
fi

echo "release smoke passed"
