#!/usr/bin/env bash
# Release-surface smoke: reproducible binaries (the kernel and the standalone
# receipt_verify verifier), SBOM, OpenVEX, and optional cosign bundle
# verification for a local artifact tree.
# quantum_posture: this smoke only checks release artifact plumbing; it does not
# certify signature algorithms or hybrid/PQ posture.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1714000000}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/helm-ai-kernel-release-smoke.XXXXXX")"
COSIGN_DIR="${COSIGN_ARTIFACT_DIR:-dist}"
REQUIRE_COSIGN="${REQUIRE_COSIGN_BUNDLES:-0}"
SMOKE_VEX_VERSION="release-smoke"

cleanup() {
    rm -rf "$TMP_DIR"
    rm -f "$ROOT/release/vex/v${SMOKE_VEX_VERSION}.openvex.json"
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
cp bin/helm-ai-kernel-* bin/receipt_verify-* bin/SHA256SUMS.txt "$TMP_DIR/build1/"
# Drop only the directory: each line keeps its hash, so the diff below compares
# contents, not just file names.
shasum -a 256 "$TMP_DIR"/build1/helm-* "$TMP_DIR"/build1/receipt_verify-* | sed 's#  .*/#  #' >"$TMP_DIR/build1.sha256"

echo "release smoke: second reproducible build"
rm -f bin/helm-ai-kernel-* bin/receipt_verify-* bin/SHA256SUMS.txt
SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" make release-binaries-reproducible >/dev/null
shasum -a 256 bin/helm-ai-kernel-* bin/receipt_verify-* | sed 's#  .*/#  #' >"$TMP_DIR/build2.sha256"
diff "$TMP_DIR/build1.sha256" "$TMP_DIR/build2.sha256" >/dev/null || {
    echo "::error::reproducible binary hashes differ"
    diff -u "$TMP_DIR/build1.sha256" "$TMP_DIR/build2.sha256" || true
    exit 1
}

# The verifier ships as release assets of its own. Fail when the build output
# lacks any of them or when the host's build does not behave like a verifier.
echo "release smoke: receipt_verify assets (build output)"
python3 scripts/release/check_receipt_verify_assets.py bin

# The smoke checks the build output only. A staged release checks itself:
# stage_release_assets.sh runs the same checker on the staged directory before
# it writes SHA256SUMS.txt and the attestation, and the release workflow's
# binaries job runs it again on dist/release-assets before attesting. The
# release-smoke job runs before any staging, so there is no staged tree here.

echo "release smoke: SBOM and VEX"
make sbom >/dev/null
SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" HELM_VERSION="$SMOKE_VEX_VERSION" bash scripts/release/generate_vex.sh >/dev/null
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

payload = json.load(open("release/vex/vrelease-smoke.openvex.json"))
products = {
    statement["vulnerability"]["name"]: statement["products"][0]["@id"]
    for statement in payload["statements"]
}
expected = {
    "GO-2026-5932": "pkg:golang/golang.org/x/crypto@v0.57.0",
}
for vulnerability, product in expected.items():
    if products.get(vulnerability) != product:
        raise SystemExit(
            f"{vulnerability} VEX product {products.get(vulnerability)!r} != {product!r}"
        )
PY

if find "$COSIGN_DIR" -name '*.cosign.bundle' -type f 2>/dev/null | grep -q .; then
    bash scripts/release/verify_cosign.sh "$COSIGN_DIR"
elif [ "$REQUIRE_COSIGN" = "1" ]; then
    echo "::error::cosign bundles are required but none were found under $COSIGN_DIR"
    exit 1
else
    echo "release smoke: no cosign bundles found under $COSIGN_DIR; set REQUIRE_COSIGN_BUNDLES=1 where bundles are mandatory"
fi

echo "release smoke passed"
