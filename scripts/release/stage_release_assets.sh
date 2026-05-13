#!/usr/bin/env bash
# Stage the complete GitHub Release asset set under dist/release-assets/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="${HELM_VERSION:-${GITHUB_REF_NAME:-}}"
VERSION="${VERSION#v}"
if [[ "$VERSION" == */* || -z "$VERSION" ]]; then
    VERSION="$(cat "$ROOT/VERSION")"
fi
TAG="v${VERSION}"
ASSETS_DIR="${RELEASE_ASSETS_DIR:-$ROOT/dist/release-assets}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/helm-release-assets.XXXXXX")"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_file() {
    local path="$1"
    if [ ! -f "$path" ]; then
        echo "::error::missing release input: $path"
        exit 1
    fi
}

cd "$ROOT"

for artifact in \
    bin/helm-ai-kernel-linux-amd64 \
    bin/helm-ai-kernel-linux-arm64 \
    bin/helm-ai-kernel-darwin-amd64 \
    bin/helm-ai-kernel-darwin-arm64 \
    bin/helm-ai-kernel-windows-amd64.exe \
    bin/helm-ai-kernel \
    dist/helm-ai-kernel.mcpb \
    sbom.json \
    release.high_risk.v3.toml \
    reference_packs/eu_ai_act_high_risk.v1.json; do
    require_file "$ROOT/$artifact"
done

vex_path="$ROOT/release/vex/${TAG}.openvex.json"
if [ ! -f "$vex_path" ]; then
    vex_path="$(find "$ROOT/release/vex" -maxdepth 1 -name 'v*.openvex.json' -type f | sort | tail -n 1)"
fi
require_file "$vex_path"

rm -rf "$ASSETS_DIR"
mkdir -p "$ASSETS_DIR"

cp "$ROOT"/bin/helm-ai-kernel-linux-amd64 "$ASSETS_DIR/"
cp "$ROOT"/bin/helm-ai-kernel-linux-arm64 "$ASSETS_DIR/"
cp "$ROOT"/bin/helm-ai-kernel-darwin-amd64 "$ASSETS_DIR/"
cp "$ROOT"/bin/helm-ai-kernel-darwin-arm64 "$ASSETS_DIR/"
cp "$ROOT"/bin/helm-ai-kernel-windows-amd64.exe "$ASSETS_DIR/"
cp "$ROOT"/dist/helm-ai-kernel.mcpb "$ASSETS_DIR/"
cp "$ROOT"/sbom.json "$ASSETS_DIR/"
cp "$vex_path" "$ASSETS_DIR/$(basename "$vex_path")"
cp "$ROOT"/release.high_risk.v3.toml "$ASSETS_DIR/"

python3 - "$ROOT" "$ASSETS_DIR/sample-policy-material.tar" <<'PY'
import pathlib
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
members = [
    pathlib.Path("release.high_risk.v3.toml"),
    pathlib.Path("reference_packs/eu_ai_act_high_risk.v1.json"),
]
with tarfile.open(out, "w") as tar:
    for rel in members:
        src = root / rel
        info = tar.gettarinfo(str(src), arcname=str(rel))
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        info.mtime = 0
        info.mode = 0o644
        with src.open("rb") as fh:
            tar.addfile(info, fh)
PY

"$ROOT/bin/helm-ai-kernel" conform --level L2 --output "$TMP_DIR/conformance" --json > "$TMP_DIR/conformance-report.json"
pack_root="$(find "$TMP_DIR/conformance" -mindepth 2 -maxdepth 2 -type d -name 'run-*' | sort | tail -n 1)"
if [ -z "$pack_root" ]; then
    echo "::error::conformance did not produce an EvidencePack directory"
    exit 1
fi
"$ROOT/bin/helm-ai-kernel" export --audit --evidence "$pack_root" --out "$ASSETS_DIR/evidence-pack.tar" >/dev/null
"$ROOT/bin/helm-ai-kernel" verify "$ASSETS_DIR/evidence-pack.tar" >/dev/null

(
    cd "$ASSETS_DIR"
    shasum -a 256 helm-ai-kernel-darwin-amd64 helm-ai-kernel-darwin-arm64 helm-ai-kernel-linux-amd64 helm-ai-kernel-linux-arm64 helm-ai-kernel-windows-amd64.exe > "$TMP_DIR/binary-SHA256SUMS.txt"
)
ruby "$ROOT/scripts/release/homebrew_formula.rb" \
    --version "$VERSION" \
    --checksums "$TMP_DIR/binary-SHA256SUMS.txt" \
    --repo Mindburn-Labs/helm-ai-kernel > "$ASSETS_DIR/helm-ai-kernel.rb"

python3 - "$ROOT" "$ASSETS_DIR" "$TAG" <<'PY'
import hashlib
import json
import os
import pathlib
import subprocess
import sys
from datetime import datetime, timezone

root = pathlib.Path(sys.argv[1])
assets_dir = pathlib.Path(sys.argv[2])
tag = sys.argv[3]

def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
artifacts = []
for path in sorted(assets_dir.iterdir(), key=lambda p: p.name):
    if not path.is_file() or path.name in {"release-attestation.json", "SHA256SUMS.txt"}:
        continue
    artifacts.append({
        "name": path.name,
        "sha256": sha256(path),
        "bytes": path.stat().st_size,
    })

payload = {
    "schema_version": "helm.release.attestation.v1",
    "release": tag,
    "version": tag.removeprefix("v"),
    "source_repository": "Mindburn-Labs/helm-ai-kernel",
    "source_commit": commit,
    "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "offline_checks": {
        "evidence_pack_verified": True,
        "sample_policy_material_includes_reference_pack": True,
        "homebrew_formula_generated": True,
    },
    "artifacts": artifacts,
}
(assets_dir / "release-attestation.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

(
    cd "$ASSETS_DIR"
    find . -maxdepth 1 -type f ! -name SHA256SUMS.txt -print |
        sed 's#^\./##' |
        sort |
        xargs shasum -a 256 > SHA256SUMS.txt
    shasum -a 256 -c SHA256SUMS.txt
)

echo "staged release assets in $ASSETS_DIR"
