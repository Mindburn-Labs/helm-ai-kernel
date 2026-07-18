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
TMP_PARENT="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
mkdir -p "$TMP_PARENT"
TMP_DIR="$(mktemp -d "$TMP_PARENT/helm-release-assets.XXXXXX")"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

on_error() {
    local exit_code=$?
    echo "::error file=scripts/release/stage_release_assets.sh::release asset staging failed at: ${BASH_COMMAND} (exit ${exit_code})" >&2
    exit "$exit_code"
}
trap on_error ERR

log_step() {
    echo "release assets: $*"
}

require_file() {
    local path="$1"
    if [ ! -f "$path" ]; then
        echo "::error file=scripts/release/stage_release_assets.sh::missing release input: $path" >&2
        exit 1
    fi
}

require_clean_source() {
    # Release assets and their attestation must describe one committed source
    # tree. Build outputs are ignored; any tracked or untracked source edit is
    # a hard stop so an attestation can never claim a different HEAD.
    if [ -n "$(git status --porcelain=v1 --untracked-files=all)" ]; then
        echo "::error file=scripts/release/stage_release_assets.sh::refusing to attest release assets from a dirty source tree" >&2
        git status --short >&2
        exit 1
    fi
}

print_conformance_failures() {
    local report="$1"
    python3 - "$report" <<'PY' >&2 || cat "$report" >&2
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    payload = json.load(fh)

print(f"conformance pass: {payload.get('pass')}")
for gate in payload.get("gate_results", []):
    if gate.get("pass"):
        continue
    print(f"- {gate.get('gate_id')}: failed")
    for reason in gate.get("reasons", []):
        print(f"  - {reason}")
PY
}

cd "$ROOT"

require_clean_source

log_step "staging $TAG into $ASSETS_DIR"

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
    if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
        echo "::error file=scripts/release/stage_release_assets.sh::missing exact OpenVEX document for $TAG" >&2
        exit 1
    fi
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

log_step "generating release conformance evidence"
conformance_dir="$TMP_DIR/conformance"
conformance_report="$conformance_dir/conform_report.json"
HELM_CONFORMANCE_ARTIFACTS_DIR="$ROOT/artifacts" bash "$ROOT/scripts/release/prepare_conformance_release_inputs.sh"
if ! HELM_RELEASE_EVIDENCE_RECEIPT=1 "$ROOT/bin/helm-ai-kernel" conform --profile SMB --gate G0 --signed --output "$conformance_dir" > "$TMP_DIR/conformance-run.log"; then
	echo "::error file=scripts/release/stage_release_assets.sh::conformance failed during release asset staging" >&2
	if [ -f "$conformance_report" ]; then
		print_conformance_failures "$conformance_report"
	else
		cat "$TMP_DIR/conformance-run.log" >&2
	fi
	exit 1
fi
if ! bash "$ROOT/scripts/release/conformance_release_gate.sh" "$conformance_report"; then
	echo "::error file=scripts/release/stage_release_assets.sh::release conformance gate rejected staged EvidencePack" >&2
	exit 1
fi
pack_root="$(find "$conformance_dir" -mindepth 2 -maxdepth 2 -type d -name 'run-*' | sort | tail -n 1)"
if [ -z "$pack_root" ]; then
    echo "::error file=scripts/release/stage_release_assets.sh::conformance did not produce an EvidencePack directory" >&2
    exit 1
fi
"$ROOT/bin/helm-ai-kernel" export --audit --evidence "$pack_root" --out "$ASSETS_DIR/evidence-pack.tar"
"$ROOT/bin/helm-ai-kernel" verify "$ASSETS_DIR/evidence-pack.tar"
tampered_pack="$TMP_DIR/evidence-pack-tampered.tar"
python3 - "$ASSETS_DIR/evidence-pack.tar" "$tampered_pack" <<'PY'
import copy
import io
import pathlib
import sys
import tarfile

src = pathlib.Path(sys.argv[1])
dst = pathlib.Path(sys.argv[2])

with tarfile.open(src, "r:*") as inp, tarfile.open(dst, "w") as out:
    for member in inp.getmembers():
        cloned = copy.copy(member)
        if member.isfile():
            fileobj = inp.extractfile(member)
            if fileobj is None:
                raise SystemExit(f"missing file object for {member.name}")
            with fileobj:
                out.addfile(cloned, fileobj)
        else:
            out.addfile(cloned)

    payload = b'{"tampered":true}\n'
    info = tarfile.TarInfo("06_PROOFGRAPH/unindexed-release-tamper.json")
    info.size = len(payload)
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.mode = 0o644
    info.mtime = 0
    out.addfile(info, io.BytesIO(payload))
PY
if "$ROOT/bin/helm-ai-kernel" verify "$tampered_pack" > "$TMP_DIR/tampered-verify.log" 2>&1; then
    echo "::error file=scripts/release/stage_release_assets.sh::tampered release EvidencePack unexpectedly verified" >&2
    cat "$TMP_DIR/tampered-verify.log" >&2
    exit 1
fi
log_step "tampered release EvidencePack rejected"

(
    cd "$ASSETS_DIR"
    shasum -a 256 helm-ai-kernel-darwin-amd64 helm-ai-kernel-darwin-arm64 helm-ai-kernel-linux-amd64 helm-ai-kernel-linux-arm64 helm-ai-kernel-windows-amd64.exe > "$TMP_DIR/binary-SHA256SUMS.txt"
)
python3 - "$ROOT" "$ASSETS_DIR/helm-ai-kernel-launchpad-data.tar" <<'PY'
import pathlib
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])

targets = ["registry/launchpad", "registry/launchkit", "policies/launchpad"]
paths = []

for target in targets:
    tpath = root / target
    if tpath.exists():
        paths.append(pathlib.Path(target))
        for p in tpath.rglob("*"):
            paths.append(p.relative_to(root))

paths = sorted(list(set(paths)), key=lambda p: p.as_posix())

with tarfile.open(out, "w") as tar:
    for rel in paths:
        src = root / rel
        info = tar.gettarinfo(str(src), arcname=rel.as_posix())
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        info.mtime = 0
        if src.is_dir():
            info.mode = 0o755
            tar.addfile(info)
        elif src.is_file():
            is_exe = (src.stat().st_mode & 0o111) != 0
            info.mode = 0o755 if is_exe else 0o644
            with src.open("rb") as fh:
                tar.addfile(info, fh)
PY
launchpad_data_sha="$(shasum -a 256 "$ASSETS_DIR/helm-ai-kernel-launchpad-data.tar" | awk '{print $1}')"

ruby "$ROOT/scripts/release/homebrew_formula.rb" \
    --version "$VERSION" \
    --checksums "$TMP_DIR/binary-SHA256SUMS.txt" \
    --launchpad-data-sha256 "$launchpad_data_sha" \
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
public_docs_manifest_path = root / "docs" / "public-docs.manifest.json"
public_docs_manifest = json.loads(public_docs_manifest_path.read_text(encoding="utf-8"))
api_contract = public_docs_manifest.get("api_contract")
if not isinstance(api_contract, dict):
    raise SystemExit("public docs manifest is missing api_contract")
if api_contract.get("schema_version") != 1:
    raise SystemExit("public docs API contract schema_version must be 1")
if api_contract.get("source_path") != "api/openapi/helm.openapi.yaml":
    raise SystemExit("public docs API contract source_path must be api/openapi/helm.openapi.yaml")
openapi_path = root / api_contract["source_path"]
actual_openapi_sha256 = "sha256:" + sha256(openapi_path)
if api_contract.get("content_sha256") != actual_openapi_sha256:
    raise SystemExit("public docs API contract content_sha256 does not match OpenAPI source")
actual_openapi_blob = subprocess.check_output(
    ["git", "hash-object", api_contract["source_path"]], cwd=root, text=True
).strip()
if api_contract.get("git_blob_sha1") != actual_openapi_blob:
    raise SystemExit("public docs API contract git_blob_sha1 does not match OpenAPI source")
if not isinstance(api_contract.get("public_operations"), list) or not api_contract["public_operations"]:
    raise SystemExit("public docs API contract must declare public_operations")
public_docs_contract = {
    "manifest_path": "docs/public-docs.manifest.json",
    "manifest_sha256": "sha256:" + sha256(public_docs_manifest_path),
    "api_contract": api_contract,
}

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
    "public_docs_contract": public_docs_contract,
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
