#!/usr/bin/env bash
# Stage the complete GitHub Release asset set under dist/release-assets/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# A detached checkout has no local mise trust record. Keep direct tool paths
# but remove only its dispatcher shims so staging never needs `mise trust`.
SANITIZED_PATH=""
IFS=: read -r -a PATH_PARTS <<< "$PATH"
for PATH_PART in "${PATH_PARTS[@]}"; do
    case "$PATH_PART" in
        ""|*/mise/shims) continue ;;
    esac
    SANITIZED_PATH="${SANITIZED_PATH:+$SANITIZED_PATH:}$PATH_PART"
done
PATH="$SANITIZED_PATH"
export PATH
# A caller can also export the shim toolchain's GOROOT/GOBIN. Let the selected
# direct `go` executable resolve its own matching toolchain inside the snapshot.
unset GOROOT GOBIN

ASSETS_DIR="${RELEASE_ASSETS_DIR:-$ROOT/dist/release-assets}"
TMP_PARENT="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
mkdir -p "$TMP_PARENT"
TMP_DIR="$(mktemp -d "$TMP_PARENT/helm-release-assets.XXXXXX")"
SNAPSHOT_ROOT="$TMP_DIR/source"
SNAPSHOT_WORKTREE_CREATED=0

cleanup() {
    # Remove the exact detached checkout through Git so its ignored build
    # outputs can never be mistaken for inputs to a later staging run.
    if [ "$SNAPSHOT_WORKTREE_CREATED" = "1" ]; then
        git -C "$ROOT" worktree remove --force "$SNAPSHOT_ROOT" >/dev/null 2>&1 || true
    fi
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
    if [ -n "$(git -C "$ROOT" status --porcelain=v1 --untracked-files=all)" ]; then
        echo "::error file=scripts/release/stage_release_assets.sh::refusing to attest release assets from a dirty source tree" >&2
        git -C "$ROOT" status --short >&2
        exit 1
    fi
}

require_clean_snapshot() {
    if [ -n "$(git -C "$SNAPSHOT_ROOT" status --porcelain=v1 --untracked-files=all)" ]; then
        echo "::error file=scripts/release/stage_release_assets.sh::detached source snapshot changed during release asset staging" >&2
        git -C "$SNAPSHOT_ROOT" status --short >&2
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

require_clean_source
SOURCE_COMMIT="$(git -C "$ROOT" rev-parse --verify 'HEAD^{commit}')"
SOURCE_TREE="$(git -C "$ROOT" rev-parse --verify "${SOURCE_COMMIT}^{tree}")"

git -C "$ROOT" worktree add --detach "$SNAPSHOT_ROOT" "$SOURCE_COMMIT" >/dev/null
SNAPSHOT_WORKTREE_CREATED=1

if [ "$(git -C "$SNAPSHOT_ROOT" rev-parse --verify 'HEAD^{commit}')" != "$SOURCE_COMMIT" ] || \
    [ "$(git -C "$SNAPSHOT_ROOT" rev-parse --verify 'HEAD^{tree}')" != "$SOURCE_TREE" ]; then
    echo "::error file=scripts/release/stage_release_assets.sh::detached source snapshot does not match captured source objects" >&2
    exit 1
fi

VERSION="${HELM_VERSION:-${GITHUB_REF_NAME:-}}"
VERSION="${VERSION#v}"
if [[ "$VERSION" == */* || -z "$VERSION" ]]; then
    VERSION="$(cat "$SNAPSHOT_ROOT/VERSION")"
fi
TAG="v${VERSION}"

require_source_snapshot_current() {
    # The release must stay on the clean source commit captured before any
    # expensive staging. The attestation reads Git objects from this snapshot,
    # never mutable files in the working tree.
    require_clean_source
    require_clean_snapshot
    local current_commit
    current_commit="$(git -C "$ROOT" rev-parse --verify 'HEAD^{commit}')"
    if [ "$current_commit" != "$SOURCE_COMMIT" ]; then
        echo "::error file=scripts/release/stage_release_assets.sh::source commit changed during release asset staging" >&2
        exit 1
    fi
    if [ "$(git -C "$SNAPSHOT_ROOT" rev-parse --verify 'HEAD^{commit}')" != "$SOURCE_COMMIT" ] || \
        [ "$(git -C "$SNAPSHOT_ROOT" rev-parse --verify 'HEAD^{tree}')" != "$SOURCE_TREE" ]; then
        echo "::error file=scripts/release/stage_release_assets.sh::detached source snapshot changed during release asset staging" >&2
        exit 1
    fi
}

log_step "staging $TAG into $ASSETS_DIR"
log_step "building release inputs from detached source snapshot $SOURCE_COMMIT"
make -C "$SNAPSHOT_ROOT" docs-truth docs-openapi-parity release-binaries-reproducible mcp-pack sbom vex
require_source_snapshot_current

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
    require_file "$SNAPSHOT_ROOT/$artifact"
done

vex_path="$SNAPSHOT_ROOT/release/vex/${TAG}.openvex.json"
if [ ! -f "$vex_path" ]; then
    if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
        echo "::error file=scripts/release/stage_release_assets.sh::missing exact OpenVEX document for $TAG" >&2
        exit 1
    fi
    vex_path="$(find "$SNAPSHOT_ROOT/release/vex" -maxdepth 1 -name 'v*.openvex.json' -type f | sort | tail -n 1)"
fi
require_file "$vex_path"

rm -rf "$ASSETS_DIR"
mkdir -p "$ASSETS_DIR"

cp "$SNAPSHOT_ROOT"/bin/helm-ai-kernel-linux-amd64 "$ASSETS_DIR/"
cp "$SNAPSHOT_ROOT"/bin/helm-ai-kernel-linux-arm64 "$ASSETS_DIR/"
cp "$SNAPSHOT_ROOT"/bin/helm-ai-kernel-darwin-amd64 "$ASSETS_DIR/"
cp "$SNAPSHOT_ROOT"/bin/helm-ai-kernel-darwin-arm64 "$ASSETS_DIR/"
cp "$SNAPSHOT_ROOT"/bin/helm-ai-kernel-windows-amd64.exe "$ASSETS_DIR/"
cp "$SNAPSHOT_ROOT"/dist/helm-ai-kernel.mcpb "$ASSETS_DIR/"
cp "$SNAPSHOT_ROOT"/sbom.json "$ASSETS_DIR/"
cp "$vex_path" "$ASSETS_DIR/$(basename "$vex_path")"
cp "$SNAPSHOT_ROOT"/release.high_risk.v3.toml "$ASSETS_DIR/"

python3 - "$SNAPSHOT_ROOT" "$ASSETS_DIR/sample-policy-material.tar" <<'PY'
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
HELM_CONFORMANCE_ARTIFACTS_DIR="$SNAPSHOT_ROOT/artifacts" bash "$SNAPSHOT_ROOT/scripts/release/prepare_conformance_release_inputs.sh"
if ! (
    cd "$SNAPSHOT_ROOT"
    HELM_RELEASE_EVIDENCE_RECEIPT=1 "$SNAPSHOT_ROOT/bin/helm-ai-kernel" conform --profile SMB --gate G0 --signed --output "$conformance_dir"
) > "$TMP_DIR/conformance-run.log"; then
	echo "::error file=scripts/release/stage_release_assets.sh::conformance failed during release asset staging" >&2
	if [ -f "$conformance_report" ]; then
		print_conformance_failures "$conformance_report"
	else
		cat "$TMP_DIR/conformance-run.log" >&2
	fi
	exit 1
fi
if ! bash "$SNAPSHOT_ROOT/scripts/release/conformance_release_gate.sh" "$conformance_report"; then
	echo "::error file=scripts/release/stage_release_assets.sh::release conformance gate rejected staged EvidencePack" >&2
	exit 1
fi
pack_root="$(find "$conformance_dir" -mindepth 2 -maxdepth 2 -type d -name 'run-*' | sort | tail -n 1)"
if [ -z "$pack_root" ]; then
    echo "::error file=scripts/release/stage_release_assets.sh::conformance did not produce an EvidencePack directory" >&2
    exit 1
fi
(
    cd "$SNAPSHOT_ROOT"
    "$SNAPSHOT_ROOT/bin/helm-ai-kernel" export --audit --evidence "$pack_root" --out "$ASSETS_DIR/evidence-pack.tar"
    "$SNAPSHOT_ROOT/bin/helm-ai-kernel" verify "$ASSETS_DIR/evidence-pack.tar"
)
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
if (
    cd "$SNAPSHOT_ROOT"
    "$SNAPSHOT_ROOT/bin/helm-ai-kernel" verify "$tampered_pack"
) > "$TMP_DIR/tampered-verify.log" 2>&1; then
    echo "::error file=scripts/release/stage_release_assets.sh::tampered release EvidencePack unexpectedly verified" >&2
    cat "$TMP_DIR/tampered-verify.log" >&2
    exit 1
fi
log_step "tampered release EvidencePack rejected"

(
    cd "$ASSETS_DIR"
    shasum -a 256 helm-ai-kernel-darwin-amd64 helm-ai-kernel-darwin-arm64 helm-ai-kernel-linux-amd64 helm-ai-kernel-linux-arm64 helm-ai-kernel-windows-amd64.exe > "$TMP_DIR/binary-SHA256SUMS.txt"
)
python3 - "$SNAPSHOT_ROOT" "$ASSETS_DIR/helm-ai-kernel-launchpad-data.tar" <<'PY'
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

ruby "$SNAPSHOT_ROOT/scripts/release/homebrew_formula.rb" \
    --version "$VERSION" \
    --checksums "$TMP_DIR/binary-SHA256SUMS.txt" \
    --launchpad-data-sha256 "$launchpad_data_sha" \
    --repo Mindburn-Labs/helm-ai-kernel > "$ASSETS_DIR/helm-ai-kernel.rb"

# Bind the release attestation to the exact source snapshot captured above.
require_source_snapshot_current

HELM_RELEASE_SOURCE_COMMIT="$SOURCE_COMMIT" \
    HELM_RELEASE_SOURCE_TREE="$SOURCE_TREE" \
    python3 - "$SNAPSHOT_ROOT" "$ASSETS_DIR" "$TAG" <<'PY'
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

source_commit = os.environ["HELM_RELEASE_SOURCE_COMMIT"]
source_tree = os.environ["HELM_RELEASE_SOURCE_TREE"]

def git_text(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()

def git_show(revision: str) -> bytes:
    return subprocess.check_output(["git", "show", revision], cwd=root)

if git_text("rev-parse", "--verify", f"{source_commit}^{{tree}}") != source_tree:
    raise SystemExit("release source tree does not match source commit")

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

public_docs_manifest_path = "docs/public-docs.manifest.json"
public_docs_manifest_data = git_show(f"{source_commit}:{public_docs_manifest_path}")
public_docs_manifest = json.loads(public_docs_manifest_data)
api_contract = public_docs_manifest.get("api_contract")
if not isinstance(api_contract, dict):
    raise SystemExit("public docs manifest is missing api_contract")
if api_contract.get("schema_version") != 1:
    raise SystemExit("public docs API contract schema_version must be 1")
if api_contract.get("source_path") != "api/openapi/helm.openapi.yaml":
    raise SystemExit("public docs API contract source_path must be api/openapi/helm.openapi.yaml")
openapi_data = git_show(f"{source_commit}:{api_contract['source_path']}")
actual_openapi_sha256 = "sha256:" + sha256_bytes(openapi_data)
if api_contract.get("content_sha256") != actual_openapi_sha256:
    raise SystemExit("public docs API contract content_sha256 does not match OpenAPI source")
actual_openapi_blob = subprocess.check_output(
    ["git", "rev-parse", "--verify", f"{source_commit}:{api_contract['source_path']}"], cwd=root, text=True
).strip()
if api_contract.get("git_blob_sha1") != actual_openapi_blob:
    raise SystemExit("public docs API contract git_blob_sha1 does not match OpenAPI source")
if not isinstance(api_contract.get("public_operations"), list) or not api_contract["public_operations"]:
    raise SystemExit("public docs API contract must declare public_operations")
public_docs_contract = {
    "manifest_path": public_docs_manifest_path,
    "manifest_sha256": "sha256:" + sha256_bytes(public_docs_manifest_data),
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
    "source_commit": source_commit,
    "source_tree_git_oid": source_tree,
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

require_source_snapshot_current

(
    cd "$ASSETS_DIR"
    find . -maxdepth 1 -type f ! -name SHA256SUMS.txt -print |
        sed 's#^\./##' |
        sort |
        xargs shasum -a 256 > SHA256SUMS.txt
    shasum -a 256 -c SHA256SUMS.txt
)

echo "staged release assets in $ASSETS_DIR"
