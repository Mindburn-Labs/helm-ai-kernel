#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARTIFACTS_DIR="${HELM_CONFORMANCE_ARTIFACTS_DIR:-$ROOT/artifacts}"
VERSION="$(cat "$ROOT/VERSION")"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
REF="${GITHUB_REF_NAME:-$(git -C "$ROOT" rev-parse --abbrev-ref HEAD)}"

mkdir -p "$ARTIFACTS_DIR"

HELM_VERSION="$VERSION" bash "$ROOT/scripts/ci/generate_sbom.sh" >/dev/null
cp "$ROOT/sbom.json" "$ARTIFACTS_DIR/sbom.json"

python3 - "$ROOT" "$ARTIFACTS_DIR" "$VERSION" "$COMMIT" "$REF" <<'PY'
import datetime as dt
import hashlib
import json
import os
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
artifacts = pathlib.Path(sys.argv[2])
version = sys.argv[3]
commit = sys.argv[4]
ref = sys.argv[5]

def sha256(rel: str) -> str:
    path = root / rel
    if not path.exists():
        return ""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def go_version() -> str:
    try:
        return subprocess.check_output(["go", "version"], cwd=root, text=True).strip()
    except Exception:
        return "unavailable"

created_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
repo = os.environ.get("GITHUB_REPOSITORY", "Mindburn-Labs/helm-oss")
server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
workflow = os.environ.get("GITHUB_WORKFLOW", "local-release-readiness")
run_id = os.environ.get("GITHUB_RUN_ID", "local")

build_identity = {
    "schema_version": "helm.build_identity.v1",
    "name": "helm",
    "version": version,
    "source_repository": repo,
    "source_url": f"{server}/{repo}",
    "source_ref": ref,
    "source_commit": commit,
    "builder": workflow,
    "run_id": run_id,
    "go_version": go_version(),
    "created_at": created_at,
}

materials = []
for rel in ("VERSION", "core/go.sum", "api/openapi/helm.openapi.yaml", "Makefile"):
    digest = sha256(rel)
    if digest:
        materials.append({"uri": rel, "digest": {"sha256": digest}})

provenance = {
    "schema_version": "helm.provenance.v1",
    "predicateType": "https://slsa.dev/provenance/v1",
    "subject": [{"name": "helm", "digest": {"gitCommit": commit}}],
    "builder": {"id": f"{server}/{repo}/actions/workflows/release.yml"},
    "buildType": "https://github.com/Mindburn-Labs/helm-oss/.github/workflows/release.yml",
    "invocation": {
        "configSource": {"uri": f"git+{server}/{repo}", "digest": {"sha1": commit}, "entryPoint": ref},
        "parameters": {"make_target": "conformance-release-report"},
    },
    "metadata": {"buildStartedOn": created_at, "buildFinishedOn": created_at},
    "materials": materials,
}

trust_roots = {
    "schema_version": "helm.trust_roots.v1",
    "roots": [
        {
            "type": "github_oidc",
            "issuer": "https://token.actions.githubusercontent.com",
            "repository": repo,
            "ref": ref,
        },
        {
            "type": "sigstore_cosign_keyless",
            "fulcio": "https://fulcio.sigstore.dev",
            "rekor": "https://rekor.sigstore.dev",
        },
    ],
    "notes": [
        "Release assets are signed by the GitHub release workflow with Sigstore/cosign keyless identity when OIDC is available.",
        "helm conform --signed emits Ed25519 signatures when HELM_SIGNING_KEY_HEX is present and digest artifacts otherwise.",
    ],
}

(artifacts / "build_identity.json").write_text(json.dumps(build_identity, indent=2, sort_keys=True) + "\n", encoding="utf-8")
(artifacts / "provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")
(artifacts / "trust_roots.json").write_text(json.dumps(trust_roots, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

echo "prepared release conformance inputs in $ARTIFACTS_DIR"
