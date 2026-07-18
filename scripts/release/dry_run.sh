#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VERSION="$(cat VERSION)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/helm-release-dry-run.XXXXXX")"
ASSETS_DIR="$TMP_DIR/assets"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "==> HELM Release Asset Dry Run v$VERSION"
RELEASE_ASSETS_DIR="$ASSETS_DIR" make release-assets >/dev/null

required=(
  helm-ai-kernel-linux-amd64
  helm-ai-kernel-linux-arm64
  helm-ai-kernel-darwin-amd64
  helm-ai-kernel-darwin-arm64
  helm-ai-kernel-windows-amd64.exe
  helm-ai-kernel.mcpb
  sbom.json
  "v$VERSION.openvex.json"
  release.high_risk.v3.toml
  sample-policy-material.tar
  evidence-pack.tar
  helm-ai-kernel-launchpad-data.tar
  helm-ai-kernel.rb
  release-attestation.json
  SHA256SUMS.txt
)

for artifact in "${required[@]}"; do
  if [[ ! -s "$ASSETS_DIR/$artifact" ]]; then
    echo "missing or empty release artifact: $artifact" >&2
    exit 1
  fi
done

(cd "$ASSETS_DIR" && shasum -a 256 -c SHA256SUMS.txt >/dev/null)
"$ROOT/bin/helm-ai-kernel" verify "$ASSETS_DIR/evidence-pack.tar" >/dev/null

python3 - "$ASSETS_DIR" "$VERSION" "$ROOT" <<'PY'
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tarfile

assets = pathlib.Path(sys.argv[1])
version = sys.argv[2]
root = pathlib.Path(sys.argv[3])

attestation = json.loads((assets / "release-attestation.json").read_text(encoding="utf-8"))
if attestation.get("version") != version:
    raise SystemExit("release attestation version mismatch")
if not re.fullmatch(r"[0-9a-f]{40}", str(attestation.get("source_commit") or "")):
    raise SystemExit("release attestation source commit is invalid")
if not re.fullmatch(r"[0-9a-f]{40}", str(attestation.get("source_tree_git_oid") or "")):
    raise SystemExit("release attestation source tree is invalid")

def git_text(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()

def git_bytes(revision: str) -> bytes:
    return subprocess.check_output(["git", "show", revision], cwd=root)

source_commit = attestation["source_commit"]
if git_text("rev-parse", "--verify", f"{source_commit}^{{tree}}") != attestation["source_tree_git_oid"]:
    raise SystemExit("release attestation source tree does not resolve from source commit")
public_docs_contract = attestation.get("public_docs_contract")
if not isinstance(public_docs_contract, dict):
    raise SystemExit("release attestation is missing public_docs_contract")
if public_docs_contract.get("manifest_path") != "docs/public-docs.manifest.json":
    raise SystemExit("release attestation public docs manifest path mismatch")
if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(public_docs_contract.get("manifest_sha256") or "")):
    raise SystemExit("release attestation public docs manifest SHA-256 is invalid")
api_contract = public_docs_contract.get("api_contract")
if not isinstance(api_contract, dict):
    raise SystemExit("release attestation public docs API contract is missing")
if api_contract.get("schema_version") != 1:
    raise SystemExit("release attestation public docs API contract schema version mismatch")
if api_contract.get("source_path") != "api/openapi/helm.openapi.yaml":
    raise SystemExit("release attestation public docs API contract source path mismatch")
if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(api_contract.get("content_sha256") or "")):
    raise SystemExit("release attestation public docs API contract SHA-256 is invalid")
if not re.fullmatch(r"[0-9a-f]{40}", str(api_contract.get("git_blob_sha1") or "")):
    raise SystemExit("release attestation public docs API contract Git blob is invalid")
if not isinstance(api_contract.get("public_operations"), list) or not api_contract["public_operations"]:
    raise SystemExit("release attestation public docs API contract has no public operations")
manifest_bytes = git_bytes(f"{source_commit}:{public_docs_contract['manifest_path']}")
if public_docs_contract["manifest_sha256"] != "sha256:" + hashlib.sha256(manifest_bytes).hexdigest():
    raise SystemExit("release attestation public docs manifest is not bound to source commit")
source_manifest = json.loads(manifest_bytes)
if source_manifest.get("api_contract") != api_contract:
    raise SystemExit("release attestation public docs API contract drifted from source commit")
if git_text("rev-parse", "--verify", f"{source_commit}:{api_contract['source_path']}") != api_contract["git_blob_sha1"]:
    raise SystemExit("release attestation public docs OpenAPI blob is not bound to source commit")
if api_contract["content_sha256"] != "sha256:" + hashlib.sha256(git_bytes(f"{source_commit}:{api_contract['source_path']}")).hexdigest():
    raise SystemExit("release attestation public docs OpenAPI digest is not bound to source commit")
names = {artifact["name"] for artifact in attestation.get("artifacts", [])}
required_names = {
    "helm-ai-kernel-linux-amd64",
    "helm-ai-kernel-linux-arm64",
    "helm-ai-kernel-darwin-amd64",
    "helm-ai-kernel-darwin-arm64",
    "helm-ai-kernel-windows-amd64.exe",
    "helm-ai-kernel.mcpb",
    "sbom.json",
    f"v{version}.openvex.json",
    "release.high_risk.v3.toml",
    "sample-policy-material.tar",
    "evidence-pack.tar",
    "helm-ai-kernel-launchpad-data.tar",
    "helm-ai-kernel.rb",
}
missing = sorted(required_names - names)
if missing:
    raise SystemExit(f"attestation missing artifacts: {missing}")

sbom = json.loads((assets / "sbom.json").read_text(encoding="utf-8"))
if sbom.get("bomFormat") != "CycloneDX":
    raise SystemExit("sbom.json is not CycloneDX")

formula = (assets / "helm-ai-kernel.rb").read_text(encoding="utf-8")
if version not in formula:
    raise SystemExit("Homebrew formula does not include the release version")
if "Mindburn-Labs/helm-ai-kernel" not in formula:
    raise SystemExit("Homebrew formula does not point at Mindburn-Labs/helm-ai-kernel")
if "helm-ai-kernel-launchpad-data.tar" not in formula or "launch matrix --json" not in formula:
    raise SystemExit("Homebrew formula does not install or test Launchpad data")
if not formula.startswith("# frozen_string_literal: true\n\nclass HelmAiKernel < Formula\n"):
    raise SystemExit("Homebrew formula has invalid leading indentation")
if "\n\n\n" in formula:
    raise SystemExit("Homebrew formula contains extra blank lines")
if formula.find("on_macos do") > formula.find('resource "launchpad-data" do'):
    raise SystemExit("Homebrew formula platform blocks must precede resources")
if "console-web" in formula or "helm-console-web" in formula:
    raise SystemExit("Homebrew formula must remain headless and must not install console web assets")

with tarfile.open(assets / "sample-policy-material.tar", "r") as tar:
    members = set(tar.getnames())
expected_members = {
    "release.high_risk.v3.toml",
    "reference_packs/eu_ai_act_high_risk.v1.json",
}
if not expected_members.issubset(members):
    raise SystemExit(f"sample policy material missing {sorted(expected_members - members)}")
PY

echo "✅ Release dry run generated and verified artifacts in $ASSETS_DIR"
