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

python3 - "$ASSETS_DIR" "$VERSION" <<'PY'
import json
import pathlib
import sys
import tarfile

assets = pathlib.Path(sys.argv[1])
version = sys.argv[2]

attestation = json.loads((assets / "release-attestation.json").read_text(encoding="utf-8"))
if attestation.get("version") != version:
    raise SystemExit("release attestation version mismatch")
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
