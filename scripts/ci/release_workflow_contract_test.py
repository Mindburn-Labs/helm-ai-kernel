#!/usr/bin/env python3
"""Guard tag-release provenance and no-fanout workflow invariants.

quantum_posture: this text-level contract test checks classical cosign and
checksum workflow wiring; it implements no cryptographic control or
post-quantum assurance.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
VERSION_SURFACES = ROOT / "release" / "version-surfaces.yaml"


class ReleaseWorkflowContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text()

    def job(self, name: str) -> str:
        match = re.search(
            rf"^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            self.workflow,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match, f"missing {name} job")
        return match.group("body")  # type: ignore[union-attr]

    def test_tag_release_is_main_only_and_catalog_is_presynced(self) -> None:
        preflight = self.job("release-preflight")
        self.assertIn("needs: version-contract", preflight)
        self.assertIn('tag_commit="$(git rev-parse "${GITHUB_REF}^{commit}")"', preflight)
        self.assertIn("git ls-remote --exit-code origin refs/heads/main", preflight)
        self.assertIn("kernel_blob=\"$(git hash-object --no-filters api/openapi/helm.openapi.yaml)\"", preflight)
        self.assertIn(
            "repos/Mindburn-Labs/contracts-catalog/contents/api/specs/helm.openapi.yaml?ref=main",
            preflight,
        )
        self.assertIn('if [ "$kernel_blob" != "$catalog_blob" ]; then', preflight)
        self.assertIn("needs: release-preflight", self.job("validate"))
        self.assertIn("release-preflight", self.job("github-release"))

    def test_release_validation_has_the_prior_release_contract_toolchain(self) -> None:
        validate = self.job("validate")
        self.assertIn("fetch-depth: 0", validate)
        self.assertIn("Install oasdiff (prior-release contract breaking-change gate)", validate)
        self.assertIn("sha256sum --check --strict", validate)
        self.assertIn("make quality-release", validate)
        self.assertNotIn("Fetch main ref for proto compatibility checks", validate)

    def test_release_never_creates_a_catalog_pr_or_bypasses_tap_policy(self) -> None:
        self.assertNotIn("downstream-fanout:", self.workflow)
        homebrew = self.job("homebrew")
        self.assertNotIn("--admin", homebrew)
        self.assertIn("--auto", homebrew)
        self.assertIn("--delete-branch", homebrew)
        self.assertIn("for attempt in $(seq 1 120); do", homebrew)
        self.assertIn('state="$(gh pr view "$pr"', homebrew)
        self.assertIn("MERGED) exit 0 ;;", homebrew)
        self.assertIn("CLOSED)", homebrew)
        self.assertIn("Timed out waiting for Homebrew PR", homebrew)

    def test_release_creation_requires_prebuilt_console_assets(self) -> None:
        binaries = self.job("binaries")
        self.assertIn("needs: [validate, deployment-smoke, kind-smoke, release-smoke]", binaries)
        self.assertIn("HELM_RELEASE_EVIDENCE_PROFILE: ${{ vars.HELM_RELEASE_EVIDENCE_PROFILE }}", binaries)
        self.assertIn("HELM_RELEASE_EVIDENCE_ANCHOR_TYPE: ${{ vars.HELM_RELEASE_EVIDENCE_ANCHOR_TYPE }}", binaries)
        self.assertIn("HELM_RELEASE_EVIDENCE_ANCHOR_URI: ${{ vars.HELM_RELEASE_EVIDENCE_ANCHOR_URI }}", binaries)
        self.assertIn("HELM_RELEASE_EVIDENCE_STORAGE_URI: ${{ vars.HELM_RELEASE_EVIDENCE_STORAGE_URI }}", binaries)
        self.assertIn("HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_COMMAND: ${{ secrets.HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_COMMAND }}", binaries)
        self.assertIn("HELM_EVIDENCE_KMS_KEY_ID: ${{ secrets.HELM_EVIDENCE_KMS_KEY_ID }}", binaries)
        self.assertIn("HELM_EVIDENCE_KMS_PUBLIC_KEY_HEX: ${{ secrets.HELM_EVIDENCE_KMS_PUBLIC_KEY_HEX }}", binaries)
        self.assertIn("HELM_EVIDENCE_KMS_SIGN_COMMAND: ${{ secrets.HELM_EVIDENCE_KMS_SIGN_COMMAND }}", binaries)
        self.assertIn("name: Require explicit external release EvidencePack trust", binaries)
        self.assertIn("HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_COMMAND", binaries)
        self.assertLess(
            binaries.index("Require explicit external release EvidencePack trust"),
            binaries.index("Build and stage release assets"),
        )
        self.assertNotIn("console-local-sidecar", binaries)
        self.assertNotIn("HELM_REQUIRE_CONSOLE_LOCAL_SIDECAR", binaries)

        reproducibility = self.job("reproducibility-check")
        self.assertIn("needs: validate", reproducibility)
        self.assertNotIn("console-local-sidecar", reproducibility)

        github_release = self.job("github-release")
        self.assertIn("console-release-assets", github_release)
        self.assertNotIn("needs: console-local-sidecar", github_release)
        self.assertIn("name: console-release-assets", github_release)
        self.assertNotIn("console-release-assets/*", github_release)
        for asset in (
            "console-release-assets/helm-console-local-sidecar-*",
            "console-release-assets/helm-ai-kernel-*-console.tar.gz",
            "console-release-assets/helm-ai-kernel-*-console.tar.gz.cosign.bundle",
            "console-release-assets/CONSOLE-SHA256SUMS.txt",
            "console-release-assets/CONSOLE-SHA256SUMS.txt.cosign.bundle",
        ):
            self.assertIn(asset, github_release)

    def test_release_workflow_never_exposes_raw_evidence_private_pem(self) -> None:
        self.assertNotIn("HELM_EVIDENCE_KMS_PRIVATE_PEM", self.workflow)

    def test_console_assets_are_verified_before_publication(self) -> None:
        console_assets = self.job("console-release-assets")
        self.assertIn("needs: console-local-sidecar", console_assets)
        self.assertNotIn("github-release", console_assets)
        self.assertNotIn("always()", console_assets)
        self.assertIn("make release-binaries-reproducible", console_assets)
        self.assertIn("console_local_sidecar.py stage", console_assets)
        self.assertIn("console_local_sidecar.py layout", console_assets)
        self.assertIn("layout_input=console-layout-input", console_assets)
        self.assertIn('cp "${assets}"/* "${layout_input}/"', console_assets)
        self.assertIn('"${layout_input}/"', console_assets)
        self.assertIn("repository: ${{ steps.console-pin.outputs.repository }}", console_assets)
        self.assertIn("ref: ${{ steps.console-pin.outputs.source_sha }}", console_assets)
        self.assertIn("token: ${{ secrets.CONSOLE_BUNDLE_TOKEN }}", console_assets)
        self.assertIn("npx playwright install --with-deps chromium", console_assets)
        self.assertIn("console_layout_browser_smoke.mjs", console_assets)
        self.assertIn("--layout console-release-assets/helm-ai-kernel-linux-amd64-console.tar.gz", console_assets)
        self.assertLess(
            console_assets.index("console_layout_browser_smoke.mjs"),
            console_assets.index("Cosign keyless-sign standalone Console layouts"),
        )
        self.assertIn("CONSOLE-SHA256SUMS.txt", console_assets)
        self.assertIn("cosign sign-blob", console_assets)
        self.assertIn("actions/upload-artifact", console_assets)
        self.assertNotIn("gh release upload", console_assets)
        self.assertNotIn("published", console_assets)
        self.assertIn("-name 'helm-console-local-sidecar-*'", console_assets)
        self.assertIn("-name 'helm-ai-kernel-*-console.tar.gz'", console_assets)
        self.assertIn("-name 'helm-ai-kernel-*-console.tar.gz.cosign.bundle'", console_assets)

        required_assets = VERSION_SURFACES.read_text()
        self.assertIn('"CONSOLE-SHA256SUMS.txt"', required_assets)
        self.assertIn('"CONSOLE-SHA256SUMS.txt.cosign.bundle"', required_assets)

        post_release = self.job("post-release-version-drift")
        self.assertIn(
            "needs: [github-release, slsa-provenance, homebrew, go-sdk-tag, console-release-assets]",
            post_release,
        )
        self.assertIn("always()", post_release)
        self.assertIn("needs.console-release-assets.result == 'success'", post_release)
        self.assertIn("for attempt in $(seq 1 40); do", post_release)
        self.assertIn("--surface-timeout 10", post_release)
        self.assertIn("Published version surfaces did not converge within the bounded retry budget.", post_release)
        self.assertLess(
            post_release.index("- name: Wait for published version convergence"),
            post_release.index("- name: Check full published version status"),
        )
        self.assertRegex(post_release, r"- name: Check full published version status\n\s+if: always\(\)")
        self.assertRegex(post_release, r"- name: Replace release version status with full post-release status\n\s+if: always\(\)")

    def test_console_dispatch_uses_an_immutable_ref_bound_to_the_source_pin(self) -> None:
        console_sidecar = self.job("console-local-sidecar")
        self.assertIn("CONSOLE_WORKFLOW_REF: ${{ steps.console-pin.outputs.workflow_ref }}", console_sidecar)
        self.assertIn('case "${CONSOLE_WORKFLOW_REF}" in', console_sidecar)
        self.assertIn('refs/tags/*) ;;', console_sidecar)
        self.assertIn('workflow_tag="${CONSOLE_WORKFLOW_REF#refs/tags/}"', console_sidecar)
        self.assertIn('gh api "repos/${CONSOLE_REPOSITORY}/commits/${workflow_tag}" --jq \'.sha\'', console_sidecar)
        self.assertIn('[ "${workflow_sha}" != "${CONSOLE_SOURCE_SHA}" ]', console_sidecar)
        self.assertIn('--ref "${workflow_tag}"', console_sidecar)
        self.assertNotIn("--ref main", console_sidecar)


if __name__ == "__main__":
    unittest.main()
