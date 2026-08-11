#!/usr/bin/env python3
"""Guard tag-release authority, provenance, and no-fanout invariants.

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

TAG_RELEASE_MUTATION_JOBS = frozenset(
    {
        "artifacthub-repo",
        "binaries",
        "chart",
        "console-local-sidecar",
        "console-release-assets",
        "container",
        "cosign-binaries",
        "cosign-container",
        "crates-sdk",
        "github-release",
        "go-sdk-tag",
        "homebrew",
        "maven-sdk",
        "npm-sdk",
        "post-release-version-drift",
        "python-sdk",
        "slsa-provenance",
    }
)

# container-sha publishes a dev-grade image for one exact, green-CI commit via
# workflow_dispatch. It is intentionally not a v-tag release job and therefore
# must not be coupled to the annotated-tag release authority boundary.
NON_RELEASE_MUTATION_JOB_EXEMPTIONS = frozenset({"container-sha"})

# These source markers classify every current externally mutating job. Keeping
# the classification here makes a new publisher fail closed until its authority
# dependency is deliberately reviewed (or it is documented as a non-release
# exemption above).
EXTERNAL_MUTATION_MARKERS = (
    "actions/attest-build-provenance@",
    "cosign sign",
    "gh release upload ",
    "gh workflow run ",
    "git push ",
    "helm push ",
    "mvn --batch-mode deploy",
    "npm publish ",
    "oras push ",
    "push: true",
    "pypa/gh-action-pypi-publish@",
    "run: cargo publish",
    "slsa-framework/slsa-github-generator/",
    "softprops/action-gh-release@",
)

RELEASE_AUTHORITY_GUARD_CLAUSES = (
    "github.event_name == 'push'",
    "github.ref_type == 'tag'",
    "github.actor == 'mindburnlabs'",
    "github.triggering_actor == 'mindburnlabs'",
    "github.run_attempt == 1",
)


class ReleaseWorkflowContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.job_blocks = {
            match.group("name"): match.group("body")
            for match in re.finditer(
                r"^  (?P<name>[A-Za-z0-9_-]+):\n"
                r"(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
                cls.workflow,
                re.MULTILINE | re.DOTALL,
            )
        }

    def job(self, name: str) -> str:
        self.assertIn(name, self.job_blocks, f"missing {name} job")
        return self.job_blocks[name]

    def job_needs(self, name: str) -> set[str]:
        lines = self.job(name).splitlines()
        for index, line in enumerate(lines):
            if not line.startswith("    needs:"):
                continue
            value = line.removeprefix("    needs:").strip()
            if value.startswith("[") and value.endswith("]"):
                return {item.strip() for item in value[1:-1].split(",") if item.strip()}
            if value:
                return {value}

            needs: set[str] = set()
            for child in lines[index + 1 :]:
                if child.startswith("      - "):
                    needs.add(child.removeprefix("      - ").strip())
                    continue
                break
            return needs
        return set()

    def job_if(self, name: str) -> str:
        match = re.search(
            r"^    if:\s*(?P<inline>[^\n]*)\n(?P<block>(?:      [^\n]*\n)*)",
            self.job(name),
            re.MULTILINE,
        )
        self.assertIsNotNone(match, f"missing job-level if for {name}")
        assert match is not None
        return "\n".join((match.group("inline"), match.group("block")))

    def external_mutation_jobs(self) -> set[str]:
        return {
            name
            for name, body in self.job_blocks.items()
            if any(marker in body for marker in EXTERNAL_MUTATION_MARKERS)
        }

    def test_release_authority_is_human_gated_armed_and_binds_the_live_tag_object(self) -> None:
        authority = self.job("release-authority")
        self.assertEqual(
            self.job_needs("release-authority"),
            {
                "benchmark-pin",
                "deployment-smoke",
                "kind-smoke",
                "release-preflight",
                "release-smoke",
                "reproducibility-check",
                "validate",
            },
        )
        self.assertIn("environment:\n      name: release-production", authority)
        for clause in RELEASE_AUTHORITY_GUARD_CLAUSES:
            self.assertIn(clause, self.job_if("release-authority"))

        self.assertIn("RELEASE_AUTHORITY_ARMED: ${{ vars.HELM_RELEASE_AUTHORITY_ARMED }}", authority)
        self.assertIn(
            'if [ "${RELEASE_AUTHORITY_ARMED:-}" != "release-production" ]; then',
            authority,
        )
        # The guard binds the event-carried SHA to the live annotated tag
        # object, then separately verifies the peeled commit.
        self.assertIn("EXPECTED_TAG_OBJECT: ${{ github.event.after }}", authority)
        self.assertIn("EXPECTED_COMMIT: ${{ github.sha }}", authority)
        self.assertIn(
            'if [ "${live_tag_object}" != "${EXPECTED_TAG_OBJECT}" ]; then',
            authority,
        )
        self.assertIn(
            'gh api "repos/${GITHUB_REPOSITORY}/git/ref/tags/${GITHUB_REF_NAME}"',
            authority,
        )
        self.assertIn('if [ "${ref_type}" != "tag" ]; then', authority)
        self.assertIn(
            'gh api "repos/${GITHUB_REPOSITORY}/git/tags/${live_tag_object}"',
            authority,
        )
        self.assertIn('if [ "${target_type}" != "commit" ]; then', authority)
        self.assertIn(
            'if [ "${target_commit}" != "${EXPECTED_COMMIT}" ]; then',
            authority,
        )

    def test_every_tag_release_mutation_requires_fresh_conductor_authority(self) -> None:
        detected = self.external_mutation_jobs()
        self.assertEqual(
            detected,
            TAG_RELEASE_MUTATION_JOBS | NON_RELEASE_MUTATION_JOB_EXEMPTIONS,
            "external mutation classification changed; review the new job before publication",
        )

        for job_name in sorted(TAG_RELEASE_MUTATION_JOBS):
            with self.subTest(job=job_name):
                self.assertIn("release-authority", self.job_needs(job_name))

    def test_container_sha_remains_the_separate_exact_sha_qa_lane(self) -> None:
        container_sha = self.job("container-sha")
        self.assertEqual(NON_RELEASE_MUTATION_JOB_EXEMPTIONS, {"container-sha"})
        self.assertNotIn("release-authority", self.job_needs("container-sha"))
        self.assertIn("if: github.event_name == 'workflow_dispatch'", container_sha)
        self.assertIn("No successful CI (ci.yml) run for ${SOURCE_SHA}", container_sha)
        self.assertIn("dev.mindburn.build-grade=dev", container_sha)

    def test_tag_release_is_main_only_and_catalog_is_presynced(self) -> None:
        preflight = self.job("release-preflight")
        self.assertIn("needs: version-contract", preflight)
        self.assertIn('tag_commit="$(git rev-parse "${GITHUB_REF}^{commit}")"', preflight)
        # Ancestry, not equality: the tagged commit must be reachable from
        # main so nothing off-main ships, while a merge landing mid-release no
        # longer strands the tag (v0.8.1 was stranded exactly that way).
        self.assertIn("git merge-base --is-ancestor", preflight)
        self.assertIn("origin/main", preflight)
        self.assertNotIn('if [ "$tag_commit" != "$main_commit" ]', preflight)
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
        self.assertIn(
            "needs: [validate, deployment-smoke, kind-smoke, release-smoke, release-authority]",
            binaries,
        )
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

        # The two authority-producing jobs remain parallel, but no public
        # publication may begin before both have succeeded.
        for publisher in (
            "cosign-binaries",
            "container",
            "go-sdk-tag",
            "npm-sdk",
            "python-sdk",
            "crates-sdk",
            "maven-sdk",
            "console-release-assets",
        ):
            self.assertIn(
                "needs: [binaries, console-local-sidecar, release-authority]",
                self.job(publisher),
                publisher,
            )

        self.assertIn("needs: [container, release-authority]", self.job("cosign-container"))
        self.assertIn("container", self.job("chart"))
        self.assertIn("cosign-container", self.job("chart"))
        self.assertIn("needs: [chart, release-authority]", self.job("artifacthub-repo"))
        self.assertIn("needs: [github-release, release-authority]", self.job("homebrew"))

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
        self.assertIn(
            "needs: [binaries, console-local-sidecar, release-authority]",
            console_assets,
        )
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
            "needs: [github-release, slsa-provenance, homebrew, go-sdk-tag, console-release-assets, release-authority]",
            post_release,
        )
        self.assertIn("always()", post_release)
        self.assertIn("needs.console-release-assets.result == 'success'", post_release)
        self.assertIn("for attempt in $(seq 1 40); do", post_release)
        self.assertRegex(
            post_release,
            r'--expected-version "\$VERSION" \\\n\s+published \\\n\s+--surface-timeout 10',
        )
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
