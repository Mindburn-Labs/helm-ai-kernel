#!/usr/bin/env python3
"""Self-tests for release version drift monitoring."""
from __future__ import annotations

import unittest

import check_version_drift as drift


class VersionDriftMonitorTests(unittest.TestCase):
    def test_published_contract_covers_release_channels(self) -> None:
        contract = drift.load_contract(drift.DEFAULT_CONTRACT)
        ids = {surface["id"] for surface in contract["published_surfaces"]}

        required = {
            "github-release",
            "artifacthub-chart",
            "ghcr-image",
            "ghcr-chart",
            "homebrew-tap",
            "npm-sdk",
            "pypi-sdk",
            "crates-sdk",
            "maven-sdk",
            "go-proxy-sdk",
            "pkg-go-dev-sdk",
            "docs-site-developer-journey",
            "docs-site-sdk-index",
            "docs-site-examples",
        }
        self.assertFalse(required - ids)

        kinds = {surface["id"]: surface["kind"] for surface in contract["published_surfaces"]}
        blocking = {surface["id"]: drift.is_blocking(surface) for surface in contract["published_surfaces"]}
        self.assertEqual(kinds["go-proxy-sdk"], "go_proxy_module")
        self.assertEqual(kinds["pkg-go-dev-sdk"], "pkg_go_dev")
        self.assertEqual(kinds["docs-site-sdk-index"], "http_contains")
        self.assertTrue(blocking["go-proxy-sdk"])
        self.assertTrue(blocking["pkg-go-dev-sdk"])

    def test_all_published_surface_kinds_are_supported(self) -> None:
        contract = drift.load_contract(drift.DEFAULT_CONTRACT)
        unsupported = {
            surface["kind"]
            for surface in contract["published_surfaces"]
            if surface["kind"] not in drift.PUBLISHED_CHECKS
        }
        self.assertFalse(unsupported)

    def test_published_only_skips_unselected_surfaces(self) -> None:
        contract = {
            "published_surfaces": [
                {"id": "selected", "kind": "example", "url": "https://example.test/selected"},
                {"id": "unselected", "kind": "example", "url": "https://example.test/unselected"},
            ]
        }
        original = drift.PUBLISHED_CHECKS.copy()
        drift.PUBLISHED_CHECKS["example"] = lambda surface, version: drift.SurfaceResult(
            surface["id"],
            "pass",
            version,
            version,
            url=surface["url"],
        )
        try:
            results = drift.check_published(contract, "0.5.12", set(), {"selected"})
        finally:
            drift.PUBLISHED_CHECKS.clear()
            drift.PUBLISHED_CHECKS.update(original)

        by_id = {result.id: result for result in results}
        self.assertEqual(by_id["selected"].status, "pass")
        self.assertEqual(by_id["unselected"].status, "skipped")
        self.assertFalse(by_id["unselected"].blocking)
        self.assertEqual(by_id["unselected"].detail, "not selected by caller")

    def test_published_only_rejects_unknown_surfaces(self) -> None:
        contract = {
            "published_surfaces": [
                {"id": "selected", "kind": "example", "url": "https://example.test/selected"},
            ]
        }
        original = drift.PUBLISHED_CHECKS.copy()
        drift.PUBLISHED_CHECKS["example"] = lambda surface, version: drift.SurfaceResult(
            surface["id"],
            "pass",
            version,
            version,
            url=surface["url"],
        )
        try:
            results = drift.check_published(contract, "0.5.12", set(), {"typo"})
        finally:
            drift.PUBLISHED_CHECKS.clear()
            drift.PUBLISHED_CHECKS.update(original)

        selection = results[0]
        self.assertEqual(selection.id, "published-surface-selection")
        self.assertEqual(selection.status, "fail")
        self.assertTrue(selection.blocking)
        self.assertEqual(selection.actual, ["typo"])
        self.assertIn("unknown --only", selection.detail or "")

    def test_ghcr_tags_check_verifies_required_manifests(self) -> None:
        calls = []
        original = drift.ghcr_manifest_status

        def fake_manifest_status(repository: str, tag: str) -> int:
            calls.append((repository, tag))
            return 200

        drift.ghcr_manifest_status = fake_manifest_status
        try:
            result = drift.check_ghcr_tags(
                {
                    "id": "ghcr-image",
                    "repository": "mindburn-labs/helm-ai-kernel",
                    "required_tags": ["v{version}", "v{version}-slim"],
                    "human_url": "https://github.com/Mindburn-Labs/helm-ai-kernel/pkgs/container/helm-ai-kernel",
                },
                "0.6.0",
            )
        finally:
            drift.ghcr_manifest_status = original

        self.assertEqual(result.status, "pass")
        self.assertEqual(result.actual, ["v0.6.0", "v0.6.0-slim"])
        self.assertEqual(
            calls,
            [
                ("mindburn-labs/helm-ai-kernel", "v0.6.0"),
                ("mindburn-labs/helm-ai-kernel", "v0.6.0-slim"),
            ],
        )

    def test_ghcr_tags_check_reports_missing_manifest_status(self) -> None:
        original = drift.ghcr_manifest_status

        def fake_manifest_status(_repository: str, tag: str) -> int:
            return 404 if tag.endswith("-slim") else 200

        drift.ghcr_manifest_status = fake_manifest_status
        try:
            result = drift.check_ghcr_tags(
                {
                    "id": "ghcr-image",
                    "repository": "mindburn-labs/helm-ai-kernel",
                    "required_tags": ["v{version}", "v{version}-slim"],
                    "human_url": "https://github.com/Mindburn-Labs/helm-ai-kernel/pkgs/container/helm-ai-kernel",
                },
                "0.6.0",
            )
        finally:
            drift.ghcr_manifest_status = original

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.actual, ["v0.6.0"])
        self.assertIn("v0.6.0-slim (404)", result.detail or "")

    def test_published_error_preserves_advisory_status(self) -> None:
        surface = {
            "id": "optional-docs-cache",
            "url": "https://example.test/cache",
            "blocking": False,
        }
        result = drift.published_error(surface, "0.5.10", TimeoutError("timed out"))

        self.assertEqual(result.status, "fail")
        self.assertFalse(result.blocking)
        self.assertIn("TimeoutError", result.detail or "")
        self.assertEqual(result.expected, "0.5.10")
        self.assertIsNone(result.actual)

    def test_status_payload_emits_timeout_failures_without_blocking_advisory(self) -> None:
        blocking = drift.published_error(
            {
                "id": "docs-site-sdk-index",
                "url": "https://example.test/sdks",
            },
            "0.5.10",
            TimeoutError("timed out"),
        )
        advisory = drift.published_error(
            {
                "id": "optional-docs-cache",
                "url": "https://example.test/cache",
                "blocking": False,
            },
            "0.5.10",
            TimeoutError("timed out"),
        )

        payload = drift.status_payload("published", "0.5.10", [blocking, advisory], [], [blocking, advisory])
        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["registry_versions"][0]["id"], "docs-site-sdk-index")
        self.assertEqual(payload["registry_versions"][0]["status"], "fail")
        self.assertTrue(payload["registry_versions"][0]["blocking"])
        self.assertIn("TimeoutError", payload["registry_versions"][0]["detail"])
        self.assertEqual(payload["registry_versions"][1]["id"], "optional-docs-cache")
        self.assertFalse(payload["registry_versions"][1]["blocking"])

        advisory_only = drift.status_payload("published", "0.5.10", [advisory], [], [advisory])
        self.assertEqual(advisory_only["status"], "pass")
        self.assertEqual(advisory_only["registry_versions"][0]["status"], "fail")

    def test_go_proxy_module_validates_subdirectory_tag(self) -> None:
        original = drift.request_json
        drift.request_json = lambda _url: {
            "Version": "v0.5.14",
            "Origin": {
                "Subdir": "sdk/go",
                "Ref": "refs/tags/sdk/go/v0.5.14",
            },
        }
        try:
            surface = {
                "id": "go-proxy-sdk",
                "kind": "go_proxy_module",
                "url": "https://proxy.golang.org/github.com/!mindburn-!labs/helm-ai-kernel/sdk/go/@v/v{version}.info",
                "origin_subdir": "sdk/go",
                "origin_ref": "refs/tags/sdk/go/v{version}",
            }
            result = drift.check_go_proxy_module(surface, "0.5.14")
        finally:
            drift.request_json = original

        self.assertEqual(result.status, "pass")
        self.assertTrue(result.blocking)
        self.assertEqual(result.actual["origin_ref"], "refs/tags/sdk/go/v0.5.14")

    def test_http_contains_reports_missing_tokens(self) -> None:
        original = drift.request_text
        drift.request_text = lambda _url: "current docs mention version-status.json and io.github.mindburnlabs:helm-sdk:0.5.2"
        try:
            surface = {
                "id": "docs-site-sdk-index",
                "kind": "http_contains",
                "url": "https://example.test/sdk",
                "contains": [
                    "io.github.mindburnlabs:helm-sdk:{version}",
                    "version-status.json",
                ],
                "rejects": [
                    "io.github.mindburnlabs:helm-sdk:0.5.2",
                ],
            }
            result = drift.check_http_contains(surface, "0.5.10")
        finally:
            drift.request_text = original

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.actual["found"], ["version-status.json"])
        self.assertEqual(result.actual["missing"], ["io.github.mindburnlabs:helm-sdk:0.5.10"])
        self.assertEqual(result.actual["rejected_found"], ["io.github.mindburnlabs:helm-sdk:0.5.2"])

    def test_http_contains_does_not_reject_version_prefix_matches(self) -> None:
        original = drift.request_text
        drift.request_text = lambda _url: (
            "current docs mention version-status.json, "
            "io.github.mindburnlabs:helm-sdk:0.5.20, "
            "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go@v0.5.20, "
            "and sdk/go/v0.5.20"
        )
        try:
            surface = {
                "id": "docs-site-sdk-index",
                "kind": "http_contains",
                "url": "https://example.test/sdk",
                "contains": [
                    "io.github.mindburnlabs:helm-sdk:{version}",
                    "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go@v{version}",
                    "sdk/go/v{version}",
                    "version-status.json",
                ],
                "rejects": [
                    "io.github.mindburnlabs:helm-sdk:0.5.2",
                    "sdk/go@main",
                ],
            }
            result = drift.check_http_contains(surface, "0.5.20")
        finally:
            drift.request_text = original

        self.assertEqual(result.status, "pass")
        self.assertEqual(result.actual["rejected_found"], [])


if __name__ == "__main__":
    unittest.main()
