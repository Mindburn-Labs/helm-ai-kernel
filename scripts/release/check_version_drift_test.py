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
            "pkg-go-dev-sdk",
            "docs-site-developer-journey",
            "docs-site-sdk-index",
            "docs-site-examples",
        }
        self.assertFalse(required - ids)

        kinds = {surface["id"]: surface["kind"] for surface in contract["published_surfaces"]}
        self.assertEqual(kinds["pkg-go-dev-sdk"], "pkg_go_dev")
        self.assertEqual(kinds["docs-site-sdk-index"], "http_contains")

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

    def test_published_error_preserves_advisory_status(self) -> None:
        surface = {
            "id": "pkg-go-dev-sdk",
            "url": "https://pkg.go.dev/example",
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
                "id": "pkg-go-dev-sdk",
                "url": "https://pkg.go.dev/example",
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
        self.assertEqual(payload["registry_versions"][1]["id"], "pkg-go-dev-sdk")
        self.assertFalse(payload["registry_versions"][1]["blocking"])

        advisory_only = drift.status_payload("published", "0.5.10", [advisory], [], [advisory])
        self.assertEqual(advisory_only["status"], "pass")
        self.assertEqual(advisory_only["registry_versions"][0]["status"], "fail")

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


if __name__ == "__main__":
    unittest.main()
