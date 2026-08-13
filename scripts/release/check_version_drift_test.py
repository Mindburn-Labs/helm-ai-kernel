#!/usr/bin/env python3
"""Self-tests for release version drift monitoring."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import unittest
from unittest import mock

import check_version_drift as drift


class VersionDriftMonitorTests(unittest.TestCase):
    def test_http_headers_scope_ambient_github_token_to_github_api(self) -> None:
        with mock.patch.dict(drift.os.environ, {"GITHUB_TOKEN": "repo-token"}):
            self.assertEqual(
                drift.http_headers("https://api.github.com/repos/Mindburn-Labs/helm-ai-kernel")["Authorization"],
                "Bearer repo-token",
            )
            self.assertEqual(
                drift.http_headers(
                    "https://api.github.com/repos/Mindburn-Labs/helm-ai-kernel",
                    {"Authorization": "Bearer explicit-token"},
                )["Authorization"],
                "Bearer explicit-token",
            )

            for url in (
                "http://api.github.com/repos/Mindburn-Labs/helm-ai-kernel",
                "https://api.github.com.evil.test/repos/Mindburn-Labs/helm-ai-kernel",
                "https://github.com/Mindburn-Labs/helm-ai-kernel/releases/download/v0.8.4/asset",
                "https://registry.npmjs.org/@mindburn/helm-ai-kernel",
                "https://helm.docs.mindburn.org/version.json",
            ):
                with self.subTest(url=url):
                    self.assertNotIn("Authorization", drift.http_headers(url))

            self.assertEqual(
                drift.http_headers(
                    "https://ghcr.io/v2/mindburn-labs/helm-ai-kernel/tags/list",
                    {"Authorization": "Bearer ghcr-token"},
                )["Authorization"],
                "Bearer ghcr-token",
            )

    def test_http_request_does_not_forward_authorization_on_redirect(self) -> None:
        with mock.patch.dict(drift.os.environ, {"GITHUB_TOKEN": "repo-token"}):
            requests = (
                (
                    drift.http_request("https://api.github.com/repos/Mindburn-Labs/helm-ai-kernel"),
                    "Bearer repo-token",
                ),
                (
                    drift.http_request(
                        "https://ghcr.io/v2/mindburn-labs/helm-ai-kernel/tags/list",
                        extra={"Authorization": "Bearer ghcr-token"},
                    ),
                    "Bearer ghcr-token",
                ),
            )

        handler = drift.urllib.request.HTTPRedirectHandler()
        for initial, expected_authorization in requests:
            with self.subTest(url=initial.full_url):
                self.assertEqual(initial.get_header("Authorization"), expected_authorization)
                self.assertNotIn("Authorization", initial.headers)

                redirected = handler.redirect_request(
                    initial,
                    None,
                    302,
                    "Found",
                    {},
                    "https://third-party.example/redirected",
                )
                self.assertIsNotNone(redirected)
                assert redirected is not None
                self.assertIsNone(redirected.get_header("Authorization"))
                self.assertEqual(redirected.get_header("Accept"), initial.get_header("Accept"))
                self.assertEqual(redirected.get_header("User-Agent"), initial.get_header("User-Agent"))

    def test_published_contract_covers_release_channels(self) -> None:
        contract = drift.load_contract(drift.DEFAULT_CONTRACT)
        ids = {surface["id"] for surface in contract["published_surfaces"]}

        required = {
            "github-release",
            "github-release-console-local-sidecar",
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
            "github-release-slsa-subjects",
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
        self.assertEqual(kinds["github-release-slsa-subjects"], "github_release_slsa_subjects")
        self.assertTrue(blocking["github-release-slsa-subjects"])

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

    def test_published_surface_is_skipped_before_its_introduced_version(self) -> None:
        results = drift.check_published(
            {
                "published_surfaces": [
                    {
                        "id": "console-sidecar",
                        "kind": "github_release_assets",
                        "introduced_in": "0.8.0",
                        "url": "https://example.test/releases/v{version}",
                        "human_url": "https://example.test/releases/v{version}",
                        "required_assets": ["sidecar.tar.gz"],
                    }
                ]
            },
            "0.7.5",
            set(),
        )
        self.assertEqual(results[0].status, "skipped")
        self.assertFalse(results[0].blocking)
        self.assertEqual(results[0].detail, "introduced in v0.8.0")

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

    def test_github_release_slsa_subjects_match_checksum_manifest(self) -> None:
        asset_digest = "a" * 64
        checksum_bytes = f"{asset_digest}  artifact.tar\n".encode()
        checksum_digest = hashlib.sha256(checksum_bytes).hexdigest()
        bundle = slsa_bundle(
            {
                "dist/release-assets/SHA256SUMS.txt": checksum_digest,
                "dist/release-assets/artifact.tar": asset_digest,
            }
        )
        original_json = drift.request_json
        original_bytes = drift.request_bytes
        drift.request_json = lambda _url: release_payload()
        drift.request_bytes = lambda url: (
            checksum_bytes if url == "https://example.test/SHA256SUMS.txt" else bundle
        )
        try:
            result = drift.check_github_release_slsa_subjects(release_surface(), "0.7.1")
        finally:
            drift.request_json = original_json
            drift.request_bytes = original_bytes

        self.assertEqual(result.status, "pass")
        self.assertEqual(result.actual["missing"], [])
        self.assertEqual(result.actual["mismatched"], [])
        self.assertEqual(result.actual["extra"], [])

    def test_github_release_slsa_subjects_report_digest_mismatch(self) -> None:
        checksum_bytes = f"{'a' * 64}  artifact.tar\n".encode()
        bundle = slsa_bundle(
            {
                "dist/release-assets/SHA256SUMS.txt": hashlib.sha256(checksum_bytes).hexdigest(),
                "dist/release-assets/artifact.tar": "b" * 64,
            }
        )
        original_json = drift.request_json
        original_bytes = drift.request_bytes
        drift.request_json = lambda _url: release_payload()
        drift.request_bytes = lambda url: (
            checksum_bytes if url == "https://example.test/SHA256SUMS.txt" else bundle
        )
        try:
            result = drift.check_github_release_slsa_subjects(release_surface(), "0.7.1")
        finally:
            drift.request_json = original_json
            drift.request_bytes = original_bytes

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.actual["mismatched"][0]["name"], "artifact.tar")
        self.assertIn("mismatched=1", result.detail or "")

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

    def test_published_value_error_is_reported_as_a_surface_failure(self) -> None:
        contract = {
            "published_surfaces": [
                {"id": "invalid-url", "kind": "example", "url": "https://example.test"},
            ]
        }
        original = drift.PUBLISHED_CHECKS.copy()

        def raise_value_error(_surface, _version):
            raise ValueError("invalid URL")

        drift.PUBLISHED_CHECKS["example"] = raise_value_error
        try:
            results = drift.check_published(contract, "0.5.12", set())
        finally:
            drift.PUBLISHED_CHECKS.clear()
            drift.PUBLISHED_CHECKS.update(original)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "fail")
        self.assertTrue(results[0].blocking)
        self.assertIn("ValueError: invalid URL", results[0].detail or "")

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

    def test_rate_limited_read_retries_then_reports_unknown_instead_of_drift(self) -> None:
        sleeps: list[float] = []
        attempts: list[str] = []

        def always_rate_limited(request, timeout=None):
            attempts.append(request.full_url)
            raise rate_limited_error(request.full_url)

        with captured_stderr() as notices, mock.patch.object(
            drift.urllib.request, "urlopen", always_rate_limited
        ), mock.patch.object(drift.time, "sleep", sleeps.append):
            results = drift.check_published(github_release_contract(), "0.8.4", set())

        self.assertEqual(len(attempts), drift.RATE_LIMIT_RETRY_ATTEMPTS)
        self.assertEqual(sleeps, [2.0, 4.0])
        self.assertIn("rate limited by api.github.com (HTTP 403); retrying in 2s", notices.getvalue())

        result = results[0]
        self.assertEqual(result.status, drift.STATUS_UNKNOWN)
        self.assertTrue(result.blocking)
        self.assertIsNone(result.actual)
        self.assertIn("could not read", result.detail or "")
        self.assertIn("rate limit exceeded", result.detail or "")
        self.assertEqual(drift.result_marker(result), "UNKNOWN")

        payload = drift.status_payload("published", "0.8.4", results, [], results)
        self.assertFalse(drift.should_fail(results, "published"))
        self.assertEqual(payload["status"], drift.STATUS_UNKNOWN)
        self.assertEqual(payload["registry_versions"][0]["status"], drift.STATUS_UNKNOWN)
        self.assertEqual(drift.exit_code(payload["status"]), drift.EXIT_UNKNOWN)
        self.assertNotEqual(drift.EXIT_UNKNOWN, 0)

    def test_rate_limited_read_recovers_within_the_retry_budget(self) -> None:
        sleeps: list[float] = []
        responses = [rate_limited_error("https://api.github.com/releases/tags/v0.8.4")]

        def flaky(request, timeout=None):
            if responses:
                raise responses.pop()
            return fake_response(json.dumps({"tag_name": "v0.8.4"}).encode())

        with captured_stderr(), mock.patch.object(drift.urllib.request, "urlopen", flaky), mock.patch.object(
            drift.time, "sleep", sleeps.append
        ):
            results = drift.check_published(github_release_contract(), "0.8.4", set())

        self.assertEqual(sleeps, [2.0])
        self.assertEqual(results[0].status, "pass")
        self.assertEqual(results[0].actual, "v0.8.4")
        self.assertEqual(drift.exit_code(drift.status_payload("published", "0.8.4", results, [], results)["status"]), 0)

    def test_rate_limit_backoff_honours_retry_after_within_the_cap(self) -> None:
        secondary = rate_limited_error("https://api.github.com", code=403, headers={"Retry-After": "7"})
        self.assertTrue(drift.is_rate_limited(secondary))
        self.assertEqual(drift.rate_limit_backoff(secondary, 1), 7.0)

        excessive = rate_limited_error("https://api.github.com", code=429, headers={"Retry-After": "3600"})
        self.assertEqual(drift.rate_limit_backoff(excessive, 1), drift.RATE_LIMIT_MAX_BACKOFF_SECONDS)

        exhausted = rate_limited_error("https://api.github.com", headers={"x-ratelimit-remaining": "0"}, reason="Forbidden")
        self.assertTrue(drift.is_rate_limited(exhausted))
        self.assertEqual(drift.rate_limit_backoff(exhausted, 3), 8.0)

    def test_plain_forbidden_is_not_retried_and_still_reports_drift(self) -> None:
        sleeps: list[float] = []
        attempts: list[str] = []

        def forbidden(request, timeout=None):
            attempts.append(request.full_url)
            raise drift.urllib.error.HTTPError(request.full_url, 403, "Forbidden", {}, None)

        with mock.patch.object(drift.urllib.request, "urlopen", forbidden), mock.patch.object(
            drift.time, "sleep", sleeps.append
        ):
            results = drift.check_published(github_release_contract(), "0.8.4", set())

        self.assertEqual(len(attempts), 1)
        self.assertEqual(sleeps, [])
        self.assertEqual(results[0].status, "fail")
        self.assertTrue(results[0].blocking)
        self.assertIn("HTTPError", results[0].detail or "")

    def test_version_mismatch_still_fails_when_another_surface_is_unknown(self) -> None:
        mismatch = drift.SurfaceResult("npm-sdk", "fail", "0.8.4", "0.8.3", url="https://example.test/npm")
        unreadable = drift.published_unknown(
            {"id": "github-release", "url": "https://api.example.test/releases/tags/v0.8.4"},
            "0.8.4",
            drift.SurfaceUnreadable("https://api.example.test/releases/tags/v0.8.4", 3, TimeoutError("rate limit exceeded")),
        )
        results = [mismatch, unreadable]

        payload = drift.status_payload("published", "0.8.4", results, [], results)
        self.assertTrue(drift.should_fail(results, "published"))
        self.assertEqual(payload["status"], "fail")
        self.assertEqual(drift.exit_code(payload["status"]), 1)
        self.assertEqual(drift.result_marker(mismatch), "FAIL")
        self.assertEqual(drift.result_marker(unreadable), "UNKNOWN")

    def test_advisory_unknown_does_not_move_the_overall_verdict(self) -> None:
        advisory = drift.published_unknown(
            {"id": "optional-docs-cache", "url": "https://example.test/cache", "blocking": False},
            "0.8.4",
            drift.SurfaceUnreadable("https://example.test/cache", 3, TimeoutError("rate limit exceeded")),
        )
        passing = drift.SurfaceResult("npm-sdk", "pass", "0.8.4", "0.8.4", url="https://example.test/npm")

        payload = drift.status_payload("published", "0.8.4", [passing, advisory], [], [passing, advisory])
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["registry_versions"][1]["status"], drift.STATUS_UNKNOWN)
        self.assertFalse(payload["registry_versions"][1]["blocking"])
        self.assertEqual(drift.exit_code(payload["status"]), 0)

    def test_successful_read_is_unchanged_by_the_retry_path(self) -> None:
        sleeps: list[float] = []
        calls: list[str] = []

        def ok(request, timeout=None):
            calls.append(request.full_url)
            return fake_response(json.dumps({"tag_name": "v0.8.4"}).encode())

        with mock.patch.object(drift.urllib.request, "urlopen", ok), mock.patch.object(
            drift.time, "sleep", sleeps.append
        ):
            results = drift.check_published(github_release_contract(), "0.8.4", set())

        self.assertEqual(len(calls), 1)
        self.assertEqual(sleeps, [])
        self.assertEqual(results[0].status, "pass")
        payload = drift.status_payload("published", "0.8.4", results, [], results)
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(drift.exit_code(payload["status"]), 0)
        self.assertEqual(drift.result_marker(results[0]), "OK")

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


def github_release_contract() -> dict[str, list[dict[str, str]]]:
    return {
        "published_surfaces": [
            {
                "id": "github-release",
                "kind": "github_release",
                "url": "https://api.github.com/repos/Mindburn-Labs/helm-ai-kernel/releases/tags/v{version}",
                "human_url": "https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v{version}",
            }
        ]
    }


def rate_limited_error(
    url: str,
    code: int = 403,
    headers: dict[str, str] | None = None,
    reason: str = "rate limit exceeded",
) -> drift.urllib.error.HTTPError:
    return drift.urllib.error.HTTPError(url, code, reason, headers or {"x-ratelimit-remaining": "0"}, None)


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self._body = body
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False


def fake_response(body: bytes, status: int = 200) -> FakeResponse:
    return FakeResponse(body, status)


@contextlib.contextmanager
def captured_stderr():
    buffer = io.StringIO()
    with contextlib.redirect_stderr(buffer):
        yield buffer


def release_surface() -> dict[str, str]:
    return {
        "id": "github-release-slsa-subjects",
        "kind": "github_release_slsa_subjects",
        "url": "https://api.example.test/releases/tags/v{version}",
        "human_url": "https://example.test/releases/tag/v{version}",
    }


def release_payload() -> dict[str, list[dict[str, str]]]:
    return {
        "assets": [
            {"name": "SHA256SUMS.txt", "browser_download_url": "https://example.test/SHA256SUMS.txt"},
            {"name": "multiple.intoto.jsonl", "browser_download_url": "https://example.test/multiple.intoto.jsonl"},
        ]
    }


def slsa_bundle(subjects: dict[str, str]) -> bytes:
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "subject": [{"name": name, "digest": {"sha256": digest}} for name, digest in sorted(subjects.items())],
    }
    payload = base64.b64encode(json.dumps(statement).encode()).decode().rstrip("=")
    return json.dumps({"dsseEnvelope": {"payload": payload}}).encode()


if __name__ == "__main__":
    unittest.main()
