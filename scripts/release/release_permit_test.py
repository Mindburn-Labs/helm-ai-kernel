#!/usr/bin/env python3
"""Hermetic tests for release_permit.py: the context binding, the closed answer
shape, and the fail-closed paths of the review step. No network call is made.

quantum_posture: tests of digest binding and workflow identity only; no
cryptographic primitive and no post-quantum claim.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_permit as rp  # noqa: E402

ROOT = rp.ROOT
FIXTURES = ROOT / "release" / "permit-fixtures"
ENV = {
    "GITHUB_REPOSITORY": "Mindburn-Labs/helm-ai-kernel",
    "GITHUB_WORKFLOW_REF": "Mindburn-Labs/helm-ai-kernel/.github/workflows/release.yml@refs/tags/v9.9.9",
    "GITHUB_RUN_ID": "42",
    "GITHUB_RUN_ATTEMPT": "1",
}


def fixture_repo() -> tuple[tempfile.TemporaryDirectory, str]:
    """A two-commit repository whose first commit carries a release tag."""
    tmp = tempfile.TemporaryDirectory()
    def run(*args: str) -> str:
        return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                              cwd=tmp.name, check=True, capture_output=True, text=True).stdout.strip()
    run("init", "-q", "-b", "main")
    (Path(tmp.name) / "a.txt").write_text("one\n")
    run("add", "."); run("commit", "-q", "-m", "first"); run("tag", "-a", "-m", "r", "v9.9.0")
    (Path(tmp.name) / "a.txt").write_text("two\n")
    run("commit", "-q", "-am", "second")
    return tmp, run("rev-parse", "HEAD")


def pulls_for(commit: str, **overrides):
    pull = {"number": 7, "merged_at": "x", "merge_commit_sha": commit, "base": {"ref": "main"}}
    pull.update(overrides)
    return lambda _url, _headers: [pull]


class ContextTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp, self.head = fixture_repo()
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.object(rp, "REPO", Path(tmp.name))
        patcher.start()
        self.addCleanup(patcher.stop)

    def build(self, fetch, tag="v9.9.9"):
        return rp.build_context(env=ENV, commit=self.head, tag=tag, fetch=fetch)

    def test_context_is_bound_to_the_tagged_commit_and_its_delta(self) -> None:
        context = self.build(pulls_for(self.head))
        self.assertEqual(context["head_sha"], self.head)
        self.assertEqual(context["merge_sha"], self.head)
        self.assertEqual(context["pull_request"], 7)
        self.assertNotEqual(context["workflow_sha"], self.head, "the reducer forbids a self-reviewing workflow")
        self.assertEqual(context["workflow_ref"], "refs/tags/v9.9.9")
        self.assertEqual(context["workflow_path"], ".github/workflows/release.yml")
        self.assertEqual([r["provider"] for r in context["required_reviewers"]], ["anthropic", "openai"])
        self.assertNotIn("_previous_release", json.loads(rp.encode_context(context)))

    def test_a_commit_without_a_merged_pull_request_fails_closed(self) -> None:
        for fetch in (
            lambda *_: [],
            pulls_for(self.head, merged_at=None),
            pulls_for("0" * 40),
            pulls_for(self.head, base={"ref": "feature"}),
            lambda *_: {"message": "rate limited"},
        ):
            with self.assertRaises(rp.PermitError):
                self.build(fetch)

    def test_missing_workflow_binding_fails_closed(self) -> None:
        with self.assertRaises(rp.PermitError):
            rp.build_context(env={**ENV, "GITHUB_WORKFLOW_REF": ""}, commit=self.head, tag=None, fetch=pulls_for(self.head))
        with self.assertRaises(rp.PermitError):
            rp.build_context(env={**ENV, "GITHUB_RUN_ID": "x"}, commit=self.head, tag=None, fetch=pulls_for(self.head))


class AnswerShapeTest(unittest.TestCase):
    def test_accepts_the_closed_shape_and_a_json_fence(self) -> None:
        answer = '{"verdict":"DENY","findings":[{"severity":"P1","code":"X","summary":"y","path":"a.go","line":3}]}'
        self.assertEqual(rp.parse_answer(answer)["findings"][0]["line"], 3)
        self.assertEqual(rp.parse_answer("```json\n" + answer + "\n```")["verdict"], "DENY")

    def test_rejects_everything_else(self) -> None:
        bad = [
            "not json",
            "[]",
            '{"verdict":"ALLOW"}',
            '{"verdict":"MAYBE","findings":[]}',
            '{"verdict":"ALLOW","findings":[],"note":"extra"}',
            '{"verdict":"ALLOW","findings":null}',
            '{"verdict":"ALLOW","findings":[{"severity":"P9","code":"X","summary":"y"}]}',
            '{"verdict":"ALLOW","findings":[{"severity":"P3","code":"","summary":"y"}]}',
            '{"verdict":"ALLOW","findings":[{"severity":"P3","code":"X","summary":"y","extra":1}]}',
            '{"verdict":"ALLOW","findings":[{"severity":"P3","code":"X","summary":"y","line":-1}]}',
        ]
        for content in bad:
            with self.subTest(content=content), self.assertRaises(rp.PermitError):
                rp.parse_answer(content)


class ReviewTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        repo, head = fixture_repo()
        self.addCleanup(repo.cleanup)
        patcher = mock.patch.object(rp, "REPO", Path(repo.name))
        patcher.start()
        self.addCleanup(patcher.stop)
        context = rp.build_context(env=ENV, commit=head, tag="v9.9.9", fetch=pulls_for(head))
        self.context = self.dir / "context.json"
        self.context.write_bytes(rp.encode_context(context))

    def test_fixture_reviews_are_bound_to_the_context_digest(self) -> None:
        rp.run_review(self.context, self.dir / "out", FIXTURES, {})
        reviews = sorted((self.dir / "out").glob("review-*.json"))
        self.assertEqual(len(reviews), 2)
        digest = rp.sha256_hex(self.context.read_bytes())
        for path in reviews:
            review = json.loads(path.read_text())
            self.assertEqual(review["context_sha256"], digest)
            self.assertEqual(review["schema"], rp.REVIEW_SCHEMA)

    def test_a_missing_secret_fails_closed_before_any_call(self) -> None:
        with mock.patch.object(rp, "openrouter_post") as post, self.assertRaises(rp.PermitError):
            rp.run_review(self.context, self.dir / "out", None, {})
        post.assert_not_called()

    def test_provider_error_and_wrong_model_fail_closed(self) -> None:
        env = {"OPENROUTER_API_KEY": "k"}
        with mock.patch.object(rp, "openrouter_post", side_effect=rp.PermitError("provider call failed")):
            with self.assertRaises(rp.PermitError):
                rp.run_review(self.context, self.dir / "out", None, env)
        wrong = {"model": "mistralai/other", "choices": [{"finish_reason": "stop", "message": {"content": '{"verdict":"ALLOW","findings":[]}'}}]}
        with mock.patch.object(rp, "openrouter_post", return_value=wrong), self.assertRaises(rp.PermitError):
            rp.run_review(self.context, self.dir / "out", None, env)
        cut = {"model": "anthropic/x", "choices": [{"finish_reason": "length", "message": {"content": "{"}}]}
        with mock.patch.object(rp, "openrouter_post", return_value=cut), self.assertRaises(rp.PermitError):
            rp.run_review(self.context, self.dir / "out", None, env)

    def test_a_malformed_answer_writes_no_review(self) -> None:
        env = {"OPENROUTER_API_KEY": "k"}
        bad = {"model": "anthropic/x", "choices": [{"finish_reason": "stop", "message": {"content": "looks fine to me"}}]}
        with mock.patch.object(rp, "openrouter_post", return_value=bad), self.assertRaises(rp.PermitError):
            rp.run_review(self.context, self.dir / "out", None, env)
        self.assertEqual(list((self.dir / "out").glob("review-*.json")), [])

    def test_quorum_must_match_the_pinned_reviewers(self) -> None:
        context = json.loads(self.context.read_text())
        context["required_reviewers"][0]["model"] = "other"
        self.context.write_text(json.dumps(context))
        with self.assertRaises(rp.PermitError):
            rp.run_review(self.context, self.dir / "out", FIXTURES, {})


class ConfigTest(unittest.TestCase):
    def test_pinned_reviewers_are_two_distinct_providers_through_openrouter(self) -> None:
        config = rp.load_reviewers()
        self.assertEqual({r["provider"] for r in config["reviewers"]}, {"anthropic", "openai"})

    def test_same_provider_twice_is_rejected(self) -> None:
        config = json.loads(rp.REVIEWERS_PATH.read_text())
        config["reviewers"][1] = {"provider": "anthropic", "model": "claude-sonnet-5.5", "openrouter_id": "anthropic/claude-sonnet-5.5"}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "r.json"
            path.write_text(json.dumps(config))
            with self.assertRaises(rp.PermitError):
                rp.load_reviewers(path)


if __name__ == "__main__":
    unittest.main()
