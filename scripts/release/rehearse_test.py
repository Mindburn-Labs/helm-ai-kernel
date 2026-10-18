#!/usr/bin/env python3
"""Hermetic self-test for scripts/release/rehearse.py.

Version computation runs the real scripts/ci/contract_breaking.sh inside a
throwaway git repository with fake oasdiff and buf on PATH, the fixture style
of scripts/ci/test_contract_breaking.sh. Network reads are replaced by fakes,
and a planted chart defect proves the key-pair check can fail.
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import rehearse

ROOT = rehearse.ROOT
FAKE_OASDIFF = """#!/usr/bin/env bash
if [ "${FAKE_OASDIFF_BREAKING:-0}" = 1 ]; then echo '[{"level":3}]'; exit 1; fi
exit "${FAKE_OASDIFF_EXIT:-0}"
"""
FAKE_BUF = """#!/usr/bin/env bash
exit "${FAKE_BUF_EXIT:-0}"
"""


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=rehearsal test", "-c", "user.email=rehearsal-test@example.invalid", *args],
        cwd=cwd, check=True, capture_output=True, text=True,
    ).stdout.strip()


def write_spec(path: Path, version: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"openapi: 3.0.3\ninfo:\n  title: rehearsal fixture\n  version: \"{version}\"\npaths: {{}}\n", encoding="utf-8")


class Fixture:
    """A git repository tagged v<tag> carrying the real contract gate script."""

    def __init__(self, tag: str, version: str | None = None, extra_commit: bool = True) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "repo"
        self.bin = Path(self.tmp.name) / "bin"
        self.root.mkdir()
        self.bin.mkdir()
        for name, body in (("oasdiff", FAKE_OASDIFF), ("buf", FAKE_BUF)):
            (self.bin / name).write_text(body, encoding="utf-8")
            (self.bin / name).chmod(0o755)
        (self.root / "scripts/ci").mkdir(parents=True)
        shutil.copy(ROOT / "scripts/ci/contract_breaking.sh", self.root / "scripts/ci/contract_breaking.sh")
        for module in ("protocols/policy-schema", "protocols/proto"):
            (self.root / module).mkdir(parents=True)
            (self.root / module / "buf.yaml").write_text("version: v2\n", encoding="utf-8")
        self.set_version(tag)
        git(self.root, "init", "-q", "-b", "main")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-qm", "seed")
        git(self.root, "tag", "-a", f"v{tag}", "-m", f"v{tag}")
        if version is not None:
            self.set_version(version)
        if extra_commit:
            (self.root / "CHANGE").write_text("change\n", encoding="utf-8")
            git(self.root, "add", "-A")
            git(self.root, "commit", "-qm", "change")

    def set_version(self, version: str) -> None:
        (self.root / "VERSION").write_text(version + "\n", encoding="utf-8")
        write_spec(self.root / "api/openapi/helm.openapi.yaml", version)
        write_spec(self.root / "protocols/specs/effects/openapi.yaml", version)

    def plan(self, **fakes: str) -> rehearse.Plan:
        env = {"PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}", **fakes}
        with mock.patch.dict(os.environ, env):
            return rehearse.plan_version(self.root)

    def close(self) -> None:
        self.tmp.cleanup()


def contract_rows(plan: rehearse.Plan) -> list[rehearse.Check]:
    return [check for check in plan.checks if check.name.startswith("(a)")]


class VersionComputationTest(unittest.TestCase):
    def fixture(self, *args, **kwargs) -> Fixture:
        fixture = Fixture(*args, **kwargs)
        self.addCleanup(fixture.close)
        return fixture

    def test_no_contract_break_is_a_patch(self) -> None:
        plan = self.fixture("0.9.0").plan()
        self.assertEqual((plan.mode, plan.would_be, plan.required_bump), ("computed", "0.9.1", "patch"))
        self.assertEqual([c.status for c in contract_rows(plan)], [rehearse.PASS, rehearse.PASS])

    def test_break_in_0yz_needs_a_minor_bump(self) -> None:
        plan = self.fixture("0.9.0").plan(FAKE_OASDIFF_BREAKING="1")
        self.assertEqual((plan.would_be, plan.required_bump), ("0.10.0", "minor"))
        openapi = contract_rows(plan)[0]
        self.assertEqual(openapi.status, rehearse.PASS)
        self.assertIn("permits it", openapi.detail)

    def test_break_after_1_0_needs_a_major_bump(self) -> None:
        plan = self.fixture("1.2.3").plan(FAKE_BUF_EXIT="100")
        self.assertEqual((plan.would_be, plan.required_bump), ("2.0.0", "major"))

    def test_version_ahead_of_the_tag_is_rehearsed_as_is(self) -> None:
        plan = self.fixture("0.9.0", version="0.10.0").plan(FAKE_OASDIFF_BREAKING="1")
        self.assertEqual((plan.mode, plan.would_be), ("version", "0.10.0"))
        self.assertEqual([c.status for c in contract_rows(plan)], [rehearse.PASS, rehearse.PASS])

    def test_version_ahead_by_too_little_is_action_needed(self) -> None:
        plan = self.fixture("0.9.0", version="0.9.1").plan(FAKE_OASDIFF_BREAKING="1")
        openapi = contract_rows(plan)[0]
        self.assertEqual((plan.would_be, plan.required_bump), ("0.9.1", "minor"))
        self.assertEqual(openapi.status, rehearse.ACTION)
        self.assertEqual(openapi.remedy, "make prepare-version VERSION=0.10.0")

    def test_nothing_to_release_on_the_tag_commit(self) -> None:
        plan = self.fixture("0.9.0", extra_commit=False).plan()
        self.assertEqual((plan.mode, plan.would_be, plan.commits_since), ("nothing", "0.9.0", 0))

    def test_a_gate_that_cannot_run_is_unknown_not_pass(self) -> None:
        plan = self.fixture("0.9.0").plan(FAKE_OASDIFF_EXIT="3")
        openapi = contract_rows(plan)[0]
        self.assertEqual(openapi.status, rehearse.UNKNOWN)
        self.assertTrue(plan.required_bump.startswith("patch (lower bound"))

    def test_break_rule_is_contract_breaking_sh_rule(self) -> None:
        for current, base, allowed in (
            ("0.10.0", "0.9.0", True),
            ("0.9.1", "0.9.0", False),
            ("2.0.0", "1.2.3", True),
            ("1.3.0", "1.2.3", False),
        ):
            with self.subTest(current=current, base=base):
                self.assertIs(rehearse.break_allowed(current, base), allowed)

    def test_missing_break_rule_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "scripts/ci").mkdir(parents=True)
            (Path(tmp) / "scripts/ci/contract_breaking.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                rehearse.break_allowed("0.10.0", "0.9.0", Path(tmp))


class CatalogTest(unittest.TestCase):
    def fetch(self, status: int, payload: dict | None = None):
        return lambda url, token=None: (status, json.dumps(payload or {}).encode())

    def test_blob_identity_matches_git_hash_object(self) -> None:
        spec = ROOT / rehearse.KERNEL_SPEC
        expected = subprocess.run(["git", "hash-object", "--no-filters", str(spec)], capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(rehearse.git_blob_sha(spec.read_bytes()), expected)

    def test_match_is_pass(self) -> None:
        sha = rehearse.git_blob_sha(rehearse.spec_at_version(ROOT, "9.9.9"))
        check = rehearse.check_catalog(ROOT, "9.9.9", fetch=self.fetch(200, {"sha": sha}))
        self.assertEqual(check.status, rehearse.PASS)

    def test_mismatch_is_action_needed_with_a_diff_summary(self) -> None:
        # The catalog holds the current spec; the tag would carry the bumped one.
        current = (ROOT / rehearse.KERNEL_SPEC).read_bytes()
        payload = {"sha": rehearse.git_blob_sha(current), "content": base64.b64encode(current).decode()}
        check = rehearse.check_catalog(ROOT, "9.9.9", fetch=self.fetch(200, payload))
        self.assertEqual(check.status, rehearse.ACTION)
        self.assertIn("-> 9.9.9", check.detail)
        self.assertIn("+1/-1 lines", check.detail)
        self.assertIn("sync PR needed before tagging", check.remedy)

    def test_fetch_errors_are_unknown_never_pass(self) -> None:
        def unreachable(url, token=None):
            raise OSError("network down")

        fetches = [unreachable] + [self.fetch(status, {"message": "x"}) for status in (301, 401, 403, 404, 429, 500)]
        fetches.append(self.fetch(200, {"message": "no sha"}))
        for fetch in fetches:
            with self.subTest(fetch=fetch):
                self.assertEqual(rehearse.check_catalog(ROOT, "9.9.9", fetch=fetch).status, rehearse.UNKNOWN)

    def test_the_catalog_token_is_sent_only_to_api_github_com(self) -> None:
        seen = []

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b"{}"

        def urlopen(request, timeout):
            seen.append((request.full_url, request.get_header("Authorization")))
            return Response()

        with mock.patch.dict(os.environ, {}, clear=False), mock.patch.object(rehearse.urllib.request, "urlopen", urlopen):
            os.environ.pop("GITHUB_TOKEN", None)
            rehearse.http_get("https://api.github.com/x", "tok")
            rehearse.http_get("https://registry.npmjs.org/x", "tok")
        self.assertEqual(seen, [("https://api.github.com/x", "Bearer tok"), ("https://registry.npmjs.org/x", None)])


class ConsolePinTest(unittest.TestCase):
    def pins_root(self) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "release").mkdir()
        shutil.copy(ROOT / rehearse.PINS, root / rehearse.PINS)
        return root

    @staticmethod
    def remote(stdout: str, code: int = 0):
        return lambda ref: subprocess.CompletedProcess([], code, stdout, "boom" if code else "")

    def test_missing_pin_row_is_action_needed(self) -> None:
        checks = rehearse.check_console_pin(self.pins_root(), "99.0.0", ls_remote=self.remote(""))
        self.assertEqual([c.status for c in checks], [rehearse.ACTION, rehearse.ACTION])
        self.assertIn("no row for v99.0.0", checks[0].detail)
        self.assertEqual(checks[1].name, "(c) console tag helm-console-sidecar-v99.0.0")

    def test_existing_row_and_annotated_tag_on_the_pinned_commit_pass(self) -> None:
        pin = json.loads((ROOT / rehearse.PINS).read_text())["pins"][-1]
        ref, commit = pin["workflow_ref"], pin["source"]["commit"]
        version = pin["kernel_release_version"][1:]
        good = self.remote(f"{'1' * 40}\t{ref}\n{commit}\t{ref}^{{}}\n")
        lightweight = self.remote(f"{commit}\t{ref}\n")
        moved = self.remote(f"{'1' * 40}\t{ref}\n{'2' * 40}\t{ref}^{{}}\n")
        root = self.pins_root()
        self.assertEqual([c.status for c in rehearse.check_console_pin(root, version, good)], [rehearse.PASS, rehearse.PASS])
        self.assertEqual(rehearse.check_console_pin(root, version, lightweight)[1].status, rehearse.ACTION)
        self.assertEqual(rehearse.check_console_pin(root, version, moved)[1].status, rehearse.ACTION)
        self.assertEqual(rehearse.check_console_pin(root, version, self.remote("", 128))[1].status, rehearse.UNKNOWN)


class ChartAndExitTest(unittest.TestCase):
    @staticmethod
    def deployment(*names: str) -> str:
        env = "".join(f"            - name: {name}\n              value: x\n" for name in names)
        return f"---\nkind: ConfigMap\n---\napiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - env:\n{env}"

    def test_planted_half_key_pair_fails_the_run(self) -> None:
        # Planted failure: the v0.9.0 chart shape, organization-runtime key without its activation key.
        planted = self.deployment("HELM_TLS_CERT_FILE", "HELM_TLS_KEY_FILE", "HELM_ORGANIZATION_RUNTIME_API_KEY")
        check = rehearse.check_chart_pairs(planted)
        self.assertEqual(check.status, rehearse.FAIL)
        self.assertIn("HELM_ORGANIZATION_RUNTIME_API_KEY without HELM_CONTROL_PLANE_ACTIVATION_PUBLIC_KEY", check.detail)
        self.assertEqual(rehearse.exit_code([check]), 1)

    def test_whole_pairs_pass_and_unwired_tls_is_not_vacuous(self) -> None:
        whole = self.deployment("HELM_TLS_CERT_FILE", "HELM_TLS_KEY_FILE")
        self.assertEqual(rehearse.check_chart_pairs(whole).status, rehearse.PASS)
        self.assertEqual(rehearse.check_chart_pairs(self.deployment("HELM_ADMIN_API_KEY")).status, rehearse.FAIL)

    def test_exit_code_semantics(self) -> None:
        action = rehearse.Check("x", rehearse.ACTION, "")
        unknown = rehearse.Check("y", rehearse.UNKNOWN, "")
        self.assertEqual(rehearse.exit_code([action, unknown]), 0)
        self.assertEqual(rehearse.exit_code([action], strict=True), 1)
        self.assertEqual(rehearse.exit_code([unknown], strict=True), 0)

    def test_secret_presence_is_pass_fail_or_unknown(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        checks = {c.name: c.status for c in rehearse.check_secrets(workflow, {
            "REHEARSAL_HAS_CONSOLE_BUNDLE_TOKEN": "false",
        })}
        self.assertEqual(checks["(g) secret CONSOLE_BUNDLE_TOKEN"], rehearse.FAIL)
        self.assertEqual(checks["(g) secret DOWNSTREAM_FANOUT_TOKEN"], rehearse.UNKNOWN)
        self.assertEqual(checks["(g) release-production environment secrets"], rehearse.UNKNOWN)
        self.assertEqual(checks["(g) maven-central environment secrets"], rehearse.UNKNOWN)

    def test_indexed_secret_is_reported_with_its_job_environment(self) -> None:
        for reference in ("secrets[" + repr("MAVEN_USERNAME") + "]", "SECRETS . MAVEN_USERNAME"):
            with self.subTest(reference=reference):
                workflow = "name: fixture\njobs:\n  publish:\n    environment: maven-central\n    env:\n      USER: ${{ " + reference + " }}\n"
                secrets, _ = rehearse.release_inputs(workflow)
                self.assertEqual(secrets, {"MAVEN_USERNAME": {"maven-central"}})
                checks = {check.name: check.status for check in rehearse.check_secrets(workflow, {})}
                self.assertEqual(checks["(g) maven-central environment secrets"], rehearse.UNKNOWN)
                self.assertNotIn("(g) indirect secret reads", checks)

    def test_indirect_secret_reads_fail_rehearsal(self) -> None:
        workflow = "name: fixture\njobs:\n  publish:\n    runs-on: ubuntu-latest\n"
        references = {
            "whole context": "    env:\n      ALL: ${{ toJSON(secrets) }}\n",
            "raw context": "    env:\n      ALL: ${{ secrets }}\n",
            "uppercase raw context": "    env:\n      ALL: ${{ SECRETS }}\n",
            "inherit": "    secrets: inherit\n",
            "dynamic index": "    env:\n      VALUE: ${{ secrets[vars.SECRET_NAME] }}\n",
            "spaced dynamic index": "    env:\n      VALUE: ${{ SECRETS [ vars.SECRET_NAME ] }}\n",
        }
        for label, reference in references.items():
            with self.subTest(reference=label):
                checks = {check.name: check for check in rehearse.check_secrets(workflow + reference, {})}
                self.assertEqual(checks["(g) indirect secret reads"].status, rehearse.FAIL)


class EnvironmentPostureTest(unittest.TestCase):
    workflow = "name: fixture\njobs:\n  binaries:\n    environment: release-production\n"

    @staticmethod
    def fetch(*, protected=True, reviewers=False, policies=None, policy_status=200):
        environment = {
            "name": "release-production",
            "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True} if protected else None,
            "protection_rules": [{"type": "branch_policy"}] if protected else [],
        }
        if reviewers:
            environment["protection_rules"].append({"type": "required_reviewers"})
        policies = [{"type": "tag", "name": "v*"}] if policies is None else policies

        def fetch(url):
            if url == rehearse.ENVIRONMENTS_URL:
                return 200, json.dumps({"environments": [environment]}).encode()
            if url.startswith(rehearse.ENVIRONMENTS_URL + "/release-production/deployment-branch-policies"):
                return policy_status, json.dumps({"total_count": len(policies), "branch_policies": policies}).encode()
            raise AssertionError(f"unexpected metadata read: {url}")

        return fetch

    def test_tag_only_environment_without_reviewers_passes(self) -> None:
        check = rehearse.check_environments(self.workflow, self.fetch())
        self.assertEqual(check.status, rehearse.PASS)
        self.assertIn("tag:v*", check.detail)

    def test_removing_environment_protection_fails_rehearsal(self) -> None:
        check = rehearse.check_environments(self.workflow, self.fetch(protected=False))
        self.assertEqual(check.status, rehearse.FAIL)
        self.assertEqual(rehearse.exit_code([check]), 1)

    def test_removing_or_broadening_tag_rule_fails_rehearsal(self) -> None:
        for policies in ([], [{"type": "branch", "name": "v*"}], [{"type": "tag", "name": "*"}],
                         [{"type": "tag", "name": "v*"}, {"type": "branch", "name": "main"}]):
            with self.subTest(policies=policies):
                check = rehearse.check_environments(self.workflow, self.fetch(policies=policies))
                self.assertEqual(check.status, rehearse.FAIL)
                self.assertEqual(rehearse.exit_code([check]), 1)

    def test_required_reviewer_is_a_release_blocker(self) -> None:
        check = rehearse.check_environments(self.workflow, self.fetch(reviewers=True))
        self.assertEqual(check.status, rehearse.FAIL)
        self.assertIn("reviewer", check.detail)

    def test_unreadable_tag_policy_is_unknown(self) -> None:
        check = rehearse.check_environments(self.workflow, self.fetch(policy_status=403))
        self.assertEqual(check.status, rehearse.UNKNOWN)
        self.assertIn("HTTP 403", check.detail)

    def test_incomplete_or_malformed_policy_read_never_passes(self) -> None:
        for body in (b"not JSON", b"{}", b'{"branch_policies":{},"total_count":1}',
                     b'{"branch_policies":[{"type":"tag","name":"v*"}],"total_count":true}'):
            with self.subTest(body=body):
                good = self.fetch()
                check = rehearse.check_environments(self.workflow, lambda url: good(url) if url == rehearse.ENVIRONMENTS_URL else (200, body))
                self.assertEqual(check.status, rehearse.UNKNOWN)

    def test_missing_environment_or_no_declaration_fails(self) -> None:
        missing = rehearse.check_environments(self.workflow, lambda url: (200, b'{"environments":[]}'))
        self.assertEqual(missing.status, rehearse.FAIL)
        no_environment = rehearse.check_environments("name: fixture\njobs:\n  publish:\n    runs-on: ubuntu-latest\n", self.fetch())
        self.assertEqual(no_environment.status, rehearse.FAIL)


class WorkflowContractTest(unittest.TestCase):
    workflow = (ROOT / ".github/workflows/release-rehearsal.yml").read_text()

    def test_every_repository_secret_and_variable_of_release_yml_is_reported(self) -> None:
        release = (ROOT / ".github/workflows/release.yml").read_text()
        secrets, variables = rehearse.release_inputs(release)
        for name in sorted(n for n, envs in secrets.items() if "" in envs):
            with self.subTest(secret=name):
                # A boolean, so the secret value never enters the job.
                self.assertIn(f"REHEARSAL_HAS_{name}: ${{{{ secrets.{name} != '' }}}}", self.workflow)
        for name in sorted(variables):
            with self.subTest(variable=name):
                self.assertIn(f"REHEARSAL_HAS_{name}: ${{{{ vars.{name} != '' }}}}", self.workflow)

    def test_read_only_scheduled_and_pinned(self) -> None:
        triggers = self.workflow.split("\njobs:\n", 1)[0]
        self.assertIn("  schedule:\n", triggers)
        self.assertIn("  workflow_dispatch:\n", triggers)
        self.assertNotIn("pull_request", triggers)
        self.assertNotIn("push:", triggers)
        self.assertIn("permissions:\n  contents: read\n", self.workflow)
        self.assertNotRegex(self.workflow, r":\s*write\b")
        for action in re.findall(r"uses: (\S+)", self.workflow):
            with self.subTest(action=action):
                self.assertRegex(action, r"@[0-9a-f]{40}$")
        self.assertIn("GITHUB_STEP_SUMMARY", self.workflow)


if __name__ == "__main__":
    unittest.main()
