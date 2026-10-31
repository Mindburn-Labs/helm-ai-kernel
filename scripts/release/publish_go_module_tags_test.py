#!/usr/bin/env python3
"""Exercise immutable Go module publication against a local Git remote."""

from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("publish_go_module_tags.sh")


class PublishGoModuleTagsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.repo = root / "source"
        self.remote = root / "remote.git"
        self.repo.mkdir()
        self.git("init", "--bare", str(self.remote))
        self.git("init")
        self.git("config", "user.name", "Module publication test")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "tag.gpgsign", "false")
        for module in ("core", "sdk/go"):
            directory = self.repo / module
            directory.mkdir(parents=True)
            (directory / "go.mod").write_text(
                f"module github.com/Mindburn-Labs/helm-ai-kernel/{module}\n"
            )
        self.git("add", ".")
        self.git("commit", "-m", "Release source")
        self.target = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("tag", "-a", "v1.2.3", "-m", "Root release")
        self.git("remote", "add", "origin", str(self.remote))
        self.git("push", "origin", "refs/tags/v1.2.3")

    def git(self, *args, check=True):
        return subprocess.run(
            ["git", *args], cwd=self.repo, text=True, capture_output=True, check=check
        )

    def publish(self):
        return subprocess.run(
            ["bash", str(SCRIPT), "v1.2.3"],
            cwd=self.repo, text=True, capture_output=True,
        )

    def remote_ref(self, ref):
        return self.git("ls-remote", "--tags", "origin", ref).stdout.strip()

    def test_publishes_both_modules_and_is_idempotent(self):
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        before = self.remote_ref("refs/tags/*")
        for module in ("core", "sdk/go"):
            self.assertTrue(
                self.remote_ref(f"refs/tags/{module}/v1.2.3^{{}}").startswith(self.target)
            )
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(before, self.remote_ref("refs/tags/*"))

    def test_repairs_core_without_replacing_existing_sdk_tag(self):
        self.git("tag", "-a", "sdk/go/v1.2.3", "-m", "Existing SDK release")
        self.git("push", "origin", "refs/tags/sdk/go/v1.2.3")
        before = self.remote_ref("refs/tags/sdk/go/v1.2.3")
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(before, self.remote_ref("refs/tags/sdk/go/v1.2.3"))
        self.assertTrue(self.remote_ref("refs/tags/core/v1.2.3^{}").startswith(self.target))

    def test_conflict_in_second_module_prevents_all_publication(self):
        self.git("commit", "--allow-empty", "-m", "Different source")
        self.git("tag", "-a", "sdk/go/v1.2.3", "-m", "Conflicting SDK release")
        self.git("push", "origin", "refs/tags/sdk/go/v1.2.3")
        before = self.remote_ref("refs/tags/*")
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to move", result.stderr)
        self.assertEqual(before, self.remote_ref("refs/tags/*"))
        self.assertEqual(self.git("tag", "--list", "core/*").stdout, "")

    def test_unknown_remote_state_fails_closed(self):
        self.git("remote", "set-url", "origin", str(self.remote / "missing"))
        self.assertNotEqual(self.publish().returncode, 0)
        self.assertEqual(self.git("tag", "--list", "core/*").stdout, "")

    def test_unpublished_root_release_fails_closed(self):
        self.git("--git-dir", str(self.remote), "update-ref", "-d", "refs/tags/v1.2.3")
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must already be published", result.stderr)
        self.assertEqual(self.remote_ref("refs/tags/*"), "")


if __name__ == "__main__":
    unittest.main()
