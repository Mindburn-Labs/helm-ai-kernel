#!/usr/bin/env python3
"""Exercise installer decisions without installing packages or touching /etc."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("install_postgres16.sh")
# Public PGDG download checksum, not a credential.
PGDG_SHA256 = "0144068502a1eddd2a0280ede10ef607d1ec592ce819940991203941564e8e76"
MOCK = r'''#!/usr/bin/env python3
from pathlib import Path
import os, sys
op = Path(sys.argv[0]).name
root = Path(os.environ["PG_FIXTURE"])
with (root / "calls").open("a") as f:
    f.write(op + " " + " ".join(sys.argv[1:]) + "\n")
if op == "uname":
    print("Linux" if sys.argv[1] == "-s" else "x86_64")
elif op == "sudo":
    os.execvp(sys.argv[1], sys.argv[1:])
elif op == "apt-cache":
    sys.exit(0 if os.environ.get("PG_NATIVE") else 100)
elif op == "curl":
    Path(sys.argv[sys.argv.index("-o") + 1]).write_text("mock-key")
elif op == "sha256sum":
    check = sys.stdin.read()
    assert check.split()[0] == os.environ["PGDG_EXPECTED_SHA256"]
    sys.exit(1 if os.environ.get("PG_BAD_KEY") else 0)
elif op == "apt-get":
    if os.environ.get("PG_APT_FAILURE"):
        sys.exit(100)
    if "install" in sys.argv and "postgresql-16" in sys.argv:
        for name in ("initdb", "postgres"):
            dest = root / "usr/lib/postgresql/16/bin" / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            version = os.environ.get("PG_INSTALLED_VERSION", "16.15")
            dest.write_text("#!/bin/sh\necho '" + name + " (PostgreSQL) " + version + "'\n")
            dest.chmod(0o755)
'''


class PostgreSQL16InstallerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "etc").mkdir()
        (self.root / "etc/os-release").write_text("ID=ubuntu\nVERSION_CODENAME=resolute\n")
        mockbin = self.root / "mockbin"
        mockbin.mkdir()
        for name in ("uname", "sudo", "apt-cache", "apt-get", "curl", "sha256sum"):
            path = mockbin / name
            path.write_text(MOCK)
            path.chmod(0o755)
        self.env = {**os.environ, "PATH": f"{mockbin}:{os.environ['PATH']}",
                    "PG_FIXTURE": str(self.root), "RUNNER_TEMP": str(self.root),
                    "PGDG_EXPECTED_SHA256": PGDG_SHA256}

    def run_installer(self, **settings):
        return subprocess.run(["bash", "-c", 'source "$1"; install_postgres16 "$2"',
                               "test", str(SCRIPT), str(self.root)],
                              env={**self.env, **settings}, text=True, capture_output=True)

    def calls(self):
        return (self.root / "calls").read_text()

    def test_preinstalled_binaries_are_verified_without_installing(self):
        # Produce the same independent version-output fixtures as apt would.
        for name in ("initdb", "postgres"):
            path = self.root / "usr/lib/postgresql/16/bin" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"#!/bin/sh\necho '{name} (PostgreSQL) 16.15'\n")
            path.chmod(0o755)
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("apt-", self.calls())
        self.assertNotIn("curl ", self.calls())

    def test_native_package_preserves_the_fast_path(self):
        result = self.run_installer(PG_NATIVE="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("apt-get install --yes --no-install-recommends postgresql-16", self.calls())
        self.assertNotIn("curl ", self.calls())
        self.assertFalse((self.root / "etc/apt/sources.list.d/pgdg.sources").exists())

    def test_missing_native_package_uses_the_pinned_signed_repository(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        sources = (self.root / "etc/apt/sources.list.d/pgdg.sources").read_text()
        self.assertIn("Suites: resolute-pgdg\n", sources)
        self.assertIn("URIs: https://apt.postgresql.org/pub/repos/apt\n", sources)
        self.assertIn("Signed-By: ", sources)
        self.assertNotIn("trusted", sources)
        self.assertIn("sha256sum --check --strict -", self.calls())
        self.assertIn("apt-get update -qq", self.calls())
        self.assertIn("postgres (PostgreSQL) 16.15", result.stdout)

    def test_wrong_key_never_registers_a_repository_or_installs(self):
        result = self.run_installer(PG_BAD_KEY="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "etc/apt/sources.list.d/pgdg.sources").exists())
        self.assertNotIn("apt-get ", self.calls())

    def test_install_failure_is_not_a_skip_or_downgrade(self):
        result = self.run_installer(PG_NATIVE="1", PG_APT_FAILURE="1")
        self.assertEqual(result.returncode, 100)

    def test_wrong_major_is_refused_after_install(self):
        result = self.run_installer(PG_NATIVE="1", PG_INSTALLED_VERSION="18.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not PostgreSQL 16", result.stdout)

    def test_both_preinstalled_binaries_must_be_version_16(self):
        for name, version in (("initdb", "16.15"), ("postgres", "18.0")):
            path = self.root / "usr/lib/postgresql/16/bin" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"#!/bin/sh\necho '{name} (PostgreSQL) {version}'\n")
            path.chmod(0o755)
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("postgres is not PostgreSQL 16", result.stdout)
        self.assertNotIn("apt-get ", self.calls())

    def test_repository_update_failure_prevents_install(self):
        result = self.run_installer(PG_APT_FAILURE="1")
        self.assertEqual(result.returncode, 100)
        self.assertIn("apt-get update -qq", self.calls())
        self.assertNotIn("apt-get install", self.calls())

    def test_unsupported_distribution_is_refused(self):
        for identity in ("ID=debian\nVERSION_CODENAME=trixie\n", "ID=ubuntu\nVERSION_CODENAME=unknown\n"):
            with self.subTest(identity=identity):
                (self.root / "etc/os-release").write_text(identity)
                result = self.run_installer()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("apt-get ", self.calls())


if __name__ == "__main__":
    unittest.main()
