#!/usr/bin/env python3
"""HELM-733: release verification accepts only release.yml@refs/tags/<tag>.

Each fixture bundle holds the certificate SAN a real keyless signature would
carry. The fake cosign below applies cosign's identity rules to it: an exact
string match for --certificate-identity and an unanchored Go-style regexp
search for --certificate-identity-regexp. That lets one matrix drive
verify_cosign.sh, install.sh and the documented recipes: a release signature
passes, and dev-lane, foreign-branch and foreign-repository signatures fail.

quantum_posture: these tests exercise classical Sigstore/cosign identity
selection with a fake cosign; they implement no cryptographic control and make
no post-quantum claim.
"""
from __future__ import annotations

import hashlib
import os
import platform
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
VERIFY_COSIGN = REPOSITORY_ROOT / "scripts" / "release" / "verify_cosign.sh"
INSTALL_SH = REPOSITORY_ROOT / "install.sh"
ISSUER = "https://token.actions.githubusercontent.com"
KERNEL = "https://github.com/Mindburn-Labs/helm-ai-kernel/.github/workflows"
TAG = "v0.8.4"

RELEASE = f"{KERNEL}/release.yml@refs/tags/{TAG}"
OTHER_RELEASE_TAG = f"{KERNEL}/release.yml@refs/tags/v0.8.3"
# The rejected signers. The first is what the retired release.yml
# container-sha lane minted for dev-sha images.
REJECTED = {
    "old dev lane (release.yml on main)": f"{KERNEL}/release.yml@refs/heads/main",
    "dev lane (dev-image.yml on main)": f"{KERNEL}/dev-image.yml@refs/heads/main",
    "release.yml on a feature branch": f"{KERNEL}/release.yml@refs/heads/feature",
    "other workflow on a branch": f"{KERNEL}/nightly-quality.yml@refs/heads/feature",
    "foreign repo, branch named after ours": (
        "https://github.com/attacker/helm-fork/.github/workflows/release.yml"
        "@refs/heads/Mindburn-Labs/helm-ai-kernel"
    ),
    "foreign repo, same workflow and tag": (
        f"https://github.com/attacker/helm-ai-kernel/.github/workflows/release.yml@refs/tags/{TAG}"
    ),
}

FAKE_COSIGN = f"""#!/usr/bin/env python3
import os, re, sys
args = sys.argv[1:]
with open(os.environ["COSIGN_LOG"], "a", encoding="utf-8") as log:
    log.write(" ".join(args) + "\\n")
if not args or args[0] != "verify-blob":
    sys.exit(64)
def value(flag):
    return args[args.index(flag) + 1] if flag in args else None
bundle, artifact = value("--bundle"), args[-1]
if value("--certificate-oidc-issuer") != "{ISSUER}":
    sys.exit(2)
if not (bundle and os.path.isfile(bundle) and os.path.isfile(artifact)):
    sys.exit(3)
san = open(bundle, encoding="utf-8").read().strip()
exact, pattern = value("--certificate-identity"), value("--certificate-identity-regexp")
if exact is not None:
    sys.exit(0 if san == exact else 1)
if pattern is not None:
    sys.exit(0 if re.search(pattern, san) else 1)
sys.exit(4)
"""

FAKE_CURL = """#!/usr/bin/env python3
import os, shutil, sys
args = sys.argv[1:]
url = next(arg for arg in args if arg.startswith("https://"))
with open(os.environ["CURL_LOG"], "a", encoding="utf-8") as log:
    log.write(" ".join(args) + "\\n")
fmt = args[args.index("-w") + 1] if "-w" in args else ""
if "url_effective" in fmt:
    if url != "https://github.com/Mindburn-Labs/helm-ai-kernel/releases/latest":
        sys.exit(22)
    sys.stdout.write("https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/" + os.environ["LATEST_TAG"])
    sys.exit(0)
prefix = "https://github.com/Mindburn-Labs/helm-ai-kernel/releases/download/"
name = url[len(prefix):].partition("/")[2] if url.startswith(prefix) else ""
source = os.path.join(os.environ["RELEASE_FIXTURES"], name) if name else ""
if not source or not os.path.isfile(source):
    sys.exit(22)
shutil.copyfile(source, args[args.index("-o") + 1])
"""


def write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def host_asset() -> str:
    arch = platform.machine()
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(arch, arch)
    return f"helm-ai-kernel-{platform.system().lower()}-{arch}"


class FakeToolsTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        write_executable(self.bin / "cosign", FAKE_COSIGN)
        self.cosign_log = self.tmp / "cosign.log"
        self.cosign_log.touch()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def env(self, **extra: str) -> dict[str, str]:
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "HOME": str(self.tmp),
            "TMPDIR": str(self.tmp),
            "COSIGN_LOG": str(self.cosign_log),
        }
        env.update(extra)
        return env

    def cosign_calls(self) -> list[str]:
        return self.cosign_log.read_text(encoding="utf-8").splitlines()


class VerifyCosignScriptTest(FakeToolsTestCase):
    def release_dir(self, san: str | None, *, with_artifact: bool = True) -> Path:
        directory = Path(tempfile.mkdtemp(dir=self.tmp))
        if with_artifact:
            (directory / "SHA256SUMS.txt").write_text("sums\n", encoding="utf-8")
        if san is not None:
            (directory / "SHA256SUMS.txt.cosign.bundle").write_text(san, encoding="utf-8")
        return directory

    def verify(self, directory: Path, **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(VERIFY_COSIGN), str(directory)],
            check=False,
            capture_output=True,
            text=True,
            env=self.env(**env),
        )

    def test_default_identity_accepts_only_release_workflow_tag_signatures(self) -> None:
        for san in (RELEASE, OTHER_RELEASE_TAG):
            with self.subTest(san=san):
                result = self.verify(self.release_dir(san))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("verified=1 failed=0", result.stdout)
        for name, san in REJECTED.items():
            with self.subTest(signer=name):
                result = self.verify(self.release_dir(san))
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("verified=0 failed=1", result.stdout)

    def test_kernel_release_tag_pins_the_exact_release_identity(self) -> None:
        result = self.verify(self.release_dir(RELEASE), KERNEL_RELEASE_TAG=TAG)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"--certificate-identity {RELEASE} ", self.cosign_calls()[-1])
        for name, san in {"another release tag": OTHER_RELEASE_TAG, **REJECTED}.items():
            with self.subTest(signer=name):
                result = self.verify(self.release_dir(san), KERNEL_RELEASE_TAG=TAG)
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_kernel_release_tag_must_be_a_release_tag(self) -> None:
        for tag in ("main", "v0.8.4.*", "v0.8", "refs/tags/v0.8.4"):
            with self.subTest(tag=tag):
                result = self.verify(self.release_dir(RELEASE), KERNEL_RELEASE_TAG=tag)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("KERNEL_RELEASE_TAG must be", result.stdout)

    def test_zero_bundles_is_not_signature_evidence(self) -> None:
        result = self.verify(self.release_dir(None))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("a zero-bundle run is not signature evidence", result.stdout)

    def test_bundle_without_its_artifact_fails(self) -> None:
        result = self.verify(self.release_dir(RELEASE, with_artifact=False))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no artifact next to bundle", result.stdout)


class InstallScriptTest(FakeToolsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.fixtures = self.tmp / "release"
        self.fixtures.mkdir()
        self.install_dir = self.tmp / "install"
        self.curl_log = self.tmp / "curl.log"
        self.curl_log.touch()
        write_executable(self.bin / "curl", FAKE_CURL)
        self.asset = host_asset()
        self.publish(binary=b"#!/bin/sh\necho v0.8.4\n", signer=RELEASE)

    def publish(self, *, binary: bytes, signer: str, sums_binary: bytes | None = None) -> None:
        (self.fixtures / self.asset).write_bytes(binary)
        listed = hashlib.sha256(sums_binary if sums_binary is not None else binary).hexdigest()
        (self.fixtures / "SHA256SUMS.txt").write_text(f"{listed}  {self.asset}\n", encoding="utf-8")
        (self.fixtures / "SHA256SUMS.txt.cosign.bundle").write_text(signer, encoding="utf-8")

    def install(self, **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(INSTALL_SH)],
            check=False,
            capture_output=True,
            text=True,
            env=self.env(
                INSTALL_DIR=str(self.install_dir),
                CURL_LOG=str(self.curl_log),
                RELEASE_FIXTURES=str(self.fixtures),
                LATEST_TAG=TAG,
                **env,
            ),
        )

    def installed(self) -> bool:
        return (self.install_dir / "helm-ai-kernel").exists()

    def test_installs_only_after_the_exact_tag_signature_and_checksum_verify(self) -> None:
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.installed())
        self.assertIn(f"--certificate-identity {RELEASE} ", self.cosign_calls()[-1])
        self.assertNotIn("regexp", self.cosign_calls()[-1])
        for call in self.curl_log.read_text(encoding="utf-8").splitlines():
            self.assertIn("--proto =https --proto-redir =https", call)

    def test_rejects_every_non_release_signer(self) -> None:
        for name, san in REJECTED.items():
            with self.subTest(signer=name):
                self.publish(binary=b"#!/bin/sh\necho evil\n", signer=san)
                result = self.install()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("Release signature verification FAILED", result.stdout)
                self.assertFalse(self.installed())

    def test_pinned_version_binds_the_signature_to_that_tag(self) -> None:
        # The fixtures carry the v0.8.4 release signature; a v0.8.3 install
        # must not accept it.
        result = self.install(HELM_VERSION="v0.8.3")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("/releases/download/v0.8.3/", self.curl_log.read_text(encoding="utf-8"))
        self.assertIn(f"{KERNEL}/release.yml@refs/tags/v0.8.3", self.cosign_calls()[-1])
        self.assertFalse(self.installed())

    def test_rejects_a_binary_that_does_not_match_the_signed_checksum(self) -> None:
        self.publish(binary=b"#!/bin/sh\necho evil\n", signer=RELEASE, sums_binary=b"good")
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Checksum verification FAILED", result.stdout)
        self.assertFalse(self.installed())

    def test_missing_cosign_or_signature_fails_closed(self) -> None:
        (self.bin / "cosign").unlink()
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cosign is required", result.stdout)
        self.assertFalse(self.installed())

        write_executable(self.bin / "cosign", FAKE_COSIGN)
        (self.fixtures / "SHA256SUMS.txt.cosign.bundle").unlink()
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cosign bundle is missing", result.stdout)
        self.assertFalse(self.installed())


class DocumentedRecipeTest(unittest.TestCase):
    def documented_cosign_commands(self) -> list[tuple[str, str]]:
        files = subprocess.run(
            ["git", "ls-files", "*.md"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.split()
        commands = []
        for name in files:
            text = (REPOSITORY_ROOT / name).read_text(encoding="utf-8").replace("\\\n", " ")
            for line in text.splitlines():
                if re.search(r"^\s*cosign verify(-blob)?\s", line):
                    commands.append((name, line))
        return commands

    def test_every_documented_cosign_verification_pins_the_exact_release_identity(self) -> None:
        commands = self.documented_cosign_commands()
        self.assertGreaterEqual(len(commands), 4, "expected the PUBLISHING and Hermes recipes")
        for name, command in commands:
            with self.subTest(doc=name, command=command[:80]):
                self.assertNotIn("--certificate-identity-regexp", command)
                match = re.search(r'--certificate-identity "([^"]+)"', command)
                self.assertIsNotNone(match, "recipe must pass an exact --certificate-identity")
                assert match is not None
                identity = re.sub(r"\$\{HELM_(TAG|VERSION)\}", TAG, match.group(1))
                self.assertEqual(identity, RELEASE)
                for signer in REJECTED.values():
                    self.assertNotEqual(identity, signer)
                self.assertIn(f"--certificate-oidc-issuer {ISSUER}", command)


if __name__ == "__main__":
    unittest.main()
