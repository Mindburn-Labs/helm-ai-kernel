#!/usr/bin/env python3
"""Exercise the rendered authority init command against durable key states."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


def init_script(rendered: str) -> str:
    deployment = rendered.split(
        "# Source: helm-ai-kernel/templates/deployment.yaml\n", 1
    )[1]
    initializer = deployment.split("        - name: prepare-authority-state\n", 1)[1]
    block = initializer.split("          args:\n            - |\n", 1)[1].split(
        "\n          env:\n", 1
    )[0]
    lines = block.splitlines()
    if not lines or any(line and not line.startswith("              ") for line in lines):
        raise ValueError("authority init command has an unexpected YAML indentation")
    return "\n".join(line[14:] if line else "" for line in lines) + "\n"


def run(script: str, data_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/bin/sh", "-ec", script],
        env={**os.environ, "HELM_AUTHORITY_DATA_DIR": str(data_dir)},
        capture_output=True,
        text=True,
        check=False,
    )


def main() -> None:
    rendered = Path(sys.argv[1]).read_text(encoding="utf-8")
    script = init_script(rendered)
    source_literal = "/var/run/helm-signing-key/root.key"
    if script.count(source_literal) != 1:
        raise AssertionError("expected one signing Secret key path in init command")

    with tempfile.TemporaryDirectory(prefix="helm-authority-init-") as tmp:
        root = Path(tmp)
        source = root / "source.key"
        source.write_bytes(b"fixture-signing-key")
        script = script.replace(source_literal, str(source))

        for state in ("absent", "empty", "matching", "different", "symlink"):
            data = root / state
            data.mkdir()
            key = data / "root.key"
            if state == "empty":
                key.touch()
                key.chmod(0o664)
            elif state == "matching":
                key.write_bytes(source.read_bytes())
                key.chmod(0o640)
            elif state == "different":
                key.write_bytes(b"different-durable-key")
            elif state == "symlink":
                target = root / "symlink-target"
                target.write_bytes(b"")
                key.symlink_to(target)

            result = run(script, data)
            if state in ("absent", "empty", "matching"):
                assert result.returncode == 0, (state, result.stderr)
                assert key.read_bytes() == source.read_bytes(), state
                assert stat.S_IMODE(key.stat().st_mode) == 0o600, state
            elif state == "different":
                assert result.returncode != 0, state
                assert "differs from signing Secret; refusing silent rotation" in result.stderr
                assert key.read_bytes() == b"different-durable-key"
            else:
                assert result.returncode != 0, state
                assert "refusing symlinked durable authority root key" in result.stderr
                assert key.is_symlink() and target.read_bytes() == b""

        source.write_bytes(b"")
        empty_source_dir = root / "empty-source"
        empty_source_dir.mkdir()
        empty_source_result = run(script, empty_source_dir)
        assert empty_source_result.returncode != 0
        assert "signing Secret is missing, empty, or unreadable" in empty_source_result.stderr
        assert not (empty_source_dir / "root.key").exists()

    print("authority-state init ok: empty source, differing key and symlink refuse; empty durable key repairs")


if __name__ == "__main__":
    main()
