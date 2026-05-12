#!/usr/bin/env python3
"""Verify that operational quality gates have maintained runbook coverage."""
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REQUIRED = [
    ("docs/QUALITY_GATES.md", ["make quality-pr", "make quality-nightly", "Advisory"]),
    ("scripts/ci/README.md", ["make quality-pr", "make release-smoke", "make kind-smoke"]),
    ("docs/VERIFICATION.md", ["make verify-cosign", "make release-smoke"]),
    ("docs/RELEASE_SECURITY.md", ["make release-binaries-reproducible", "make release-smoke"]),
    ("docs/TROUBLESHOOTING.md", ["release smoke", "Kubernetes Helm validation"]),
    ("docs/KUBERNETES_DEPLOYMENT.md", ["helm-chart-smoke"]),
    ("deploy/README.md", ["helm lint", "deploy/helm-chart"]),
]


def main() -> int:
    failures: list[str] = []
    for rel_path, needles in REQUIRED:
        path = ROOT / rel_path
        if not path.exists():
            failures.append(f"missing runbook document: {rel_path}")
            continue
        text = path.read_text(errors="ignore")
        for needle in needles:
            if needle not in text:
                failures.append(f"{rel_path} does not mention {needle!r}")

    if failures:
        print("Runbook coverage check failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print(f"Runbook coverage check passed: {len(REQUIRED)} documents verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
