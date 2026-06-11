#!/usr/bin/env python3
"""Static hardening checks for Docker and Compose smoke exposure."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def fail(message: str) -> None:
    print(f"::error::{message}", file=sys.stderr)
    raise SystemExit(1)


def require(text: str, token: str, path: Path) -> None:
    if token not in text:
        fail(f"{path}: missing required smoke hardening token: {token}")


def forbid(text: str, token: str, path: Path) -> None:
    if token in text:
        fail(f"{path}: forbidden predictable smoke exposure token remains: {token}")


def check_docker_smoke(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for token in [
        "random_key()",
        'ADMIN_KEY="${HELM_SMOKE_ADMIN_KEY:-$(random_key)}"',
        'SERVICE_KEY="${HELM_SMOKE_SERVICE_KEY:-$(random_key)}"',
        'EVIDENCE_SIGNING_KEY="${HELM_SMOKE_EVIDENCE_SIGNING_KEY:-$(random_key)}"',
        '-p "127.0.0.1:${API_PORT}:8080"',
        '-p "127.0.0.1:${HEALTH_PORT}:8081"',
        'printf \'http://127.0.0.1:%s\' "$API_PORT"',
        'printf \'http://127.0.0.1:%s/health\' "$HEALTH_PORT"',
        'HELM_ADMIN_API_KEY="$ADMIN_KEY"',
        'HELM_SERVICE_API_KEY="$SERVICE_KEY"',
        'EVIDENCE_SIGNING_KEY="$EVIDENCE_SIGNING_KEY"',
    ]:
        require(text, token, path)

    for token in [
        "helm-admin-smoke",
        "helm-service-smoke",
        "helm-evidence-smoke",
        '-p "${API_PORT}:8080"',
        '-p "${HEALTH_PORT}:8081"',
        '-p "0.0.0.0:${API_PORT}:8080"',
        '-p "0.0.0.0:${HEALTH_PORT}:8081"',
    ]:
        forbid(text, token, path)


def check_compose(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    require(text, '"127.0.0.1:${HELM_SMOKE_API_PORT:-8080}:8080"', path)
    require(text, '"127.0.0.1:${HELM_SMOKE_HEALTH_PORT:-8081}:8081"', path)
    forbid(text, '"${HELM_SMOKE_API_PORT:-8080}:8080"', path)
    forbid(text, '"${HELM_SMOKE_HEALTH_PORT:-8081}:8081"', path)
    forbid(text, '"0.0.0.0:${HELM_SMOKE_API_PORT:-8080}:8080"', path)
    forbid(text, '"0.0.0.0:${HELM_SMOKE_HEALTH_PORT:-8081}:8081"', path)


def main() -> None:
    check_docker_smoke(ROOT / "scripts/ci/docker_smoke.sh")
    check_compose(ROOT / "docker-compose.yml")
    print("Docker smoke hardening checks passed.")


if __name__ == "__main__":
    main()
