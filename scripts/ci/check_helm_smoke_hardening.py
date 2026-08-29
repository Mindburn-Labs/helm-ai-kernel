#!/usr/bin/env python3
"""Static hardening checks for containerized Helm smoke fallbacks."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SHA256_REF = re.compile(r"@sha256:[0-9a-f]{64}")


def fail(message: str) -> None:
    print(f"::error::{message}", file=sys.stderr)
    raise SystemExit(1)


def require(text: str, token: str, path: Path) -> None:
    if token not in text:
        fail(f"{path}: missing required authority-state hardening token: {token}")


def require_digest_default(path: Path, text: str) -> None:
    match = re.search(r'KUBE_HELM_IMAGE="\$\{KUBE_HELM_IMAGE:-([^}]+)\}"', text)
    if not match:
        fail(f"{path}: missing KUBE_HELM_IMAGE default")
    if not SHA256_REF.search(match.group(1)):
        fail(f"{path}: KUBE_HELM_IMAGE default must be digest pinned")
    if "require_pinned_helm_image" not in text:
        fail(f"{path}: missing runtime digest-pin guard")


def check_kind_smoke(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    require_digest_default(path, text)
    forbidden = [
        "--network host",
        '${HOME}/.kube:/root/.kube',
        "$HOME/.kube:/root/.kube",
        "-v \"${HOME}/.kube",
    ]
    for token in forbidden:
        if token in text:
            fail(f"{path}: forbidden host kubeconfig/network fallback remains: {token}")
    required = [
        "--network kind",
        "HELM_KUBECONFIG",
        "target=/root/.kube/config,readonly",
        "kind-${CLUSTER}",
        "-control-plane:6443",
        "pod-security.kubernetes.io/enforce=restricted",
        "ctr --namespace k8s.io images inspect",
        "ctr --namespace k8s.io images tag --force",
        "--set image.digest=",
    ]
    for token in required:
        if token not in text:
            fail(f"{path}: missing hardened kind fallback token: {token}")


def check_chart_smoke(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    require_digest_default(path, text)
    for token in [
        "PRODUCTION_IMAGE_DIGEST",
        "requires image.digest pinned by immutable sha256 digest",
        "--set image.digest=",
    ]:
        require(text, token, path)


def check_authority_state_chart(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    required = [
        'name: prepare-authority-state',
        'runtimeInit.image must be pinned by immutable sha256 digest',
        'runAsNonRoot: true',
        'runAsUser: {{ required "podSecurityContext.runAsUser is required for authority-state initialization" .Values.podSecurityContext.runAsUser }}',
        'runAsGroup: {{ required "podSecurityContext.runAsGroup is required for authority-state initialization" .Values.podSecurityContext.runAsGroup }}',
        'readOnlyRootFilesystem: true',
        'drop:\n                - ALL',
        'authority data volume is not writable by the restricted runtime identity',
        'chmod 0600 "$root_key"',
        'cmp -s "$source_key" "$root_key"',
        'refusing silent rotation',
        'mountPath: /var/run/helm-signing-key',
        'defaultMode: 256',
    ]
    for token in required:
        require(text, token, path)
    for token in [
        'runAsNonRoot: false',
        'runAsUser: 0',
        'runAsGroup: 0',
        'allowPrivilegeEscalation: true',
        'privileged: true',
        'add:',
        'chown ',
        'HELM_AUTHORITY_RUNTIME_UID',
        'HELM_AUTHORITY_RUNTIME_GID',
        'chmod 0700 "$data_dir"',
        'subPath: root.key',
        'mountPath: {{ printf "%s/root.key"',
    ]:
        if token in text:
            fail(f"{path}: forbidden privileged, root/CHOWN, or direct signing Secret mount remains: {token}")


def main() -> None:
    check_kind_smoke(ROOT / "scripts/ci/kind_smoke.sh")
    check_chart_smoke(ROOT / "scripts/ci/helm_chart_smoke.sh")
    check_authority_state_chart(ROOT / "deploy/helm-chart/templates/deployment.yaml")
    print("Helm smoke hardening checks passed.")


if __name__ == "__main__":
    main()
