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


def check_launchpad_smoke(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for token in [
        "--container-runtime=containerd",
        "ctr --namespace k8s.io images inspect",
        "ctr --namespace k8s.io images tag --force",
        'crictl inspecti "$KERNEL_IMAGE_DIGEST_REF"',
        '--set "image.digest=${KERNEL_IMAGE_DIGEST}"',
    ]:
        require(text, token, path)


def check_launchpad_test_network_policy(values_path: Path, test_path: Path) -> None:
    text = values_path.read_text(encoding="utf-8")
    require(
        text,
        """        - podSelector:
            matchLabels:
              app.kubernetes.io/part-of: helm-ai-kernel
              app.kubernetes.io/component: test
      ports:
        - protocol: TCP
          port: 8081""",
        values_path,
    )

    test_text = test_path.read_text(encoding="utf-8")
    require(
        test_text,
        'app.kubernetes.io/name: {{ printf "%s-launchpad-test" (include "helm-ai-kernel.name" .)',
        test_path,
    )
    if '{{- include "helm-ai-kernel.labels" . | nindent 4 }}' in test_text:
        fail(f"{test_path}: launchpad test pod must not inherit the kernel service selector labels")


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
    check_launchpad_smoke(ROOT / "scripts/ci/launchpad_k8s_smoke.sh")
    check_launchpad_test_network_policy(
        ROOT / "scripts/ci/helm_production_network_policy_values.yaml",
        ROOT / "deploy/helm-chart/templates/tests/launchpad-connectivity.yaml",
    )
    check_authority_state_chart(ROOT / "deploy/helm-chart/templates/deployment.yaml")
    print("Helm smoke hardening checks passed.")


if __name__ == "__main__":
    main()
