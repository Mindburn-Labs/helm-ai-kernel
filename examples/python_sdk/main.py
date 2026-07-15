#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from typing import Any

from helm_sdk import DecisionRequest, EvaluationScope, HelmApiError, HelmClient


CANONICAL_VERDICTS = {"ALLOW", "DENY", "ESCALATE"}


def require_verdict(record: dict[str, Any], expected: str, label: str) -> str:
    verdict = str(record.get("verdict", ""))
    if verdict not in CANONICAL_VERDICTS:
        raise AssertionError(f"{label}: non-canonical verdict {verdict!r}")
    if verdict != expected:
        raise AssertionError(f"{label}: got {verdict}, want {expected}")
    return verdict


def require_receipt(record: dict[str, Any], label: str) -> dict[str, Any]:
    receipt = record.get("receipt")
    refs = record.get("proof_refs", {})
    if not isinstance(receipt, dict):
        raise AssertionError(f"{label}: receipt missing")
    if not receipt.get("receipt_id"):
        raise AssertionError(f"{label}: receipt_id missing")
    if not receipt.get("signature"):
        raise AssertionError(f"{label}: signature missing")
    if not isinstance(refs, dict) or not refs.get("receipt_hash"):
        raise AssertionError(f"{label}: proof_refs.receipt_hash missing")
    if receipt.get("metadata", {}).get("side_effect_dispatched") is not False:
        raise AssertionError(f"{label}: side effects must remain undispatched")
    return receipt


def require_mcp_denial(client: HelmClient) -> str:
    try:
        client.authorize_mcp_call(
            {
                "server_id": "unknown-python-sdk-fixture",
                "tool_name": "local.echo",
                "args_hash": "sha256:python-sdk-local-only",
            }
        )
    except HelmApiError as exc:
        body = exc.body if isinstance(exc.body, dict) else {}
        verdict = str(body.get("verdict", "DENY"))
        if verdict not in {"DENY", "ESCALATE"}:
            raise AssertionError(f"MCP denial returned {verdict}, expected DENY or ESCALATE")
        return verdict
    raise AssertionError("MCP authorization unexpectedly allowed an unknown server")


def main() -> None:
    helm_url = os.environ.get("HELM_URL", "http://127.0.0.1:7715")
    admin_key = os.environ.get("HELM_ADMIN_API_KEY")
    tenant_id = os.environ.get("HELM_TENANT_ID", "default")
    principal_id = os.environ.get("HELM_PRINCIPAL_ID", "sdk-python-agent")
    session_id = os.environ.get("HELM_SESSION_ID", "sdk-python-session")
    with HelmClient(
        base_url=helm_url,
        api_key=admin_key,
        tenant_id=tenant_id,
        principal_id=principal_id,
        workspace_id=os.environ.get("HELM_WORKSPACE_ID"),
    ) as helm:
        evaluation_scope = EvaluationScope(
            tenant_id=tenant_id,
            principal_id=principal_id,
            session_id=session_id,
            workspace_id=os.environ.get("HELM_WORKSPACE_ID"),
        )
        allowed = helm.evaluate_decision_with_scope(
            DecisionRequest(
                action="read-ticket",
                resource="ticket:SDK-100",
                context={"example": "python-sdk"},
            ),
            evaluation_scope,
            "sdk-python-allowed",
        )
        denied = helm.evaluate_decision_with_scope(
            DecisionRequest(
                action="dangerous-shell",
                resource="system:shell",
                context={"example": "python-sdk"},
            ),
            evaluation_scope,
            "sdk-python-denied",
        )
        allowed_record = allowed.decision.to_dict()
        denied_record = denied.decision.to_dict()
        require_verdict(allowed_record, "ALLOW", "allowed tool call")
        require_verdict(denied_record, "DENY", "denied dangerous action")

        demo = helm.run_public_demo("read_ticket")
        receipt = require_receipt(demo, "signed receipt")
        verification = helm.verify_public_demo_receipt(
            receipt,
            str(demo["proof_refs"]["receipt_hash"]),
        )
        if verification.get("valid") is not True:
            raise AssertionError(f"receipt verification failed: {verification}")

        mcp_verdict = require_mcp_denial(helm)
        preflight = helm.preflight_sandbox_grant(
            {
                "runtime": "wazero",
                "profile": "sdk-python-example",
                "image_digest": "sha256:" + "a" * 64,
                "policy_epoch": "sdk-python-example",
            }
        )
        require_verdict(preflight, "ALLOW", "sandbox preflight")

        evidence = helm.export_evidence(session_id)
        evidence_result = helm.verify_evidence(evidence)
        if evidence_result.verdict != "PASS":
            raise AssertionError(f"evidence verification failed: {evidence_result.to_dict()}")

    print(
        json.dumps(
            {
                "sdk": "python",
                "allowed": allowed_record["verdict"],
                "denied": denied_record["verdict"],
                "mcp_unknown_server": mcp_verdict,
                "receipt_verified": True,
                "sandbox_preflight": preflight["verdict"],
                "evidence_verification": evidence_result.verdict,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
