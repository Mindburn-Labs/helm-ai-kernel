"""Evaluate, fetch exact receipt bytes, and verify locally with the public API."""
import json
import os
import sys
from pathlib import Path

from helm_sdk import EvaluateRequest, HelmClient, verify_receipt

if sys.argv[1:] == ["--offline"]:
    for expected in ["ALLOW", "DENY"]:
        raw = (Path(os.environ["HELM_SDK_EVIDENCE_DIR"]) / f"python-{expected}.receipt.json").read_bytes()
        key = os.environ["HELM_TRUSTED_RECEIPT_KEY"]
        result = verify_receipt(raw, key)
        assert result.valid and result.verdict == expected, result
        changed = json.loads(raw)
        changed["verdict"] = "TAMPERED"
        assert not verify_receipt(json.dumps(changed).encode(), key).valid
        assert not verify_receipt(raw, "00" * 32).valid
        print(json.dumps({"sdk": "python", "offline": True, "valid": True, "verdict": expected}))
    sys.exit(0)

with HelmClient(
    base_url=os.environ["HELM_URL"], api_key=os.environ["HELM_ADMIN_API_KEY"],
    tenant_id="sdk-offline-tenant", principal_id="sdk-offline-principal",
) as helm:
    for tool, effect, expected in [
        ("read-ticket", "ticket:SDK-100", "ALLOW"),
        ("dangerous-shell", "system:shell", "DENY"),
    ]:
        decision = helm.evaluate_decision_v5(EvaluateRequest(
            tool=tool, effect_level=effect, session_id="python-offline-sdk",
        ))
        assert decision.verdict == expected and decision.receipt_id
        raw = helm.get_receipt_json(decision.receipt_id)
        result = verify_receipt(raw, os.environ["HELM_TRUSTED_RECEIPT_KEY"])
        assert result.valid and result.verdict == expected, result
        assert result.receipt_id == decision.receipt_id
        assert not verify_receipt(raw, "00" * 32).valid
        if directory := os.environ.get("HELM_SDK_EVIDENCE_DIR"):
            (Path(directory) / f"python-{expected}.receipt.json").write_bytes(raw)
        print(json.dumps({"sdk": "python", "verdict": result.verdict,
                          "receipt_id": result.receipt_id, "valid": result.valid}))
