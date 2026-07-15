"""
HELM SDK Example — Python

Shows: chat completions, denial handling, conformance.
Run: pip install httpx && python main.py
"""

import os
import sys
sys.path.insert(0, "../../sdk/python")

from helm_sdk import ChatCompletionRequest, ChatMessage, ConformanceRequest, HelmApiError, HelmClient

HELM_URL = os.environ.get("HELM_URL", "http://127.0.0.1:7714")


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"{name} is required for the governed serve runtime")
    return value

def main():
    helm = HelmClient(
        base_url=HELM_URL,
        api_key=required_env("HELM_ADMIN_API_KEY"),
        tenant_id=required_env("HELM_TENANT_ID"),
        principal_id=required_env("HELM_PRINCIPAL_ID"),
        workspace_id=os.environ.get("HELM_WORKSPACE_ID", "").strip() or None,
        session_id=required_env("HELM_SESSION_ID"),
    )

    # 1. Chat completions (governed by HELM)
    print("=== Chat Completions ===")
    try:
        res = helm.chat_completions(ChatCompletionRequest(
            model="gpt-4",
            messages=[ChatMessage(role="user", content="List files in /tmp")],
        ))
        print(f"Response: {res.choices[0].message.content if res.choices else 'no choices'}")
    except (HelmApiError, ValueError) as e:
        print(f"Denied: {getattr(e, 'reason_code', 'LOCAL_VALIDATION')} — {e}")

    # 2. Export + verify evidence
    print("\n=== Evidence ===")
    try:
        pack = helm.export_evidence()
        print(f"Exported {len(pack)} bytes")
        result = helm.verify_evidence(pack)
        print(f"Verification: {result.verdict}")
    except HelmApiError as e:
        print(f"Evidence error: {e.reason_code}")

    # 3. Conformance
    print("\n=== Conformance ===")
    try:
        conf = helm.conformance_run(ConformanceRequest(level="L2"))
        print(f"Verdict: {conf.verdict}, Gates: {conf.gates}, Failed: {conf.failed}")
    except HelmApiError as e:
        print(f"Conformance error: {e.reason_code}")

    # 4. Health
    print("\n=== Health ===")
    try:
        h = helm.health()
        print(f"Status: {h}")
    except Exception as e:
        print(f"Health check failed: {e}")

if __name__ == "__main__":
    main()
