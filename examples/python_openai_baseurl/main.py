"""
HELM SDK Example — Python

Shows: chat completions, denial handling, conformance.
Run: pip install httpx && python main.py
"""

import sys
sys.path.insert(0, "../../sdk/python")

from helm_sdk import HelmClient, HelmApiError, ChatCompletionRequest, ConformanceRequest
from helm_sdk.types_gen import ChatMessage

HELM_URL = "http://localhost:8080"

def main():
    helm = HelmClient(base_url=HELM_URL)

    # 1. Chat completions (governed by HELM)
    print("=== Chat Completions ===")
    try:
        res = helm.chat_completions(ChatCompletionRequest(
            model="gpt-4",
            messages=[ChatMessage(role="user", content="List files in /tmp")],
        ))
        print(f"Response: {res.choices[0].message.content if res.choices else 'no choices'}")
    except HelmApiError as e:
        print(f"Denied: {e.reason_code} — {e}")

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
