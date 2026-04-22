"""
HELM Receipt Verification Example (Python SDK)

Demonstrates how to:
1. Connect to a HELM kernel
2. List ProofGraph sessions
3. Retrieve receipts
4. Verify receipt integrity (hash + signature)
5. Export and verify evidence packs

Prerequisites:
  pip install helm
"""
import hashlib
import json
from helm_sdk import HelmClient

def main():
    # 1. Connect to HELM kernel
    client = HelmClient(
        base_url="http://localhost:8080",
        api_key="your-api-key-here"  # or set HELM_API_KEY env var
    )

    # 2. Health check
    health = client.health()
    print(f"✅ Kernel healthy: {health}")

    # 3. List sessions
    sessions = client.list_sessions()
    print(f"📋 Found {len(sessions)} ProofGraph sessions")

    if not sessions:
        print("No sessions yet. Execute a tool call first.")
        return

    session = sessions[0]
    print(f"  → Using session: {session.session_id}")

    # 4. Get receipts for session
    receipts = client.get_receipts(session.session_id)
    print(f"🧾 Found {len(receipts)} receipts")

    for receipt in receipts[:3]:  # Show first 3
        print(f"\n  Receipt: {receipt.receipt_id}")
        print(f"  Status:  {receipt.status}")
        print(f"  Hash:    {receipt.blob_hash}")
        print(f"  Time:    {receipt.timestamp}")

        # 5. Verify receipt hash locally
        # The blob_hash is SHA-256 of the JCS-canonicalized receipt payload
        payload = {
            "decision_id": receipt.decision_id,
            "effect_id": receipt.effect_id,
            "executor_id": receipt.executor_id,
            "status": receipt.status,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        computed_hash = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()

        if computed_hash == receipt.blob_hash:
            print(f"  ✅ Hash verified locally")
        else:
            print(f"  ⚠️  Local hash: {computed_hash}")
            print(f"     Receipt hash: {receipt.blob_hash}")
            print(f"     (Mismatch may indicate tampered receipt)")

    # 6. Export evidence pack
    print(f"\n📦 Exporting evidence pack...")
    evidence = client.export_evidence(session.session_id)
    print(f"  Bundle size: {len(evidence)} bytes")

    # 7. Verify evidence pack integrity
    result = client.verify_evidence(evidence)
    print(f"\n🔍 Verification result:")
    print(f"  Valid:     {result.valid}")
    print(f"  Integrity: {result.integrity_check}")
    print(f"  Receipts:  {result.receipt_count}")

    if result.valid:
        print("\n✅ Evidence pack integrity VERIFIED")
    else:
        print("\n❌ Evidence pack verification FAILED")

if __name__ == "__main__":
    main()
