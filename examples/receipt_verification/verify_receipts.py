"""Inspect receipts and request server-side EvidencePack verification."""

import os
import sys

from helm_sdk import HelmClient


def main() -> int:
    with HelmClient(
        base_url=os.environ.get("HELM_URL", "http://127.0.0.1:7714"),
        api_key=os.environ.get("HELM_ADMIN_API_KEY") or os.environ.get("HELM_API_KEY"),
        tenant_id=os.environ.get("HELM_TENANT_ID"),
        principal_id=os.environ.get("HELM_PRINCIPAL_ID"),
    ) as helm:
        sessions = helm.list_sessions(limit=1)
        if not sessions:
            print("No ProofGraph sessions. Evaluate a tool call first.")
            return 0

        session_id = sessions[0].session_id
        if not session_id:
            raise ValueError("The server did not return a session ID.")

        receipts = helm.get_receipts(session_id)
        print(f"ProofGraph session {session_id} has {len(receipts)} receipts")
        for receipt in receipts[:3]:
            print(f"  {receipt.receipt_id}  {receipt.status}  input snapshot {receipt.blob_hash or '-'}")

        evidence = helm.export_evidence(session_id)
        result = helm.verify_evidence(evidence)
        print(f"Server-side EvidencePack verification: {result.outcome}")
        for check in result.checks_run:
            print(f"  {check.name}: {check.status} ({check.detail})")
        for error in result.errors:
            print(error, file=sys.stderr)
        return 0 if result.outcome == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
