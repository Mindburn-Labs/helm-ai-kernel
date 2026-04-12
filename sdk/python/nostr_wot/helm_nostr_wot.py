"""
HELM Nostr Web-of-Trust Identity Bridge (Python)

Maps Nostr pubkeys to HELM trust scores and verifies Nostr events
through HELM governance. Uses stdlib only (no external deps beyond helm-sdk).

Usage:
    from helm_nostr_wot import NostrWoTBridge

    bridge = NostrWoTBridge(helm_url="http://localhost:8080")
    score = bridge.resolve_trust("npub1...")
    result = bridge.verify_event({"id": "...", "pubkey": "...", ...})
"""

from __future__ import annotations

import hashlib
import json
import time
import threading
from dataclasses import dataclass, field
from typing import Any, Optional
import urllib.request
import urllib.error


@dataclass
class TrustScore:
    """HELM trust score for a Nostr identity."""
    nostr_pubkey: str
    helm_principal: str
    score: float  # 0.0 (untrusted) to 1.0 (fully trusted)
    confidence: float  # 0.0 to 1.0
    reason_code: str
    resolved_at: str
    metadata: dict = field(default_factory=dict)


@dataclass
class EventVerification:
    """Result of verifying a Nostr event through HELM governance."""
    event_id: str
    nostr_pubkey: str
    allowed: bool
    verdict: str  # "ALLOW" | "DENY" | "ESCALATE"
    reason_code: str
    receipt_id: str
    trust_score: Optional[TrustScore] = None
    error: Optional[str] = None


@dataclass
class HelmReceipt:
    """Governance receipt for a Nostr WoT operation."""
    receipt_id: str
    timestamp: str
    operation: str
    nostr_pubkey: str
    verdict: str
    reason_code: str
    lamport_clock: int
    prev_hash: str
    hash: str
    metadata: dict = field(default_factory=dict)


class NostrWoTBridge:
    """
    Maps Nostr Web-of-Trust identities to HELM trust scores.

    Resolves Nostr pubkeys against HELM's identity registry and
    evaluates Nostr events through the governance plane. Operates
    fail-closed: unreachable HELM server results in zero trust score
    and denied events.

    Args:
        helm_url: Base URL of HELM server
        fail_closed: Deny on HELM unreachable (default: True)
        default_principal_prefix: Prefix for mapping Nostr pubkeys to HELM principals
        metadata: Global metadata for all receipts
    """

    def __init__(
        self,
        helm_url: str = "http://localhost:8080",
        fail_closed: bool = True,
        default_principal_prefix: str = "nostr:",
        metadata: Optional[dict] = None,
    ):
        self.helm_url = helm_url.rstrip("/")
        self.fail_closed = fail_closed
        self.default_principal_prefix = default_principal_prefix
        self.metadata = metadata or {}
        self._receipts: list[HelmReceipt] = []
        self._prev_hash = "GENESIS"
        self._lamport = 0
        self._lock = threading.Lock()

    def resolve_trust(self, nostr_pubkey: str) -> TrustScore:
        """
        Resolve a Nostr pubkey to a HELM trust score.

        Maps the Nostr identity to a HELM principal and queries the
        trust registry for its current score.

        Args:
            nostr_pubkey: Nostr public key (hex or npub format)

        Returns:
            TrustScore with the resolved trust level
        """
        helm_principal = self._pubkey_to_principal(nostr_pubkey)
        resolved_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        try:
            response = self._call_helm("/v1/trust/resolve", {
                "principal": helm_principal,
                "source": "nostr-wot",
                "pubkey": nostr_pubkey,
            })
            score = TrustScore(
                nostr_pubkey=nostr_pubkey,
                helm_principal=helm_principal,
                score=float(response.get("score", 0.0)),
                confidence=float(response.get("confidence", 0.0)),
                reason_code=response.get("reason_code", "RESOLVED"),
                resolved_at=resolved_at,
                metadata=response.get("metadata", {}),
            )
        except (urllib.error.URLError, ConnectionError):
            if self.fail_closed:
                score = TrustScore(
                    nostr_pubkey=nostr_pubkey,
                    helm_principal=helm_principal,
                    score=0.0,
                    confidence=0.0,
                    reason_code="HELM_UNREACHABLE",
                    resolved_at=resolved_at,
                )
            else:
                score = TrustScore(
                    nostr_pubkey=nostr_pubkey,
                    helm_principal=helm_principal,
                    score=0.5,
                    confidence=0.0,
                    reason_code="HELM_UNREACHABLE_OPEN",
                    resolved_at=resolved_at,
                )

        self._record_receipt("resolve_trust", nostr_pubkey, score.reason_code)
        return score

    def verify_event(self, nostr_event: dict) -> EventVerification:
        """
        Verify a Nostr event through HELM governance.

        Evaluates the event's pubkey, kind, and content against HELM
        policy before allowing it to proceed.

        Args:
            nostr_event: Nostr event dict with at least "id", "pubkey", "kind", "content"

        Returns:
            EventVerification with the governance verdict
        """
        event_id = nostr_event.get("id", "")
        pubkey = nostr_event.get("pubkey", "")
        kind = nostr_event.get("kind", 0)
        helm_principal = self._pubkey_to_principal(pubkey)

        verdict = "ALLOW"
        reason_code = "POLICY_PASS"
        trust_score = None

        try:
            # Resolve trust first.
            trust_score = self.resolve_trust(pubkey)

            # Evaluate event through HELM governance.
            response = self._call_helm("/v1/tools/evaluate", {
                "tool_name": f"nostr.event.kind_{kind}",
                "arguments": {
                    "event_id": event_id,
                    "pubkey": pubkey,
                    "kind": kind,
                    "content": nostr_event.get("content", ""),
                    "tags": nostr_event.get("tags", []),
                },
                "principal": helm_principal,
                "trust_score": trust_score.score,
            })
            verdict = response.get("verdict", "ALLOW")
            reason_code = response.get("reason_code", "POLICY_PASS")
        except (urllib.error.URLError, ConnectionError):
            if self.fail_closed:
                verdict = "DENY"
                reason_code = "HELM_UNREACHABLE"

        receipt = self._record_receipt(
            f"verify_event.kind_{kind}",
            pubkey,
            reason_code,
        )

        return EventVerification(
            event_id=event_id,
            nostr_pubkey=pubkey,
            allowed=verdict == "ALLOW",
            verdict=verdict,
            reason_code=reason_code,
            receipt_id=receipt.receipt_id,
            trust_score=trust_score,
            error=reason_code if verdict != "ALLOW" else None,
        )

    @property
    def receipts(self) -> list[HelmReceipt]:
        """Get all collected receipts."""
        return list(self._receipts)

    def export_evidence_pack(self, path: str) -> str:
        """Export receipts as deterministic .tar EvidencePack."""
        import tarfile
        import io as _io

        with tarfile.open(path, "w") as tar:
            for i, receipt in enumerate(sorted(self._receipts, key=lambda r: r.lamport_clock)):
                data = json.dumps({
                    "receipt_id": receipt.receipt_id,
                    "timestamp": receipt.timestamp,
                    "operation": receipt.operation,
                    "nostr_pubkey": receipt.nostr_pubkey,
                    "verdict": receipt.verdict,
                    "reason_code": receipt.reason_code,
                    "lamport_clock": receipt.lamport_clock,
                    "prev_hash": receipt.prev_hash,
                    "hash": receipt.hash,
                    "metadata": receipt.metadata,
                }, indent=2).encode()

                info = tarfile.TarInfo(name=f"{i:03d}_{receipt.receipt_id}.json")
                info.size = len(data)
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                tar.addfile(info, _io.BytesIO(data))

            manifest = json.dumps({
                "session_id": f"nostr-wot-{int(time.time())}",
                "receipt_count": len(self._receipts),
                "final_hash": self._prev_hash,
                "lamport": self._lamport,
                "bridge": "nostr-wot",
            }, indent=2).encode()
            info = tarfile.TarInfo(name="manifest.json")
            info.size = len(manifest)
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            tar.addfile(info, _io.BytesIO(manifest))

        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def _pubkey_to_principal(self, nostr_pubkey: str) -> str:
        """Map a Nostr pubkey to a HELM principal identifier."""
        return f"{self.default_principal_prefix}{nostr_pubkey}"

    def _record_receipt(self, operation: str, nostr_pubkey: str, reason_code: str) -> HelmReceipt:
        """Record a governance receipt with hash chaining."""
        verdict = "ALLOW" if reason_code == "POLICY_PASS" or reason_code == "RESOLVED" else "DENY"

        with self._lock:
            self._lamport += 1
            lamport = self._lamport
            prev_hash = self._prev_hash

            preimage = f"{operation}|{nostr_pubkey}|{verdict}|{reason_code}|{lamport}|{prev_hash}"
            receipt_hash = hashlib.sha256(preimage.encode()).hexdigest()
            self._prev_hash = receipt_hash

        receipt = HelmReceipt(
            receipt_id=f"rcpt-nostr-{receipt_hash[:8]}-{lamport}",
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            operation=operation,
            nostr_pubkey=nostr_pubkey,
            verdict=verdict,
            reason_code=reason_code,
            lamport_clock=lamport,
            prev_hash=prev_hash,
            hash=receipt_hash,
            metadata={**self.metadata, "bridge": "nostr-wot"},
        )
        with self._lock:
            self._receipts.append(receipt)

        return receipt

    def _call_helm(self, endpoint: str, payload: dict) -> dict:
        """Call the HELM API."""
        url = f"{self.helm_url}{endpoint}"
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
