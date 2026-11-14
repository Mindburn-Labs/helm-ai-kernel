# quantum_posture: regression checks for classical Ed25519 receipt verification only.
"""Offline receipt.v5 verification, held to the vectors receipt_verify passes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from helm_sdk import verify_receipt
from helm_sdk.verify import SIGNED_MEMBERS, _ed25519_verify, _signing_payload

VECTORS = (
    Path(__file__).resolve().parents[3]
    / "core/pkg/receiptverify/testdata/offline-verifier-vectors.json"
)
REFERENCE_PACK = Path(__file__).resolve().parents[3] / "reference_packs/receipt-v5"


def _vectors() -> list[dict]:
    return json.loads(VECTORS.read_text(encoding="utf-8"))["vectors"]


@pytest.mark.parametrize("vector", _vectors(), ids=lambda v: v["id"])
def test_shared_vector(vector: dict) -> None:
    result = verify_receipt(vector["receipt"], vector["trusted_keys"])
    assert result.valid is vector["valid"], result.detail
    if vector["valid"]:
        assert result.error is None
        assert result.verdict == vector["verdict"]
        assert result.receipt_id == vector["receipt_id"]
    else:
        assert result.error == vector["error"], result.detail
        assert result.signed == {}


def test_bytes_and_trusted_key_forms_agree_with_text() -> None:
    vector = next(
        v for v in _vectors() if v["id"] == "reference_escaped_string_members"
    )
    keys = vector["trusted_keys"]
    assert verify_receipt(vector["receipt"].encode("utf-8"), keys).valid
    assert not verify_receipt(json.loads(vector["receipt"]), keys).valid
    assert verify_receipt(vector["receipt"], {"any-id": keys[0]}).valid
    assert verify_receipt(vector["receipt"], "ed25519:" + keys[0]).valid


def test_signing_payload_matches_the_reference_pack() -> None:
    pack = json.loads((REFERENCE_PACK / "vectors.json").read_text(encoding="utf-8"))
    for vector in pack["vectors"]:
        receipt = json.loads(
            (REFERENCE_PACK / vector["receipt"]["canonical"]).read_text(
                encoding="utf-8"
            )
        )
        expected = (
            (REFERENCE_PACK / vector["signing_payload"]["canonical"])
            .read_bytes()
            .rstrip(b"\n")
        )
        signed = {k: receipt[k] for k in json.loads(expected)}
        assert _signing_payload(signed) == expected, vector["id"]


def test_invalid_utf8_and_bad_keys_are_refused() -> None:
    vector = _vectors()[0]
    assert (
        verify_receipt(
            b"\xff" + vector["receipt"].encode(), vector["trusted_keys"]
        ).error
        == "malformed"
    )
    assert verify_receipt(vector["receipt"], []).error == "no_trusted_key"
    assert verify_receipt(vector["receipt"], ["not-hex"]).error == "bad_key"
    assert verify_receipt(42, vector["trusted_keys"]).error == "malformed"  # type: ignore[arg-type]


def test_ed25519_rejects_non_canonical_s() -> None:
    vector = _vectors()[0]
    receipt = json.loads(vector["receipt"])
    key = bytes.fromhex(vector["trusted_keys"][0])
    signature = bytes.fromhex(receipt["signature"])
    payload = _signing_payload({member: receipt[member] for member in SIGNED_MEMBERS})
    assert _ed25519_verify(key, payload, signature)
    order = 2**252 + 27742317777372353535851937790883648493
    s = int.from_bytes(signature[32:], "little") + order
    assert not _ed25519_verify(key, payload, signature[:32] + s.to_bytes(32, "little"))
    assert not _ed25519_verify(key[:31], payload, signature)


def test_raw_receipt_fetch_preserves_wire_input() -> None:
    import httpx

    from helm_sdk import HelmClient

    raw = b'{"lamport_clock":1e0,"verdict":"ALLOW","verdict":"DENY"}'
    requests = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, content=raw)

    with HelmClient(
        base_url="https://example.invalid", api_key="local-test-token"
    ) as helm:
        helm._client.close()
        helm._client = httpx.Client(
            base_url="https://example.invalid",
            headers={"Authorization": "Bearer local-test-token"},
            transport=httpx.MockTransport(respond),
        )
        assert helm.get_receipt_json("receipt-test") == raw
    assert requests[0].url.raw_path == b"/api/v1/proofgraph/receipts/receipt-test"
    assert requests[0].headers["Authorization"] == "Bearer local-test-token"
