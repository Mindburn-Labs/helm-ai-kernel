"""Offline verification of HELM receipt.v5 signatures.

``verify_receipt`` answers one question without contacting HELM: did the
holder of a public key you trust sign this receipt, and do its signed members
say what the receipt says? It reads no network, clock or environment.

It checks the receipt.v5 signed envelope:

- the document is one JSON object with no duplicate member and no member that
  differs from a typed receipt member only in letter case; at most 64 nested containers;
- ``signature_version`` is ``receipt.v5`` (an unversioned legacy receipt is
  refused) and the thirteen signed members are present with their wire types;
- ``lamport_clock`` is an integer in the interoperable range [0, 2**53 - 1];
- ``signature_profile`` and ``signature_algorithm`` are both absent or empty,
  or exactly ``classical`` and ``ed25519``;
- the Ed25519 signature verifies over the RFC 8785 canonical JSON of the
  thirteen signed members under one of the trusted keys.

``key_id`` is a routing hint, never a filter: every trusted key is tried. The
receipt's own ``public_key_set`` is never trusted. Chain linkage (prev_hash),
permits and gateway binding documents are checked by ``receipt_verify``, not
here. The schema of unsigned metadata is not validated. Only ``signed``
contains authenticated members; ``key_id`` is an unsigned claim. Invalid
UTF-8 is refused.

The shared vectors in
``core/pkg/receiptverify/testdata/offline-verifier-vectors.json`` hold this
module, the Go and TypeScript SDKs and ``receipt_verify`` to the same verdicts.

quantum_posture: classical Ed25519 only; no hybrid or post-quantum claim.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .verify_members import check_receipt_member_names

RECEIPT_SIGNATURE_V5 = "receipt.v5"
MAX_SAFE_INTEGER = 9007199254740991

# The receipt.v5 signed members, in RFC 8785 (UTF-16 code unit) order. All
# are ASCII, so this is also byte order.
SIGNED_MEMBERS = (
    "args_hash",
    "decision_id",
    "effect_id",
    "lamport_clock",
    "output_hash",
    "policy_hash",
    "prev_hash",
    "reason_code",
    "receipt_id",
    "session_id",
    "signature_version",
    "status",
    "verdict",
)
_STRING_MEMBERS = tuple(m for m in SIGNED_MEMBERS if m != "lamport_clock")
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX128 = re.compile(r"^[0-9a-fA-F]{128}$")
_INTEGER = re.compile(r"^(0|[1-9][0-9]*)$")
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")

TrustedKeys = Union[str, Iterable[str], Mapping[str, str]]


@dataclass(frozen=True)
class ReceiptVerification:
    """The verdict. ``valid`` is True only when every check passed."""

    valid: bool
    error: str | None = None
    detail: str = ""
    receipt_id: str = ""
    verdict: str = ""
    reason_code: str = ""
    key_id: str = ""
    signed: dict[str, Any] = field(default_factory=dict)


class _Refused(Exception):
    def __init__(self, error: str, detail: str):
        super().__init__(detail)
        self.error = error
        self.detail = detail


class _Integer:
    """A JSON integer literal kept as written."""

    __slots__ = ("literal",)

    def __init__(self, literal: str):
        self.literal = literal


class _NonInteger:
    """A JSON number with a fraction or exponent, kept as written."""

    __slots__ = ("literal",)

    def __init__(self, literal: str):
        self.literal = literal


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in items:
        key = _string(key)
        if key in out:
            raise _Refused("duplicate_member", f"duplicate object member {key!r}")
        out[key] = value
    return out


def _constant(name: str) -> Any:
    raise _Refused("malformed", f"{name} is not a JSON value")


def _check_depth(text: str) -> None:
    depth = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > 64:
                raise _Refused("malformed", "JSON exceeds the 64-level nesting limit")
        elif ch in "]}":
            depth -= 1


def _parse(document: str | bytes | bytearray) -> dict[str, Any]:
    if isinstance(document, (bytes, bytearray)):
        try:
            text = bytes(document).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _Refused("malformed", "receipt document must be UTF-8") from exc
    elif isinstance(document, str):
        text = document
    else:
        raise _Refused("malformed", "receipt must be raw JSON text or bytes")
    _check_depth(text)
    try:
        text.encode("utf-8")
        parsed = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_Integer,
            parse_float=_NonInteger,
            parse_constant=_constant,
        )
    except _Refused:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise _Refused("malformed", f"receipt is not one JSON value: {exc}") from exc
    if not isinstance(parsed, dict):
        raise _Refused("malformed", "receipt must be a JSON object")
    if "receipts" in parsed:
        raise _Refused("malformed", "input must be one receipt object, not a bundle")
    return parsed


def _string(value: str) -> str:
    # encoding/json decodes an unpaired surrogate escape to U+FFFD; so does
    # the signer, so the verifier must too.
    return _LONE_SURROGATE.sub("�", value)


def _check_members(receipt: dict[str, Any]) -> tuple[dict[str, Any], str]:
    check_receipt_member_names(receipt, _Refused)
    if "signature_version" not in receipt:
        raise _Refused(
            "unsupported_version",
            "receipt has no signature_version; legacy receipts are not verified here",
        )
    version = receipt["signature_version"]
    if not isinstance(version, str) or version != RECEIPT_SIGNATURE_V5:
        raise _Refused(
            "unsupported_version", f"unsupported receipt signature version {version!r}"
        )
    signed: dict[str, Any] = {}
    for member in _STRING_MEMBERS:
        if member not in receipt:
            raise _Refused(
                "missing_member", f"receipt.v5 missing signed member {member!r}"
            )
        value = receipt[member]
        if not isinstance(value, str):
            raise _Refused(
                "missing_member",
                f"receipt.v5 signed member {member!r} must be a string",
            )
        signed[member] = _string(value)
    if "lamport_clock" not in receipt:
        raise _Refused(
            "missing_member", "receipt.v5 missing signed member 'lamport_clock'"
        )
    clock = receipt["lamport_clock"]
    if isinstance(clock, _NonInteger):
        raise _Refused(
            "non_interoperable_number",
            f"lamport_clock {clock.literal!r} is not an integer",
        )
    if not isinstance(clock, _Integer):
        raise _Refused(
            "missing_member",
            "receipt.v5 signed member 'lamport_clock' must be an unsigned integer",
        )
    if (
        not _INTEGER.fullmatch(clock.literal)
        or len(clock.literal) > 16
        or (len(clock.literal) == 16 and clock.literal > str(MAX_SAFE_INTEGER))
    ):
        raise _Refused(
            "non_interoperable_number",
            f"lamport_clock {clock.literal!r} is outside "
            "the interoperable range [0, 2**53 - 1]",
        )
    signed["lamport_clock"] = int(clock.literal)

    profile = receipt.get("signature_profile", "")
    algorithm = receipt.get("signature_algorithm", "")
    if not isinstance(profile, str) or not isinstance(algorithm, str):
        raise _Refused(
            "signature_metadata",
            "signature_profile and signature_algorithm must be strings",
        )
    if not (
        (profile, algorithm) == ("", "")
        or (profile, algorithm) == ("classical", "ed25519")
    ):
        raise _Refused(
            "signature_metadata",
            "signature metadata must be both empty or exactly classical/ed25519",
        )
    signature = receipt.get("signature")
    if not isinstance(signature, str) or signature == "":
        raise _Refused("unsigned", "receipt carries no signature")
    if not _HEX128.fullmatch(signature):
        raise _Refused("signature_rejected", "signature is not 64 bytes of hex")
    key_id = receipt.get("key_id", "")
    return signed, (key_id if isinstance(key_id, str) else "")


def _jcs_string(value: str) -> str:
    out = ['"']
    for ch in value:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _signing_payload(signed: Mapping[str, Any]) -> bytes:
    """The RFC 8785 canonical bytes a receipt.v5 signature covers."""
    parts = []
    for member in SIGNED_MEMBERS:
        value = signed[member]
        rendered = str(value) if member == "lamport_clock" else _jcs_string(value)
        parts.append(f'"{member}":{rendered}')
    return ("{" + ",".join(parts) + "}").encode("utf-8")


def _trusted(keys: TrustedKeys, hint: str) -> list[bytes]:
    if isinstance(keys, str):
        named: list[tuple[str, str]] = [("", keys)]
    elif isinstance(keys, Mapping):
        named = [(str(k), v) for k, v in keys.items()]
    else:
        named = [("", k) for k in keys]
    if not named:
        raise _Refused("no_trusted_key", "no trusted public key supplied")
    ordered = sorted(named, key=lambda item: item[0] != hint or hint == "")
    out = []
    for _, value in ordered:
        if not isinstance(value, str):
            raise _Refused("bad_key", "a trusted key must be hex text")
        text = value.strip()
        if text.startswith("ed25519:"):
            text = text[len("ed25519:") :]
        if not _HEX64.fullmatch(text):
            raise _Refused(
                "bad_key", "a trusted key must be a 32-byte Ed25519 public key in hex"
            )
        out.append(bytes.fromhex(text))
    return out


def verify_receipt(
    receipt: str | bytes | bytearray,
    trusted_keys: TrustedKeys,
) -> ReceiptVerification:
    """Verify one receipt.v5 offline against keys you obtained out of band.

    ``receipt`` is the receipt as JSON text or bytes (preferred: duplicate
    members and number spellings must remain visible).
    ``trusted_keys`` is one hex Ed25519 public key, a list of them, or a
    mapping of key id to key. A key served by the same HELM that signed the
    receipt is HELM vouching for itself: pin it once, out of band.
    """
    try:
        document = _parse(receipt)
        signed, key_id = _check_members(document)
        keys = _trusted(trusted_keys, key_id)
        signature = bytes.fromhex(document["signature"])
        payload = _signing_payload(signed)
        if not any(_ed25519_verify(key, payload, signature) for key in keys):
            raise _Refused(
                "signature_rejected", "signature does not verify under any trusted key"
            )
    except _Refused as refused:
        return ReceiptVerification(
            valid=False, error=refused.error, detail=refused.detail
        )
    return ReceiptVerification(
        valid=True,
        detail="the receipt.v5 signature verifies under a trusted key",
        receipt_id=signed["receipt_id"],
        verdict=signed["verdict"],
        reason_code=signed["reason_code"],
        key_id=key_id,
        signed=signed,
    )


def _ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False
