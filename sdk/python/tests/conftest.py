"""Shared pytest fixtures for HELM Python SDK tests."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from helm_sdk.client import HelmClient


def make_mock_response(
    status_code: int = 200,
    json_data: Any = None,
    content: bytes = b"",
) -> MagicMock:
    """Create a mock httpx.Response with the given status/body."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data if json_data is not None else {}
    resp.text = json.dumps(json_data) if json_data else ""
    resp.content = content
    return resp


SAMPLE_RECEIPT = {
    "receipt_id": "r1",
    "decision_id": "d1",
    "effect_id": "e1",
    "status": "APPROVED",
    "reason_code": "ALLOW",
    "output_hash": "h",
    "blob_hash": "b",
    "prev_hash": "p",
    "lamport_clock": 1,
    "signature": "s",
    "timestamp": "2026-01-01T00:00:00Z",
    "principal": "pr",
}


@pytest.fixture()
def helm_client() -> HelmClient:
    """Return a HelmClient pointed at a dummy URL (for mocked tests)."""
    return HelmClient(base_url="http://test-helm:8080")


@pytest.fixture()
def sample_receipt() -> dict[str, Any]:
    """Return a sample receipt dict suitable for constructing Receipt objects."""
    return dict(SAMPLE_RECEIPT)
