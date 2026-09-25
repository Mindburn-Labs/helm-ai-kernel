import json
from pathlib import Path

import httpx
import pytest

from helm_sdk.client import HelmApiError, HelmClient

# The kernel pins this body in core/pkg/httperr (TestErrorModelVector).
VECTOR = Path(__file__).parents[3] / "protocols/specs/errors/error-model-503.json"


def test_reads_the_helm_error_model() -> None:
    body = json.loads(VECTOR.read_text())
    client = HelmClient("http://kernel.test")
    response = httpx.Response(503, json=body)
    with pytest.raises(HelmApiError) as raised:
        client._check(response)
    err = raised.value
    assert str(err) == "emergency-stop fence active"
    assert err.reason_code == "EMERGENCY_STOP_FENCED"
    assert err.code == "unavailable"
    assert err.retryable is True
