from helm_sdk import reason_codes


def test_registry_strings() -> None:
    assert len(reason_codes.ALL) == 106
    assert reason_codes.EMERGENCY_STOP_FENCED == "EMERGENCY_STOP_FENCED"
    assert reason_codes.is_registered(reason_codes.EMERGENCY_STOP_FENCED)
    assert not reason_codes.is_registered("NOT_A_REGISTERED_CODE")
