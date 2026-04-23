import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf import duration_pb2 as _duration_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class EffectType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EFFECT_TYPE_UNSPECIFIED: _ClassVar[EffectType]
    EFFECT_TYPE_READ: _ClassVar[EffectType]
    EFFECT_TYPE_WRITE: _ClassVar[EffectType]
    EFFECT_TYPE_DELETE: _ClassVar[EffectType]
    EFFECT_TYPE_EXECUTE: _ClassVar[EffectType]
    EFFECT_TYPE_NETWORK: _ClassVar[EffectType]
    EFFECT_TYPE_FINANCE: _ClassVar[EffectType]
EFFECT_TYPE_UNSPECIFIED: EffectType
EFFECT_TYPE_READ: EffectType
EFFECT_TYPE_WRITE: EffectType
EFFECT_TYPE_DELETE: EffectType
EFFECT_TYPE_EXECUTE: EffectType
EFFECT_TYPE_NETWORK: EffectType
EFFECT_TYPE_FINANCE: EffectType

class EffectScope(_message.Message):
    __slots__ = ("allowed_action", "allowed_params", "deny_patterns")
    ALLOWED_ACTION_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_PARAMS_FIELD_NUMBER: _ClassVar[int]
    DENY_PATTERNS_FIELD_NUMBER: _ClassVar[int]
    allowed_action: str
    allowed_params: _containers.RepeatedScalarFieldContainer[str]
    deny_patterns: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, allowed_action: _Optional[str] = ..., allowed_params: _Optional[_Iterable[str]] = ..., deny_patterns: _Optional[_Iterable[str]] = ...) -> None: ...

class EffectPermit(_message.Message):
    __slots__ = ("permit_id", "intent_hash", "verdict_hash", "plan_hash", "policy_hash", "effect_type", "connector_id", "scope", "resource_ref", "expires_at", "single_use", "nonce", "issued_at", "issuer_id", "signature")
    PERMIT_ID_FIELD_NUMBER: _ClassVar[int]
    INTENT_HASH_FIELD_NUMBER: _ClassVar[int]
    VERDICT_HASH_FIELD_NUMBER: _ClassVar[int]
    PLAN_HASH_FIELD_NUMBER: _ClassVar[int]
    POLICY_HASH_FIELD_NUMBER: _ClassVar[int]
    EFFECT_TYPE_FIELD_NUMBER: _ClassVar[int]
    CONNECTOR_ID_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_REF_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    SINGLE_USE_FIELD_NUMBER: _ClassVar[int]
    NONCE_FIELD_NUMBER: _ClassVar[int]
    ISSUED_AT_FIELD_NUMBER: _ClassVar[int]
    ISSUER_ID_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    permit_id: str
    intent_hash: str
    verdict_hash: str
    plan_hash: str
    policy_hash: str
    effect_type: EffectType
    connector_id: str
    scope: EffectScope
    resource_ref: str
    expires_at: _timestamp_pb2.Timestamp
    single_use: bool
    nonce: str
    issued_at: _timestamp_pb2.Timestamp
    issuer_id: str
    signature: str
    def __init__(self, permit_id: _Optional[str] = ..., intent_hash: _Optional[str] = ..., verdict_hash: _Optional[str] = ..., plan_hash: _Optional[str] = ..., policy_hash: _Optional[str] = ..., effect_type: _Optional[_Union[EffectType, str]] = ..., connector_id: _Optional[str] = ..., scope: _Optional[_Union[EffectScope, _Mapping]] = ..., resource_ref: _Optional[str] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., single_use: bool = ..., nonce: _Optional[str] = ..., issued_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., issuer_id: _Optional[str] = ..., signature: _Optional[str] = ...) -> None: ...

class GatewayEffectRequest(_message.Message):
    __slots__ = ("request_id", "effect_type", "connector_id", "tool_name", "params", "resource_ref", "plan_hash", "policy_hash", "verdict_hash", "requested_at")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    EFFECT_TYPE_FIELD_NUMBER: _ClassVar[int]
    CONNECTOR_ID_FIELD_NUMBER: _ClassVar[int]
    TOOL_NAME_FIELD_NUMBER: _ClassVar[int]
    PARAMS_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_REF_FIELD_NUMBER: _ClassVar[int]
    PLAN_HASH_FIELD_NUMBER: _ClassVar[int]
    POLICY_HASH_FIELD_NUMBER: _ClassVar[int]
    VERDICT_HASH_FIELD_NUMBER: _ClassVar[int]
    REQUESTED_AT_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    effect_type: EffectType
    connector_id: str
    tool_name: str
    params: bytes
    resource_ref: str
    plan_hash: str
    policy_hash: str
    verdict_hash: str
    requested_at: _timestamp_pb2.Timestamp
    def __init__(self, request_id: _Optional[str] = ..., effect_type: _Optional[_Union[EffectType, str]] = ..., connector_id: _Optional[str] = ..., tool_name: _Optional[str] = ..., params: _Optional[bytes] = ..., resource_ref: _Optional[str] = ..., plan_hash: _Optional[str] = ..., policy_hash: _Optional[str] = ..., verdict_hash: _Optional[str] = ..., requested_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class GatewayEffectOutcome(_message.Message):
    __slots__ = ("request_id", "permit_id", "success", "output", "error", "output_hash", "duration", "completed_at")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    PERMIT_ID_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_HASH_FIELD_NUMBER: _ClassVar[int]
    DURATION_FIELD_NUMBER: _ClassVar[int]
    COMPLETED_AT_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    permit_id: str
    success: bool
    output: bytes
    error: str
    output_hash: str
    duration: _duration_pb2.Duration
    completed_at: _timestamp_pb2.Timestamp
    def __init__(self, request_id: _Optional[str] = ..., permit_id: _Optional[str] = ..., success: bool = ..., output: _Optional[bytes] = ..., error: _Optional[str] = ..., output_hash: _Optional[str] = ..., duration: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ..., completed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...
