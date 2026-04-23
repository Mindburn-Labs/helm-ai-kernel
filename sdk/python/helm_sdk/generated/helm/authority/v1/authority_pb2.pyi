import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class EvaluationResult(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EVALUATION_RESULT_UNSPECIFIED: _ClassVar[EvaluationResult]
    EVALUATION_RESULT_ALLOW: _ClassVar[EvaluationResult]
    EVALUATION_RESULT_DENY: _ClassVar[EvaluationResult]
    EVALUATION_RESULT_REQUIRE_APPROVAL: _ClassVar[EvaluationResult]
    EVALUATION_RESULT_REQUIRE_EVIDENCE: _ClassVar[EvaluationResult]
    EVALUATION_RESULT_DEFER: _ClassVar[EvaluationResult]
EVALUATION_RESULT_UNSPECIFIED: EvaluationResult
EVALUATION_RESULT_ALLOW: EvaluationResult
EVALUATION_RESULT_DENY: EvaluationResult
EVALUATION_RESULT_REQUIRE_APPROVAL: EvaluationResult
EVALUATION_RESULT_REQUIRE_EVIDENCE: EvaluationResult
EVALUATION_RESULT_DEFER: EvaluationResult

class EvaluationRequest(_message.Message):
    __slots__ = ("request_id", "principal_id", "principal_type", "effect_types", "policy_epoch", "idempotency_key", "context", "timestamp")
    class ContextEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    PRINCIPAL_ID_FIELD_NUMBER: _ClassVar[int]
    PRINCIPAL_TYPE_FIELD_NUMBER: _ClassVar[int]
    EFFECT_TYPES_FIELD_NUMBER: _ClassVar[int]
    POLICY_EPOCH_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    principal_id: str
    principal_type: str
    effect_types: _containers.RepeatedScalarFieldContainer[str]
    policy_epoch: str
    idempotency_key: str
    context: _containers.ScalarMap[str, str]
    timestamp: _timestamp_pb2.Timestamp
    def __init__(self, request_id: _Optional[str] = ..., principal_id: _Optional[str] = ..., principal_type: _Optional[str] = ..., effect_types: _Optional[_Iterable[str]] = ..., policy_epoch: _Optional[str] = ..., idempotency_key: _Optional[str] = ..., context: _Optional[_Mapping[str, str]] = ..., timestamp: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class EvaluationDecision(_message.Message):
    __slots__ = ("decision_id", "request_id", "result", "reason_codes", "policy_epoch", "issued_at", "expires_at", "content_hash")
    DECISION_ID_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    REASON_CODES_FIELD_NUMBER: _ClassVar[int]
    POLICY_EPOCH_FIELD_NUMBER: _ClassVar[int]
    ISSUED_AT_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    CONTENT_HASH_FIELD_NUMBER: _ClassVar[int]
    decision_id: str
    request_id: str
    result: EvaluationResult
    reason_codes: _containers.RepeatedScalarFieldContainer[str]
    policy_epoch: str
    issued_at: _timestamp_pb2.Timestamp
    expires_at: _timestamp_pb2.Timestamp
    content_hash: str
    def __init__(self, decision_id: _Optional[str] = ..., request_id: _Optional[str] = ..., result: _Optional[_Union[EvaluationResult, str]] = ..., reason_codes: _Optional[_Iterable[str]] = ..., policy_epoch: _Optional[str] = ..., issued_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., content_hash: _Optional[str] = ...) -> None: ...
