import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Verdict(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    VERDICT_UNSPECIFIED: _ClassVar[Verdict]
    VERDICT_ALLOW: _ClassVar[Verdict]
    VERDICT_DENY: _ClassVar[Verdict]
    VERDICT_ESCALATE: _ClassVar[Verdict]

class ReasonCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    REASON_CODE_UNSPECIFIED: _ClassVar[ReasonCode]
    REASON_CODE_POLICY_VIOLATION: _ClassVar[ReasonCode]
    REASON_CODE_NO_POLICY_DEFINED: _ClassVar[ReasonCode]
    REASON_CODE_PRG_EVALUATION_ERROR: _ClassVar[ReasonCode]
    REASON_CODE_MISSING_REQUIREMENT: _ClassVar[ReasonCode]
    REASON_CODE_PDP_DENY: _ClassVar[ReasonCode]
    REASON_CODE_PDP_ERROR: _ClassVar[ReasonCode]
    REASON_CODE_BUDGET_EXCEEDED: _ClassVar[ReasonCode]
    REASON_CODE_BUDGET_ERROR: _ClassVar[ReasonCode]
    REASON_CODE_ENVELOPE_INVALID: _ClassVar[ReasonCode]
    REASON_CODE_SCHEMA_VIOLATION: _ClassVar[ReasonCode]
    REASON_CODE_TEMPORAL_INTERVENTION: _ClassVar[ReasonCode]
    REASON_CODE_TEMPORAL_THROTTLE: _ClassVar[ReasonCode]
    REASON_CODE_SANDBOX_VIOLATION: _ClassVar[ReasonCode]
    REASON_CODE_PROVENANCE_FAILURE: _ClassVar[ReasonCode]
    REASON_CODE_VERIFICATION_FAILURE: _ClassVar[ReasonCode]
    REASON_CODE_TENANT_ISOLATION: _ClassVar[ReasonCode]
    REASON_CODE_JURISDICTION_VIOLATION: _ClassVar[ReasonCode]
VERDICT_UNSPECIFIED: Verdict
VERDICT_ALLOW: Verdict
VERDICT_DENY: Verdict
VERDICT_ESCALATE: Verdict
REASON_CODE_UNSPECIFIED: ReasonCode
REASON_CODE_POLICY_VIOLATION: ReasonCode
REASON_CODE_NO_POLICY_DEFINED: ReasonCode
REASON_CODE_PRG_EVALUATION_ERROR: ReasonCode
REASON_CODE_MISSING_REQUIREMENT: ReasonCode
REASON_CODE_PDP_DENY: ReasonCode
REASON_CODE_PDP_ERROR: ReasonCode
REASON_CODE_BUDGET_EXCEEDED: ReasonCode
REASON_CODE_BUDGET_ERROR: ReasonCode
REASON_CODE_ENVELOPE_INVALID: ReasonCode
REASON_CODE_SCHEMA_VIOLATION: ReasonCode
REASON_CODE_TEMPORAL_INTERVENTION: ReasonCode
REASON_CODE_TEMPORAL_THROTTLE: ReasonCode
REASON_CODE_SANDBOX_VIOLATION: ReasonCode
REASON_CODE_PROVENANCE_FAILURE: ReasonCode
REASON_CODE_VERIFICATION_FAILURE: ReasonCode
REASON_CODE_TENANT_ISOLATION: ReasonCode
REASON_CODE_JURISDICTION_VIOLATION: ReasonCode

class Effect(_message.Message):
    __slots__ = ("effect_type", "effect_id", "params", "budget_id")
    EFFECT_TYPE_FIELD_NUMBER: _ClassVar[int]
    EFFECT_ID_FIELD_NUMBER: _ClassVar[int]
    PARAMS_FIELD_NUMBER: _ClassVar[int]
    BUDGET_ID_FIELD_NUMBER: _ClassVar[int]
    effect_type: str
    effect_id: str
    params: bytes
    budget_id: str
    def __init__(self, effect_type: _Optional[str] = ..., effect_id: _Optional[str] = ..., params: _Optional[bytes] = ..., budget_id: _Optional[str] = ...) -> None: ...

class DecisionRecord(_message.Message):
    __slots__ = ("id", "timestamp", "verdict", "reason", "reason_code", "effect_digest", "requirement_set_hash", "signature", "signer_key_id", "policy_ref", "policy_decision_hash", "input_context")
    ID_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    VERDICT_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    EFFECT_DIGEST_FIELD_NUMBER: _ClassVar[int]
    REQUIREMENT_SET_HASH_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    SIGNER_KEY_ID_FIELD_NUMBER: _ClassVar[int]
    POLICY_REF_FIELD_NUMBER: _ClassVar[int]
    POLICY_DECISION_HASH_FIELD_NUMBER: _ClassVar[int]
    INPUT_CONTEXT_FIELD_NUMBER: _ClassVar[int]
    id: str
    timestamp: _timestamp_pb2.Timestamp
    verdict: Verdict
    reason: str
    reason_code: ReasonCode
    effect_digest: str
    requirement_set_hash: str
    signature: str
    signer_key_id: str
    policy_ref: str
    policy_decision_hash: str
    input_context: bytes
    def __init__(self, id: _Optional[str] = ..., timestamp: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., verdict: _Optional[_Union[Verdict, str]] = ..., reason: _Optional[str] = ..., reason_code: _Optional[_Union[ReasonCode, str]] = ..., effect_digest: _Optional[str] = ..., requirement_set_hash: _Optional[str] = ..., signature: _Optional[str] = ..., signer_key_id: _Optional[str] = ..., policy_ref: _Optional[str] = ..., policy_decision_hash: _Optional[str] = ..., input_context: _Optional[bytes] = ...) -> None: ...

class AuthorizedExecutionIntent(_message.Message):
    __slots__ = ("intent_id", "decision_id", "effect_id", "issued_at", "expires_at", "signature", "signer_key_id", "principal")
    INTENT_ID_FIELD_NUMBER: _ClassVar[int]
    DECISION_ID_FIELD_NUMBER: _ClassVar[int]
    EFFECT_ID_FIELD_NUMBER: _ClassVar[int]
    ISSUED_AT_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    SIGNER_KEY_ID_FIELD_NUMBER: _ClassVar[int]
    PRINCIPAL_FIELD_NUMBER: _ClassVar[int]
    intent_id: str
    decision_id: str
    effect_id: str
    issued_at: _timestamp_pb2.Timestamp
    expires_at: _timestamp_pb2.Timestamp
    signature: str
    signer_key_id: str
    principal: str
    def __init__(self, intent_id: _Optional[str] = ..., decision_id: _Optional[str] = ..., effect_id: _Optional[str] = ..., issued_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., signature: _Optional[str] = ..., signer_key_id: _Optional[str] = ..., principal: _Optional[str] = ...) -> None: ...

class Receipt(_message.Message):
    __slots__ = ("receipt_version", "receipt_id", "decision_id", "effect_id", "verdict", "principal", "tool", "action", "timestamp", "lamport", "proofgraph_node", "signature", "signer_key_id", "payload_hash", "reason_code", "metadata")
    class MetadataEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    RECEIPT_VERSION_FIELD_NUMBER: _ClassVar[int]
    RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    DECISION_ID_FIELD_NUMBER: _ClassVar[int]
    EFFECT_ID_FIELD_NUMBER: _ClassVar[int]
    VERDICT_FIELD_NUMBER: _ClassVar[int]
    PRINCIPAL_FIELD_NUMBER: _ClassVar[int]
    TOOL_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    LAMPORT_FIELD_NUMBER: _ClassVar[int]
    PROOFGRAPH_NODE_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    SIGNER_KEY_ID_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_HASH_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    receipt_version: str
    receipt_id: str
    decision_id: str
    effect_id: str
    verdict: Verdict
    principal: str
    tool: str
    action: str
    timestamp: _timestamp_pb2.Timestamp
    lamport: int
    proofgraph_node: str
    signature: str
    signer_key_id: str
    payload_hash: str
    reason_code: ReasonCode
    metadata: _containers.ScalarMap[str, str]
    def __init__(self, receipt_version: _Optional[str] = ..., receipt_id: _Optional[str] = ..., decision_id: _Optional[str] = ..., effect_id: _Optional[str] = ..., verdict: _Optional[_Union[Verdict, str]] = ..., principal: _Optional[str] = ..., tool: _Optional[str] = ..., action: _Optional[str] = ..., timestamp: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., lamport: _Optional[int] = ..., proofgraph_node: _Optional[str] = ..., signature: _Optional[str] = ..., signer_key_id: _Optional[str] = ..., payload_hash: _Optional[str] = ..., reason_code: _Optional[_Union[ReasonCode, str]] = ..., metadata: _Optional[_Mapping[str, str]] = ...) -> None: ...

class PDPRequest(_message.Message):
    __slots__ = ("effect", "subject", "context")
    EFFECT_FIELD_NUMBER: _ClassVar[int]
    SUBJECT_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_FIELD_NUMBER: _ClassVar[int]
    effect: Effect
    subject: SubjectDescriptor
    context: ContextDescriptor
    def __init__(self, effect: _Optional[_Union[Effect, _Mapping]] = ..., subject: _Optional[_Union[SubjectDescriptor, _Mapping]] = ..., context: _Optional[_Union[ContextDescriptor, _Mapping]] = ...) -> None: ...

class SubjectDescriptor(_message.Message):
    __slots__ = ("principal", "tenant", "roles")
    PRINCIPAL_FIELD_NUMBER: _ClassVar[int]
    TENANT_FIELD_NUMBER: _ClassVar[int]
    ROLES_FIELD_NUMBER: _ClassVar[int]
    principal: str
    tenant: str
    roles: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, principal: _Optional[str] = ..., tenant: _Optional[str] = ..., roles: _Optional[_Iterable[str]] = ...) -> None: ...

class ContextDescriptor(_message.Message):
    __slots__ = ("jurisdiction", "environment", "time_window_start", "time_window_end")
    JURISDICTION_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_FIELD_NUMBER: _ClassVar[int]
    TIME_WINDOW_START_FIELD_NUMBER: _ClassVar[int]
    TIME_WINDOW_END_FIELD_NUMBER: _ClassVar[int]
    jurisdiction: str
    environment: str
    time_window_start: _timestamp_pb2.Timestamp
    time_window_end: _timestamp_pb2.Timestamp
    def __init__(self, jurisdiction: _Optional[str] = ..., environment: _Optional[str] = ..., time_window_start: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., time_window_end: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class PDPResponse(_message.Message):
    __slots__ = ("allow", "reason_code", "policy_ref", "decision_hash", "obligations")
    ALLOW_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    POLICY_REF_FIELD_NUMBER: _ClassVar[int]
    DECISION_HASH_FIELD_NUMBER: _ClassVar[int]
    OBLIGATIONS_FIELD_NUMBER: _ClassVar[int]
    allow: bool
    reason_code: ReasonCode
    policy_ref: str
    decision_hash: str
    obligations: _containers.RepeatedCompositeFieldContainer[Obligation]
    def __init__(self, allow: bool = ..., reason_code: _Optional[_Union[ReasonCode, str]] = ..., policy_ref: _Optional[str] = ..., decision_hash: _Optional[str] = ..., obligations: _Optional[_Iterable[_Union[Obligation, _Mapping]]] = ...) -> None: ...

class Obligation(_message.Message):
    __slots__ = ("id", "type", "description", "deadline")
    ID_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    DEADLINE_FIELD_NUMBER: _ClassVar[int]
    id: str
    type: str
    description: str
    deadline: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[str] = ..., type: _Optional[str] = ..., description: _Optional[str] = ..., deadline: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class EffectRequest(_message.Message):
    __slots__ = ("effect", "principal", "context")
    class ContextEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    EFFECT_FIELD_NUMBER: _ClassVar[int]
    PRINCIPAL_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_FIELD_NUMBER: _ClassVar[int]
    effect: Effect
    principal: str
    context: _containers.ScalarMap[str, str]
    def __init__(self, effect: _Optional[_Union[Effect, _Mapping]] = ..., principal: _Optional[str] = ..., context: _Optional[_Mapping[str, str]] = ...) -> None: ...

class EffectResponse(_message.Message):
    __slots__ = ("verdict", "reason_code", "reason", "receipt", "intent")
    VERDICT_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    RECEIPT_FIELD_NUMBER: _ClassVar[int]
    INTENT_FIELD_NUMBER: _ClassVar[int]
    verdict: Verdict
    reason_code: ReasonCode
    reason: str
    receipt: Receipt
    intent: AuthorizedExecutionIntent
    def __init__(self, verdict: _Optional[_Union[Verdict, str]] = ..., reason_code: _Optional[_Union[ReasonCode, str]] = ..., reason: _Optional[str] = ..., receipt: _Optional[_Union[Receipt, _Mapping]] = ..., intent: _Optional[_Union[AuthorizedExecutionIntent, _Mapping]] = ...) -> None: ...

class ExecutionResult(_message.Message):
    __slots__ = ("intent_id", "success", "output", "error_message", "completed_at")
    INTENT_ID_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    ERROR_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    COMPLETED_AT_FIELD_NUMBER: _ClassVar[int]
    intent_id: str
    success: bool
    output: bytes
    error_message: str
    completed_at: _timestamp_pb2.Timestamp
    def __init__(self, intent_id: _Optional[str] = ..., success: bool = ..., output: _Optional[bytes] = ..., error_message: _Optional[str] = ..., completed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class CompletionReceipt(_message.Message):
    __slots__ = ("receipt", "proofgraph_node")
    RECEIPT_FIELD_NUMBER: _ClassVar[int]
    PROOFGRAPH_NODE_FIELD_NUMBER: _ClassVar[int]
    receipt: Receipt
    proofgraph_node: str
    def __init__(self, receipt: _Optional[_Union[Receipt, _Mapping]] = ..., proofgraph_node: _Optional[str] = ...) -> None: ...
