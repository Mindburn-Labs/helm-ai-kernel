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
    __slots__ = ("id", "timestamp", "verdict", "reason", "reason_code", "effect_digest", "requirement_set_hash", "signature", "signer_key_id", "policy_ref", "policy_decision_hash", "input_context", "subject_id", "action", "resource", "signature_schema", "signature_type", "proposal_id", "step_id", "phenotype_hash", "policy_version", "policy_backend", "policy_content_hash", "policy_epoch", "state_cursor", "snapshot", "env_fingerprint", "reason_code_text", "trajectory_risk_score", "session_centroid_hash", "risk_accumulation_window", "intervention", "tenant_id", "workspace_id", "session_id")
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
    SUBJECT_ID_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_SCHEMA_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_TYPE_FIELD_NUMBER: _ClassVar[int]
    PROPOSAL_ID_FIELD_NUMBER: _ClassVar[int]
    STEP_ID_FIELD_NUMBER: _ClassVar[int]
    PHENOTYPE_HASH_FIELD_NUMBER: _ClassVar[int]
    POLICY_VERSION_FIELD_NUMBER: _ClassVar[int]
    POLICY_BACKEND_FIELD_NUMBER: _ClassVar[int]
    POLICY_CONTENT_HASH_FIELD_NUMBER: _ClassVar[int]
    POLICY_EPOCH_FIELD_NUMBER: _ClassVar[int]
    STATE_CURSOR_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ENV_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_TEXT_FIELD_NUMBER: _ClassVar[int]
    TRAJECTORY_RISK_SCORE_FIELD_NUMBER: _ClassVar[int]
    SESSION_CENTROID_HASH_FIELD_NUMBER: _ClassVar[int]
    RISK_ACCUMULATION_WINDOW_FIELD_NUMBER: _ClassVar[int]
    INTERVENTION_FIELD_NUMBER: _ClassVar[int]
    TENANT_ID_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
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
    subject_id: str
    action: str
    resource: str
    signature_schema: str
    signature_type: str
    proposal_id: str
    step_id: str
    phenotype_hash: str
    policy_version: str
    policy_backend: str
    policy_content_hash: str
    policy_epoch: str
    state_cursor: str
    snapshot: str
    env_fingerprint: str
    reason_code_text: str
    trajectory_risk_score: float
    session_centroid_hash: str
    risk_accumulation_window: int
    intervention: DecisionInterventionMetadata
    tenant_id: str
    workspace_id: str
    session_id: str
    def __init__(self, id: _Optional[str] = ..., timestamp: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., verdict: _Optional[_Union[Verdict, str]] = ..., reason: _Optional[str] = ..., reason_code: _Optional[_Union[ReasonCode, str]] = ..., effect_digest: _Optional[str] = ..., requirement_set_hash: _Optional[str] = ..., signature: _Optional[str] = ..., signer_key_id: _Optional[str] = ..., policy_ref: _Optional[str] = ..., policy_decision_hash: _Optional[str] = ..., input_context: _Optional[bytes] = ..., subject_id: _Optional[str] = ..., action: _Optional[str] = ..., resource: _Optional[str] = ..., signature_schema: _Optional[str] = ..., signature_type: _Optional[str] = ..., proposal_id: _Optional[str] = ..., step_id: _Optional[str] = ..., phenotype_hash: _Optional[str] = ..., policy_version: _Optional[str] = ..., policy_backend: _Optional[str] = ..., policy_content_hash: _Optional[str] = ..., policy_epoch: _Optional[str] = ..., state_cursor: _Optional[str] = ..., snapshot: _Optional[str] = ..., env_fingerprint: _Optional[str] = ..., reason_code_text: _Optional[str] = ..., trajectory_risk_score: _Optional[float] = ..., session_centroid_hash: _Optional[str] = ..., risk_accumulation_window: _Optional[int] = ..., intervention: _Optional[_Union[DecisionInterventionMetadata, _Mapping]] = ..., tenant_id: _Optional[str] = ..., workspace_id: _Optional[str] = ..., session_id: _Optional[str] = ...) -> None: ...

class AuthorizedExecutionIntent(_message.Message):
    __slots__ = ("intent_id", "decision_id", "effect_id", "issued_at", "expires_at", "signature", "signer_key_id", "principal", "effect_digest_hash", "idempotency_key", "signer", "signature_schema", "signature_type", "allowed_tool", "taint", "emergency_activation_id", "emergency_delegation_session_id", "emergency_scope_hash")
    INTENT_ID_FIELD_NUMBER: _ClassVar[int]
    DECISION_ID_FIELD_NUMBER: _ClassVar[int]
    EFFECT_ID_FIELD_NUMBER: _ClassVar[int]
    ISSUED_AT_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    SIGNER_KEY_ID_FIELD_NUMBER: _ClassVar[int]
    PRINCIPAL_FIELD_NUMBER: _ClassVar[int]
    EFFECT_DIGEST_HASH_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    SIGNER_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_SCHEMA_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_TYPE_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_TOOL_FIELD_NUMBER: _ClassVar[int]
    TAINT_FIELD_NUMBER: _ClassVar[int]
    EMERGENCY_ACTIVATION_ID_FIELD_NUMBER: _ClassVar[int]
    EMERGENCY_DELEGATION_SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    EMERGENCY_SCOPE_HASH_FIELD_NUMBER: _ClassVar[int]
    intent_id: str
    decision_id: str
    effect_id: str
    issued_at: _timestamp_pb2.Timestamp
    expires_at: _timestamp_pb2.Timestamp
    signature: str
    signer_key_id: str
    principal: str
    effect_digest_hash: str
    idempotency_key: str
    signer: str
    signature_schema: str
    signature_type: str
    allowed_tool: str
    taint: _containers.RepeatedScalarFieldContainer[str]
    emergency_activation_id: str
    emergency_delegation_session_id: str
    emergency_scope_hash: str
    def __init__(self, intent_id: _Optional[str] = ..., decision_id: _Optional[str] = ..., effect_id: _Optional[str] = ..., issued_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., signature: _Optional[str] = ..., signer_key_id: _Optional[str] = ..., principal: _Optional[str] = ..., effect_digest_hash: _Optional[str] = ..., idempotency_key: _Optional[str] = ..., signer: _Optional[str] = ..., signature_schema: _Optional[str] = ..., signature_type: _Optional[str] = ..., allowed_tool: _Optional[str] = ..., taint: _Optional[_Iterable[str]] = ..., emergency_activation_id: _Optional[str] = ..., emergency_delegation_session_id: _Optional[str] = ..., emergency_scope_hash: _Optional[str] = ...) -> None: ...

class Receipt(_message.Message):
    __slots__ = ("receipt_version", "receipt_id", "decision_id", "effect_id", "verdict", "principal", "tool", "action", "timestamp", "lamport", "proofgraph_node", "signature", "signer_key_id", "payload_hash", "reason_code", "metadata", "signature_schema", "signature_profile", "signature_algorithm", "key_id", "public_key_set", "external_reference_id", "status", "blob_hash", "output_hash", "prev_hash", "lamport_clock", "args_hash", "executor_id", "effect_type", "tool_fingerprint", "idempotency_key", "tool_name", "reason_code_text", "policy_hash", "session_id", "scope_hash", "issued_at", "emergency_activation_id", "emergency_delegation_session_id", "emergency_scope_hash", "safe_dep_state", "safe_dep_reason_code", "network_log_ref", "secret_events_ref", "sandbox_lease_id", "effect_graph_node_id", "port_exposures_json", "replay_script_json", "provenance_json", "bundled_artifacts_json", "transparency_json", "log_id", "leaf_index")
    class MetadataEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    class PublicKeySetEntry(_message.Message):
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
    SIGNATURE_SCHEMA_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_PROFILE_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_ALGORITHM_FIELD_NUMBER: _ClassVar[int]
    KEY_ID_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEY_SET_FIELD_NUMBER: _ClassVar[int]
    EXTERNAL_REFERENCE_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    BLOB_HASH_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_HASH_FIELD_NUMBER: _ClassVar[int]
    PREV_HASH_FIELD_NUMBER: _ClassVar[int]
    LAMPORT_CLOCK_FIELD_NUMBER: _ClassVar[int]
    ARGS_HASH_FIELD_NUMBER: _ClassVar[int]
    EXECUTOR_ID_FIELD_NUMBER: _ClassVar[int]
    EFFECT_TYPE_FIELD_NUMBER: _ClassVar[int]
    TOOL_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    TOOL_NAME_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_TEXT_FIELD_NUMBER: _ClassVar[int]
    POLICY_HASH_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    SCOPE_HASH_FIELD_NUMBER: _ClassVar[int]
    ISSUED_AT_FIELD_NUMBER: _ClassVar[int]
    EMERGENCY_ACTIVATION_ID_FIELD_NUMBER: _ClassVar[int]
    EMERGENCY_DELEGATION_SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    EMERGENCY_SCOPE_HASH_FIELD_NUMBER: _ClassVar[int]
    SAFE_DEP_STATE_FIELD_NUMBER: _ClassVar[int]
    SAFE_DEP_REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    NETWORK_LOG_REF_FIELD_NUMBER: _ClassVar[int]
    SECRET_EVENTS_REF_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_LEASE_ID_FIELD_NUMBER: _ClassVar[int]
    EFFECT_GRAPH_NODE_ID_FIELD_NUMBER: _ClassVar[int]
    PORT_EXPOSURES_JSON_FIELD_NUMBER: _ClassVar[int]
    REPLAY_SCRIPT_JSON_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_JSON_FIELD_NUMBER: _ClassVar[int]
    BUNDLED_ARTIFACTS_JSON_FIELD_NUMBER: _ClassVar[int]
    TRANSPARENCY_JSON_FIELD_NUMBER: _ClassVar[int]
    LOG_ID_FIELD_NUMBER: _ClassVar[int]
    LEAF_INDEX_FIELD_NUMBER: _ClassVar[int]
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
    signature_schema: str
    signature_profile: str
    signature_algorithm: str
    key_id: str
    public_key_set: _containers.ScalarMap[str, str]
    external_reference_id: str
    status: str
    blob_hash: str
    output_hash: str
    prev_hash: str
    lamport_clock: int
    args_hash: str
    executor_id: str
    effect_type: str
    tool_fingerprint: str
    idempotency_key: str
    tool_name: str
    reason_code_text: str
    policy_hash: str
    session_id: str
    scope_hash: str
    issued_at: _timestamp_pb2.Timestamp
    emergency_activation_id: str
    emergency_delegation_session_id: str
    emergency_scope_hash: str
    safe_dep_state: str
    safe_dep_reason_code: str
    network_log_ref: str
    secret_events_ref: str
    sandbox_lease_id: str
    effect_graph_node_id: str
    port_exposures_json: bytes
    replay_script_json: bytes
    provenance_json: bytes
    bundled_artifacts_json: bytes
    transparency_json: bytes
    log_id: str
    leaf_index: int
    def __init__(self, receipt_version: _Optional[str] = ..., receipt_id: _Optional[str] = ..., decision_id: _Optional[str] = ..., effect_id: _Optional[str] = ..., verdict: _Optional[_Union[Verdict, str]] = ..., principal: _Optional[str] = ..., tool: _Optional[str] = ..., action: _Optional[str] = ..., timestamp: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., lamport: _Optional[int] = ..., proofgraph_node: _Optional[str] = ..., signature: _Optional[str] = ..., signer_key_id: _Optional[str] = ..., payload_hash: _Optional[str] = ..., reason_code: _Optional[_Union[ReasonCode, str]] = ..., metadata: _Optional[_Mapping[str, str]] = ..., signature_schema: _Optional[str] = ..., signature_profile: _Optional[str] = ..., signature_algorithm: _Optional[str] = ..., key_id: _Optional[str] = ..., public_key_set: _Optional[_Mapping[str, str]] = ..., external_reference_id: _Optional[str] = ..., status: _Optional[str] = ..., blob_hash: _Optional[str] = ..., output_hash: _Optional[str] = ..., prev_hash: _Optional[str] = ..., lamport_clock: _Optional[int] = ..., args_hash: _Optional[str] = ..., executor_id: _Optional[str] = ..., effect_type: _Optional[str] = ..., tool_fingerprint: _Optional[str] = ..., idempotency_key: _Optional[str] = ..., tool_name: _Optional[str] = ..., reason_code_text: _Optional[str] = ..., policy_hash: _Optional[str] = ..., session_id: _Optional[str] = ..., scope_hash: _Optional[str] = ..., issued_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., emergency_activation_id: _Optional[str] = ..., emergency_delegation_session_id: _Optional[str] = ..., emergency_scope_hash: _Optional[str] = ..., safe_dep_state: _Optional[str] = ..., safe_dep_reason_code: _Optional[str] = ..., network_log_ref: _Optional[str] = ..., secret_events_ref: _Optional[str] = ..., sandbox_lease_id: _Optional[str] = ..., effect_graph_node_id: _Optional[str] = ..., port_exposures_json: _Optional[bytes] = ..., replay_script_json: _Optional[bytes] = ..., provenance_json: _Optional[bytes] = ..., bundled_artifacts_json: _Optional[bytes] = ..., transparency_json: _Optional[bytes] = ..., log_id: _Optional[str] = ..., leaf_index: _Optional[int] = ...) -> None: ...

class DecisionInterventionMetadata(_message.Message):
    __slots__ = ("type", "reason_code", "wait_duration_nanos", "tokens_saved")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    WAIT_DURATION_NANOS_FIELD_NUMBER: _ClassVar[int]
    TOKENS_SAVED_FIELD_NUMBER: _ClassVar[int]
    type: str
    reason_code: str
    wait_duration_nanos: int
    tokens_saved: int
    def __init__(self, type: _Optional[str] = ..., reason_code: _Optional[str] = ..., wait_duration_nanos: _Optional[int] = ..., tokens_saved: _Optional[int] = ...) -> None: ...

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
