import datetime

from google.protobuf import struct_pb2 as _struct_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Verdict(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    VERDICT_UNSPECIFIED: _ClassVar[Verdict]
    VERDICT_ALLOW: _ClassVar[Verdict]
    VERDICT_DENY: _ClassVar[Verdict]
    VERDICT_ESCALATE: _ClassVar[Verdict]

class Protocol(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PROTOCOL_UNSPECIFIED: _ClassVar[Protocol]
    PROTOCOL_MCP: _ClassVar[Protocol]
    PROTOCOL_A2A: _ClassVar[Protocol]
    PROTOCOL_HTTP: _ClassVar[Protocol]
    PROTOCOL_GRPC: _ClassVar[Protocol]
    PROTOCOL_OPENAI: _ClassVar[Protocol]
VERDICT_UNSPECIFIED: Verdict
VERDICT_ALLOW: Verdict
VERDICT_DENY: Verdict
VERDICT_ESCALATE: Verdict
PROTOCOL_UNSPECIFIED: Protocol
PROTOCOL_MCP: Protocol
PROTOCOL_A2A: Protocol
PROTOCOL_HTTP: Protocol
PROTOCOL_GRPC: Protocol
PROTOCOL_OPENAI: Protocol

class AuthorizationRequest(_message.Message):
    __slots__ = ("schema_version", "contract_version", "request_id", "tenant_id", "workspace_id", "principal_id", "principal_seq", "agent_identity_profile_ref", "protocol", "action_urn", "tool_urn", "connector_id", "connector_contract_hash", "executor_kind", "effect_class", "risk_class", "args_c14n_hash", "request_body_hash", "plan_hash", "policy_hash", "p0_hash", "policy_epoch", "idempotency_key_candidate", "payload_class", "redaction_profile", "upstream_trace_id", "upstream_run_id", "deadline_ms", "risk_context", "risk_context_hash")
    SCHEMA_VERSION_FIELD_NUMBER: _ClassVar[int]
    CONTRACT_VERSION_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    TENANT_ID_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_ID_FIELD_NUMBER: _ClassVar[int]
    PRINCIPAL_ID_FIELD_NUMBER: _ClassVar[int]
    PRINCIPAL_SEQ_FIELD_NUMBER: _ClassVar[int]
    AGENT_IDENTITY_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    ACTION_URN_FIELD_NUMBER: _ClassVar[int]
    TOOL_URN_FIELD_NUMBER: _ClassVar[int]
    CONNECTOR_ID_FIELD_NUMBER: _ClassVar[int]
    CONNECTOR_CONTRACT_HASH_FIELD_NUMBER: _ClassVar[int]
    EXECUTOR_KIND_FIELD_NUMBER: _ClassVar[int]
    EFFECT_CLASS_FIELD_NUMBER: _ClassVar[int]
    RISK_CLASS_FIELD_NUMBER: _ClassVar[int]
    ARGS_C14N_HASH_FIELD_NUMBER: _ClassVar[int]
    REQUEST_BODY_HASH_FIELD_NUMBER: _ClassVar[int]
    PLAN_HASH_FIELD_NUMBER: _ClassVar[int]
    POLICY_HASH_FIELD_NUMBER: _ClassVar[int]
    P0_HASH_FIELD_NUMBER: _ClassVar[int]
    POLICY_EPOCH_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_CANDIDATE_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_CLASS_FIELD_NUMBER: _ClassVar[int]
    REDACTION_PROFILE_FIELD_NUMBER: _ClassVar[int]
    UPSTREAM_TRACE_ID_FIELD_NUMBER: _ClassVar[int]
    UPSTREAM_RUN_ID_FIELD_NUMBER: _ClassVar[int]
    DEADLINE_MS_FIELD_NUMBER: _ClassVar[int]
    RISK_CONTEXT_FIELD_NUMBER: _ClassVar[int]
    RISK_CONTEXT_HASH_FIELD_NUMBER: _ClassVar[int]
    schema_version: str
    contract_version: str
    request_id: str
    tenant_id: str
    workspace_id: str
    principal_id: str
    principal_seq: int
    agent_identity_profile_ref: str
    protocol: Protocol
    action_urn: str
    tool_urn: str
    connector_id: str
    connector_contract_hash: str
    executor_kind: str
    effect_class: str
    risk_class: str
    args_c14n_hash: str
    request_body_hash: str
    plan_hash: str
    policy_hash: str
    p0_hash: str
    policy_epoch: str
    idempotency_key_candidate: str
    payload_class: str
    redaction_profile: str
    upstream_trace_id: str
    upstream_run_id: str
    deadline_ms: int
    risk_context: _struct_pb2.Struct
    risk_context_hash: str
    def __init__(self, schema_version: _Optional[str] = ..., contract_version: _Optional[str] = ..., request_id: _Optional[str] = ..., tenant_id: _Optional[str] = ..., workspace_id: _Optional[str] = ..., principal_id: _Optional[str] = ..., principal_seq: _Optional[int] = ..., agent_identity_profile_ref: _Optional[str] = ..., protocol: _Optional[_Union[Protocol, str]] = ..., action_urn: _Optional[str] = ..., tool_urn: _Optional[str] = ..., connector_id: _Optional[str] = ..., connector_contract_hash: _Optional[str] = ..., executor_kind: _Optional[str] = ..., effect_class: _Optional[str] = ..., risk_class: _Optional[str] = ..., args_c14n_hash: _Optional[str] = ..., request_body_hash: _Optional[str] = ..., plan_hash: _Optional[str] = ..., policy_hash: _Optional[str] = ..., p0_hash: _Optional[str] = ..., policy_epoch: _Optional[str] = ..., idempotency_key_candidate: _Optional[str] = ..., payload_class: _Optional[str] = ..., redaction_profile: _Optional[str] = ..., upstream_trace_id: _Optional[str] = ..., upstream_run_id: _Optional[str] = ..., deadline_ms: _Optional[int] = ..., risk_context: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., risk_context_hash: _Optional[str] = ...) -> None: ...

class AuthorizationResponse(_message.Message):
    __slots__ = ("schema_version", "contract_version", "request_id", "tenant_id", "workspace_id", "principal_id", "principal_seq", "agent_identity_profile_ref", "protocol", "action_urn", "tool_urn", "connector_id", "connector_contract_hash", "executor_kind", "effect_class", "risk_class", "args_c14n_hash", "request_body_hash", "plan_hash", "policy_hash", "p0_hash", "policy_epoch", "idempotency_key_candidate", "payload_class", "redaction_profile", "upstream_trace_id", "upstream_run_id", "deadline_ms", "risk_context_hash", "verdict", "reason_code", "kernel_trust_root_id", "signing_key_ref", "kernel_verdict_ref", "kernel_verdict_hash", "kernel_verdict_signature", "kernel_verdict_issued_at", "kernel_verdict_expires_at", "effect_permit_ref", "permit_nonce", "permit_expiry", "proof_session_ref", "evidence_reservation_ref", "budget_reservation_ref", "cache_policy", "replay_hint", "denial_receipt_ref", "escalation_ref", "escalation_receipt_ref", "proof_obligation", "connector_receipt_policy", "proof_finalization_policy")
    SCHEMA_VERSION_FIELD_NUMBER: _ClassVar[int]
    CONTRACT_VERSION_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    TENANT_ID_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_ID_FIELD_NUMBER: _ClassVar[int]
    PRINCIPAL_ID_FIELD_NUMBER: _ClassVar[int]
    PRINCIPAL_SEQ_FIELD_NUMBER: _ClassVar[int]
    AGENT_IDENTITY_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    ACTION_URN_FIELD_NUMBER: _ClassVar[int]
    TOOL_URN_FIELD_NUMBER: _ClassVar[int]
    CONNECTOR_ID_FIELD_NUMBER: _ClassVar[int]
    CONNECTOR_CONTRACT_HASH_FIELD_NUMBER: _ClassVar[int]
    EXECUTOR_KIND_FIELD_NUMBER: _ClassVar[int]
    EFFECT_CLASS_FIELD_NUMBER: _ClassVar[int]
    RISK_CLASS_FIELD_NUMBER: _ClassVar[int]
    ARGS_C14N_HASH_FIELD_NUMBER: _ClassVar[int]
    REQUEST_BODY_HASH_FIELD_NUMBER: _ClassVar[int]
    PLAN_HASH_FIELD_NUMBER: _ClassVar[int]
    POLICY_HASH_FIELD_NUMBER: _ClassVar[int]
    P0_HASH_FIELD_NUMBER: _ClassVar[int]
    POLICY_EPOCH_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_CANDIDATE_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_CLASS_FIELD_NUMBER: _ClassVar[int]
    REDACTION_PROFILE_FIELD_NUMBER: _ClassVar[int]
    UPSTREAM_TRACE_ID_FIELD_NUMBER: _ClassVar[int]
    UPSTREAM_RUN_ID_FIELD_NUMBER: _ClassVar[int]
    DEADLINE_MS_FIELD_NUMBER: _ClassVar[int]
    RISK_CONTEXT_HASH_FIELD_NUMBER: _ClassVar[int]
    VERDICT_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    KERNEL_TRUST_ROOT_ID_FIELD_NUMBER: _ClassVar[int]
    SIGNING_KEY_REF_FIELD_NUMBER: _ClassVar[int]
    KERNEL_VERDICT_REF_FIELD_NUMBER: _ClassVar[int]
    KERNEL_VERDICT_HASH_FIELD_NUMBER: _ClassVar[int]
    KERNEL_VERDICT_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    KERNEL_VERDICT_ISSUED_AT_FIELD_NUMBER: _ClassVar[int]
    KERNEL_VERDICT_EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    EFFECT_PERMIT_REF_FIELD_NUMBER: _ClassVar[int]
    PERMIT_NONCE_FIELD_NUMBER: _ClassVar[int]
    PERMIT_EXPIRY_FIELD_NUMBER: _ClassVar[int]
    PROOF_SESSION_REF_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_RESERVATION_REF_FIELD_NUMBER: _ClassVar[int]
    BUDGET_RESERVATION_REF_FIELD_NUMBER: _ClassVar[int]
    CACHE_POLICY_FIELD_NUMBER: _ClassVar[int]
    REPLAY_HINT_FIELD_NUMBER: _ClassVar[int]
    DENIAL_RECEIPT_REF_FIELD_NUMBER: _ClassVar[int]
    ESCALATION_REF_FIELD_NUMBER: _ClassVar[int]
    ESCALATION_RECEIPT_REF_FIELD_NUMBER: _ClassVar[int]
    PROOF_OBLIGATION_FIELD_NUMBER: _ClassVar[int]
    CONNECTOR_RECEIPT_POLICY_FIELD_NUMBER: _ClassVar[int]
    PROOF_FINALIZATION_POLICY_FIELD_NUMBER: _ClassVar[int]
    schema_version: str
    contract_version: str
    request_id: str
    tenant_id: str
    workspace_id: str
    principal_id: str
    principal_seq: int
    agent_identity_profile_ref: str
    protocol: Protocol
    action_urn: str
    tool_urn: str
    connector_id: str
    connector_contract_hash: str
    executor_kind: str
    effect_class: str
    risk_class: str
    args_c14n_hash: str
    request_body_hash: str
    plan_hash: str
    policy_hash: str
    p0_hash: str
    policy_epoch: str
    idempotency_key_candidate: str
    payload_class: str
    redaction_profile: str
    upstream_trace_id: str
    upstream_run_id: str
    deadline_ms: int
    risk_context_hash: str
    verdict: Verdict
    reason_code: str
    kernel_trust_root_id: str
    signing_key_ref: str
    kernel_verdict_ref: str
    kernel_verdict_hash: str
    kernel_verdict_signature: bytes
    kernel_verdict_issued_at: _timestamp_pb2.Timestamp
    kernel_verdict_expires_at: _timestamp_pb2.Timestamp
    effect_permit_ref: str
    permit_nonce: str
    permit_expiry: _timestamp_pb2.Timestamp
    proof_session_ref: str
    evidence_reservation_ref: str
    budget_reservation_ref: str
    cache_policy: str
    replay_hint: str
    denial_receipt_ref: str
    escalation_ref: str
    escalation_receipt_ref: str
    proof_obligation: str
    connector_receipt_policy: str
    proof_finalization_policy: str
    def __init__(self, schema_version: _Optional[str] = ..., contract_version: _Optional[str] = ..., request_id: _Optional[str] = ..., tenant_id: _Optional[str] = ..., workspace_id: _Optional[str] = ..., principal_id: _Optional[str] = ..., principal_seq: _Optional[int] = ..., agent_identity_profile_ref: _Optional[str] = ..., protocol: _Optional[_Union[Protocol, str]] = ..., action_urn: _Optional[str] = ..., tool_urn: _Optional[str] = ..., connector_id: _Optional[str] = ..., connector_contract_hash: _Optional[str] = ..., executor_kind: _Optional[str] = ..., effect_class: _Optional[str] = ..., risk_class: _Optional[str] = ..., args_c14n_hash: _Optional[str] = ..., request_body_hash: _Optional[str] = ..., plan_hash: _Optional[str] = ..., policy_hash: _Optional[str] = ..., p0_hash: _Optional[str] = ..., policy_epoch: _Optional[str] = ..., idempotency_key_candidate: _Optional[str] = ..., payload_class: _Optional[str] = ..., redaction_profile: _Optional[str] = ..., upstream_trace_id: _Optional[str] = ..., upstream_run_id: _Optional[str] = ..., deadline_ms: _Optional[int] = ..., risk_context_hash: _Optional[str] = ..., verdict: _Optional[_Union[Verdict, str]] = ..., reason_code: _Optional[str] = ..., kernel_trust_root_id: _Optional[str] = ..., signing_key_ref: _Optional[str] = ..., kernel_verdict_ref: _Optional[str] = ..., kernel_verdict_hash: _Optional[str] = ..., kernel_verdict_signature: _Optional[bytes] = ..., kernel_verdict_issued_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., kernel_verdict_expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., effect_permit_ref: _Optional[str] = ..., permit_nonce: _Optional[str] = ..., permit_expiry: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., proof_session_ref: _Optional[str] = ..., evidence_reservation_ref: _Optional[str] = ..., budget_reservation_ref: _Optional[str] = ..., cache_policy: _Optional[str] = ..., replay_hint: _Optional[str] = ..., denial_receipt_ref: _Optional[str] = ..., escalation_ref: _Optional[str] = ..., escalation_receipt_ref: _Optional[str] = ..., proof_obligation: _Optional[str] = ..., connector_receipt_policy: _Optional[str] = ..., proof_finalization_policy: _Optional[str] = ...) -> None: ...
