import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class InterventionReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INTERVENTION_REASON_UNSPECIFIED: _ClassVar[InterventionReason]
    INTERVENTION_REASON_POLICY_DENY: _ClassVar[InterventionReason]
    INTERVENTION_REASON_APPROVAL_NEEDED: _ClassVar[InterventionReason]
    INTERVENTION_REASON_EVIDENCE_GAP: _ClassVar[InterventionReason]
    INTERVENTION_REASON_RISK_THRESHOLD: _ClassVar[InterventionReason]
    INTERVENTION_REASON_MANUAL_TRIGGER: _ClassVar[InterventionReason]
    INTERVENTION_REASON_BUDGET_EXCEEDED: _ClassVar[InterventionReason]

class InterventionState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INTERVENTION_STATE_UNSPECIFIED: _ClassVar[InterventionState]
    INTERVENTION_STATE_PENDING: _ClassVar[InterventionState]
    INTERVENTION_STATE_ACTIVE: _ClassVar[InterventionState]
    INTERVENTION_STATE_RESOLVED: _ClassVar[InterventionState]
    INTERVENTION_STATE_EXPIRED: _ClassVar[InterventionState]
    INTERVENTION_STATE_CANCELED: _ClassVar[InterventionState]

class InterventionDecision(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INTERVENTION_DECISION_UNSPECIFIED: _ClassVar[InterventionDecision]
    INTERVENTION_DECISION_APPROVE: _ClassVar[InterventionDecision]
    INTERVENTION_DECISION_DENY: _ClassVar[InterventionDecision]
    INTERVENTION_DECISION_MODIFY: _ClassVar[InterventionDecision]
    INTERVENTION_DECISION_ESCALATE: _ClassVar[InterventionDecision]
    INTERVENTION_DECISION_CANCEL: _ClassVar[InterventionDecision]
INTERVENTION_REASON_UNSPECIFIED: InterventionReason
INTERVENTION_REASON_POLICY_DENY: InterventionReason
INTERVENTION_REASON_APPROVAL_NEEDED: InterventionReason
INTERVENTION_REASON_EVIDENCE_GAP: InterventionReason
INTERVENTION_REASON_RISK_THRESHOLD: InterventionReason
INTERVENTION_REASON_MANUAL_TRIGGER: InterventionReason
INTERVENTION_REASON_BUDGET_EXCEEDED: InterventionReason
INTERVENTION_STATE_UNSPECIFIED: InterventionState
INTERVENTION_STATE_PENDING: InterventionState
INTERVENTION_STATE_ACTIVE: InterventionState
INTERVENTION_STATE_RESOLVED: InterventionState
INTERVENTION_STATE_EXPIRED: InterventionState
INTERVENTION_STATE_CANCELED: InterventionState
INTERVENTION_DECISION_UNSPECIFIED: InterventionDecision
INTERVENTION_DECISION_APPROVE: InterventionDecision
INTERVENTION_DECISION_DENY: InterventionDecision
INTERVENTION_DECISION_MODIFY: InterventionDecision
INTERVENTION_DECISION_ESCALATE: InterventionDecision
INTERVENTION_DECISION_CANCEL: InterventionDecision

class InterventionScope(_message.Message):
    __slots__ = ("target_resources", "target_actions", "max_budget", "jurisdiction")
    TARGET_RESOURCES_FIELD_NUMBER: _ClassVar[int]
    TARGET_ACTIONS_FIELD_NUMBER: _ClassVar[int]
    MAX_BUDGET_FIELD_NUMBER: _ClassVar[int]
    JURISDICTION_FIELD_NUMBER: _ClassVar[int]
    target_resources: _containers.RepeatedScalarFieldContainer[str]
    target_actions: _containers.RepeatedScalarFieldContainer[str]
    max_budget: float
    jurisdiction: str
    def __init__(self, target_resources: _Optional[_Iterable[str]] = ..., target_actions: _Optional[_Iterable[str]] = ..., max_budget: _Optional[float] = ..., jurisdiction: _Optional[str] = ...) -> None: ...

class InterventionOption(_message.Message):
    __slots__ = ("option_id", "label", "description", "type")
    OPTION_ID_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    option_id: str
    label: str
    description: str
    type: str
    def __init__(self, option_id: _Optional[str] = ..., label: _Optional[str] = ..., description: _Optional[str] = ..., type: _Optional[str] = ...) -> None: ...

class InterventionObject(_message.Message):
    __slots__ = ("intervention_id", "execution_id", "principal_id", "reason", "state", "description", "effect_types", "policy_epoch", "scope", "options", "created_at", "expires_at", "content_hash")
    INTERVENTION_ID_FIELD_NUMBER: _ClassVar[int]
    EXECUTION_ID_FIELD_NUMBER: _ClassVar[int]
    PRINCIPAL_ID_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    EFFECT_TYPES_FIELD_NUMBER: _ClassVar[int]
    POLICY_EPOCH_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    OPTIONS_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    CONTENT_HASH_FIELD_NUMBER: _ClassVar[int]
    intervention_id: str
    execution_id: str
    principal_id: str
    reason: InterventionReason
    state: InterventionState
    description: str
    effect_types: _containers.RepeatedScalarFieldContainer[str]
    policy_epoch: str
    scope: InterventionScope
    options: _containers.RepeatedCompositeFieldContainer[InterventionOption]
    created_at: _timestamp_pb2.Timestamp
    expires_at: _timestamp_pb2.Timestamp
    content_hash: str
    def __init__(self, intervention_id: _Optional[str] = ..., execution_id: _Optional[str] = ..., principal_id: _Optional[str] = ..., reason: _Optional[_Union[InterventionReason, str]] = ..., state: _Optional[_Union[InterventionState, str]] = ..., description: _Optional[str] = ..., effect_types: _Optional[_Iterable[str]] = ..., policy_epoch: _Optional[str] = ..., scope: _Optional[_Union[InterventionScope, _Mapping]] = ..., options: _Optional[_Iterable[_Union[InterventionOption, _Mapping]]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., content_hash: _Optional[str] = ...) -> None: ...

class InterventionReceipt(_message.Message):
    __slots__ = ("receipt_id", "intervention_id", "decider_id", "decider_type", "decision", "selected_option", "rationale", "conditions", "policy_epoch", "issued_at", "signature", "signer_public_key", "content_hash")
    RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    INTERVENTION_ID_FIELD_NUMBER: _ClassVar[int]
    DECIDER_ID_FIELD_NUMBER: _ClassVar[int]
    DECIDER_TYPE_FIELD_NUMBER: _ClassVar[int]
    DECISION_FIELD_NUMBER: _ClassVar[int]
    SELECTED_OPTION_FIELD_NUMBER: _ClassVar[int]
    RATIONALE_FIELD_NUMBER: _ClassVar[int]
    CONDITIONS_FIELD_NUMBER: _ClassVar[int]
    POLICY_EPOCH_FIELD_NUMBER: _ClassVar[int]
    ISSUED_AT_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    SIGNER_PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    CONTENT_HASH_FIELD_NUMBER: _ClassVar[int]
    receipt_id: str
    intervention_id: str
    decider_id: str
    decider_type: str
    decision: InterventionDecision
    selected_option: str
    rationale: str
    conditions: _containers.RepeatedScalarFieldContainer[str]
    policy_epoch: str
    issued_at: _timestamp_pb2.Timestamp
    signature: str
    signer_public_key: str
    content_hash: str
    def __init__(self, receipt_id: _Optional[str] = ..., intervention_id: _Optional[str] = ..., decider_id: _Optional[str] = ..., decider_type: _Optional[str] = ..., decision: _Optional[_Union[InterventionDecision, str]] = ..., selected_option: _Optional[str] = ..., rationale: _Optional[str] = ..., conditions: _Optional[_Iterable[str]] = ..., policy_epoch: _Optional[str] = ..., issued_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., signature: _Optional[str] = ..., signer_public_key: _Optional[str] = ..., content_hash: _Optional[str] = ...) -> None: ...
