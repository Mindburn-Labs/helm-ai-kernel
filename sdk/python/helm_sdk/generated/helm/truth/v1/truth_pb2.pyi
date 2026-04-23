import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class TruthType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TRUTH_TYPE_UNSPECIFIED: _ClassVar[TruthType]
    TRUTH_TYPE_POLICY: _ClassVar[TruthType]
    TRUTH_TYPE_SCHEMA: _ClassVar[TruthType]
    TRUTH_TYPE_REGULATION: _ClassVar[TruthType]
    TRUTH_TYPE_ORG_GENOME: _ClassVar[TruthType]
    TRUTH_TYPE_PACK_ABI: _ClassVar[TruthType]
    TRUTH_TYPE_ATTESTATION: _ClassVar[TruthType]
TRUTH_TYPE_UNSPECIFIED: TruthType
TRUTH_TYPE_POLICY: TruthType
TRUTH_TYPE_SCHEMA: TruthType
TRUTH_TYPE_REGULATION: TruthType
TRUTH_TYPE_ORG_GENOME: TruthType
TRUTH_TYPE_PACK_ABI: TruthType
TRUTH_TYPE_ATTESTATION: TruthType

class VersionScope(_message.Message):
    __slots__ = ("major", "minor", "patch", "epoch", "label")
    MAJOR_FIELD_NUMBER: _ClassVar[int]
    MINOR_FIELD_NUMBER: _ClassVar[int]
    PATCH_FIELD_NUMBER: _ClassVar[int]
    EPOCH_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    major: int
    minor: int
    patch: int
    epoch: str
    label: str
    def __init__(self, major: _Optional[int] = ..., minor: _Optional[int] = ..., patch: _Optional[int] = ..., epoch: _Optional[str] = ..., label: _Optional[str] = ...) -> None: ...

class FreshnessInfo(_message.Message):
    __slots__ = ("last_validated", "valid_until", "stale")
    LAST_VALIDATED_FIELD_NUMBER: _ClassVar[int]
    VALID_UNTIL_FIELD_NUMBER: _ClassVar[int]
    STALE_FIELD_NUMBER: _ClassVar[int]
    last_validated: _timestamp_pb2.Timestamp
    valid_until: _timestamp_pb2.Timestamp
    stale: bool
    def __init__(self, last_validated: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., valid_until: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., stale: bool = ...) -> None: ...

class CompatibilityInfo(_message.Message):
    __slots__ = ("breaking_change", "deprecated_since", "replaced_by", "compatible_with")
    BREAKING_CHANGE_FIELD_NUMBER: _ClassVar[int]
    DEPRECATED_SINCE_FIELD_NUMBER: _ClassVar[int]
    REPLACED_BY_FIELD_NUMBER: _ClassVar[int]
    COMPATIBLE_WITH_FIELD_NUMBER: _ClassVar[int]
    breaking_change: bool
    deprecated_since: str
    replaced_by: str
    compatible_with: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, breaking_change: bool = ..., deprecated_since: _Optional[str] = ..., replaced_by: _Optional[str] = ..., compatible_with: _Optional[_Iterable[str]] = ...) -> None: ...

class ProvenanceInfo(_message.Message):
    __slots__ = ("author_id", "source_ref", "tool")
    AUTHOR_ID_FIELD_NUMBER: _ClassVar[int]
    SOURCE_REF_FIELD_NUMBER: _ClassVar[int]
    TOOL_FIELD_NUMBER: _ClassVar[int]
    author_id: str
    source_ref: str
    tool: str
    def __init__(self, author_id: _Optional[str] = ..., source_ref: _Optional[str] = ..., tool: _Optional[str] = ...) -> None: ...

class TruthObject(_message.Message):
    __slots__ = ("object_id", "type", "name", "version", "content", "content_hash", "freshness", "compatibility", "provenance", "registered_at", "signature")
    OBJECT_ID_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    CONTENT_HASH_FIELD_NUMBER: _ClassVar[int]
    FRESHNESS_FIELD_NUMBER: _ClassVar[int]
    COMPATIBILITY_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    REGISTERED_AT_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    object_id: str
    type: TruthType
    name: str
    version: VersionScope
    content: bytes
    content_hash: str
    freshness: FreshnessInfo
    compatibility: CompatibilityInfo
    provenance: ProvenanceInfo
    registered_at: _timestamp_pb2.Timestamp
    signature: str
    def __init__(self, object_id: _Optional[str] = ..., type: _Optional[_Union[TruthType, str]] = ..., name: _Optional[str] = ..., version: _Optional[_Union[VersionScope, _Mapping]] = ..., content: _Optional[bytes] = ..., content_hash: _Optional[str] = ..., freshness: _Optional[_Union[FreshnessInfo, _Mapping]] = ..., compatibility: _Optional[_Union[CompatibilityInfo, _Mapping]] = ..., provenance: _Optional[_Union[ProvenanceInfo, _Mapping]] = ..., registered_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., signature: _Optional[str] = ...) -> None: ...

class LineageEntry(_message.Message):
    __slots__ = ("entry_id", "object_id", "parent_id", "relation", "annotation", "recorded_at", "recorded_by")
    ENTRY_ID_FIELD_NUMBER: _ClassVar[int]
    OBJECT_ID_FIELD_NUMBER: _ClassVar[int]
    PARENT_ID_FIELD_NUMBER: _ClassVar[int]
    RELATION_FIELD_NUMBER: _ClassVar[int]
    ANNOTATION_FIELD_NUMBER: _ClassVar[int]
    RECORDED_AT_FIELD_NUMBER: _ClassVar[int]
    RECORDED_BY_FIELD_NUMBER: _ClassVar[int]
    entry_id: str
    object_id: str
    parent_id: str
    relation: str
    annotation: str
    recorded_at: _timestamp_pb2.Timestamp
    recorded_by: str
    def __init__(self, entry_id: _Optional[str] = ..., object_id: _Optional[str] = ..., parent_id: _Optional[str] = ..., relation: _Optional[str] = ..., annotation: _Optional[str] = ..., recorded_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., recorded_by: _Optional[str] = ...) -> None: ...

class GetTruthRequest(_message.Message):
    __slots__ = ("object_id",)
    OBJECT_ID_FIELD_NUMBER: _ClassVar[int]
    object_id: str
    def __init__(self, object_id: _Optional[str] = ...) -> None: ...

class GetLatestTruthRequest(_message.Message):
    __slots__ = ("type", "name")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    type: TruthType
    name: str
    def __init__(self, type: _Optional[_Union[TruthType, str]] = ..., name: _Optional[str] = ...) -> None: ...
