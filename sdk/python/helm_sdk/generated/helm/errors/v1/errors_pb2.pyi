from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class ErrorDetail(_message.Message):
    __slots__ = ("reason_code", "retryable")
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    RETRYABLE_FIELD_NUMBER: _ClassVar[int]
    reason_code: str
    retryable: bool
    def __init__(self, reason_code: _Optional[str] = ..., retryable: bool = ...) -> None: ...
