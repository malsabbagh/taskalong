"""Frozen public documents over the strict v1 JSON boundary.

The encoded representation is immutable even for nested objects and arrays.
Callers receive independent dictionaries, never references to mutable state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Self

from .validation import canonical_bytes, loads, validate


@dataclass(frozen=True, slots=True)
class JsonDocument:
    _canonical: bytes
    schema_name: ClassVar[str]

    def __post_init__(self) -> None:
        admitted = validate(self.schema_name, loads(self._canonical))
        object.__setattr__(self, "_canonical", canonical_bytes(admitted))

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> Self:
        return cls(canonical_bytes(document))

    def to_dict(self) -> dict[str, Any]:
        return loads(self._canonical)

    def to_bytes(self) -> bytes:
        return self._canonical

    @property
    def digest(self) -> str | None:
        return self.to_dict().get("digest")


@dataclass(frozen=True, slots=True)
class TaskSpec(JsonDocument):
    schema_name: ClassVar[str] = "task-spec"


@dataclass(frozen=True, slots=True)
class TaskRun(JsonDocument):
    schema_name: ClassVar[str] = "task-run"


@dataclass(frozen=True, slots=True)
class RunEvent(JsonDocument):
    schema_name: ClassVar[str] = "run-event"


@dataclass(frozen=True, slots=True)
class RuntimeProfile(JsonDocument):
    schema_name: ClassVar[str] = "runtime-profile"


@dataclass(frozen=True, slots=True)
class WorkerPacket(JsonDocument):
    schema_name: ClassVar[str] = "worker-packet"


@dataclass(frozen=True, slots=True)
class WorkerResult(JsonDocument):
    schema_name: ClassVar[str] = "worker-result"


@dataclass(frozen=True, slots=True)
class ExecutionObservation(JsonDocument):
    schema_name: ClassVar[str] = "execution-observation"


@dataclass(frozen=True, slots=True)
class Evidence(JsonDocument):
    schema_name: ClassVar[str] = "evidence"


@dataclass(frozen=True, slots=True)
class Acceptance(JsonDocument):
    schema_name: ClassVar[str] = "acceptance"


@dataclass(frozen=True, slots=True)
class AuthorityRecord(JsonDocument):
    schema_name: ClassVar[str] = "authority"


@dataclass(frozen=True, slots=True)
class EffectIntent(JsonDocument):
    schema_name: ClassVar[str] = "effect-intent"


@dataclass(frozen=True, slots=True)
class CommandResult(JsonDocument):
    schema_name: ClassVar[str] = "command-result"
