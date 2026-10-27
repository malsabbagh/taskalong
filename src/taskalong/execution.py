"""Explicit single-step v2-family documents; construction performs no effects.

Version 2.2 is additive. The original 1.0, 2.0 and 2.1 readers and resource
identities keep their shipped meanings. Portable documents are not authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, TYPE_CHECKING

from .contracts import JsonDocument, TaskSpec
from .errors import TaskAlongError
from .validation import canonical_bytes, loads, seal, seal_versioned, validate_versioned
if TYPE_CHECKING:
    from .trial import TrialTaskSpec


@dataclass(frozen=True, slots=True)
class ExecutionDocument(JsonDocument):
    def __post_init__(self):
        admitted = validate_versioned(self.schema_name, loads(self._canonical), expected_version="2.2")
        object.__setattr__(self, "_canonical", canonical_bytes(admitted))


@dataclass(frozen=True, slots=True)
class TaskSpecV2(ExecutionDocument):
    schema_name: ClassVar[str] = "task-spec"


@dataclass(frozen=True, slots=True)
class InstructionBundle(ExecutionDocument):
    schema_name: ClassVar[str] = "instruction-bundle"


@dataclass(frozen=True, slots=True)
class ToolPolicy(ExecutionDocument):
    schema_name: ClassVar[str] = "tool-policy"


@dataclass(frozen=True, slots=True)
class SandboxPolicy(ExecutionDocument):
    schema_name: ClassVar[str] = "sandbox-policy"


@dataclass(frozen=True, slots=True)
class CheckBinding(ExecutionDocument):
    schema_name: ClassVar[str] = "check-binding"


@dataclass(frozen=True, slots=True)
class WorkerPacketV2(ExecutionDocument):
    schema_name: ClassVar[str] = "worker-packet"


@dataclass(frozen=True, slots=True)
class ExecutionEvidence(ExecutionDocument):
    schema_name: ClassVar[str] = "evidence"


@dataclass(frozen=True, slots=True)
class DriverDocument(JsonDocument):
    """Explicit 2.3 family; legacy 2.2 documents retain their own reader."""
    def __post_init__(self):
        admitted = validate_versioned(self.schema_name, loads(self._canonical), expected_version="2.3")
        object.__setattr__(self, "_canonical", canonical_bytes(admitted))


@dataclass(frozen=True, slots=True)
class DriverTaskSpec(DriverDocument):
    schema_name: ClassVar[str] = "task-spec"


@dataclass(frozen=True, slots=True)
class OllamaDocument(JsonDocument):
    """Explicit 2.4 fixture family; never widens a shipped version reader."""
    def __post_init__(self):
        admitted = validate_versioned(self.schema_name, loads(self._canonical), expected_version="2.4")
        object.__setattr__(self, "_canonical", canonical_bytes(admitted))


@dataclass(frozen=True, slots=True)
class OllamaTaskSpec(OllamaDocument):
    schema_name: ClassVar[str] = "task-spec"


@dataclass(frozen=True, slots=True)
class CursorDocument(JsonDocument):
    """Explicit 2.5 fixture data; its syntax grants no execution authority."""
    def __post_init__(self):
        admitted = validate_versioned(self.schema_name, loads(self._canonical), expected_version="2.5")
        object.__setattr__(self, "_canonical", canonical_bytes(admitted))


@dataclass(frozen=True, slots=True)
class CursorTaskSpec(CursorDocument):
    schema_name: ClassVar[str] = "task-spec"


@dataclass(frozen=True, slots=True)
class AntigravityDocument(JsonDocument):
    """Explicit 2.6 original fixture documents; no vendor execution authority."""
    def __post_init__(self):
        admitted = validate_versioned(self.schema_name, loads(self._canonical), expected_version="2.6")
        object.__setattr__(self, "_canonical", canonical_bytes(admitted))


@dataclass(frozen=True, slots=True)
class AntigravityTaskSpec(AntigravityDocument):
    schema_name: ClassVar[str] = "task-spec"


def project_packet(packet, admission):
    """Freeze canonical packet, then exact wire bytes, then their mapping.

    This compiler is reached only after trusted synthetic projection admission.
    Neither worker fields nor a wire extension can register or qualify a route.
    """
    canonical = seal_versioned("worker-packet", packet | {"schema_version": "2.2",
        "binding_digest": admission["binding"]["digest"], "admission_digest": admission["digest"],
        "projection": "codex-v1-fixture/1"}, version="2.2")
    wire = seal("worker-packet", packet | {"extensions": packet["extensions"] | {
        "taskalong:canonical_packet_digest": canonical["digest"], "taskalong:admission_digest": admission["digest"]}})
    mapping = seal_versioned("packet-projection", {"run_id": packet["run_id"], "attempt_id": packet["attempt_id"],
        "spec_digest": packet["spec_digest"], "canonical_packet_digest": canonical["digest"],
        "wire_packet_digest": wire["digest"], "admission_digest": admission["digest"],
        "projection_digest": admission["projection"]["digest"], "projection": "codex-v1-fixture/1"}, version="2.2")
    return canonical, wire, mapping


@dataclass(frozen=True, slots=True)
class PolicyResolver:
    """Bounded operator-supplied exact content, never discovery or latest-ID lookup.

    The caller must select this snapshot through the trusted local control plane.
    Accepting a document here proves its syntax/identity, not its enforcement.
    """
    documents: tuple[ExecutionDocument, ...]

    def __post_init__(self):
        if type(self.documents) is not tuple or len(self.documents) > 64:
            raise TaskAlongError("policy_unresolved", "A bounded immutable policy snapshot is required.")
        allowed = (InstructionBundle, ToolPolicy, SandboxPolicy, CheckBinding)
        if any(type(item) not in allowed for item in self.documents):
            raise TaskAlongError("policy_unresolved", "The policy snapshot contains an unsupported document.")
        # Revalidate every value at the trust boundary and reject ambiguous inputs.
        values = tuple(type(item)(item.to_bytes()) for item in self.documents)
        if len({item.digest for item in values}) != len(values):
            raise TaskAlongError("policy_unresolved", "The policy snapshot contains duplicate identities.")
        object.__setattr__(self, "documents", values)

    def resolve(self, content_digest: str, kind):
        for document in self.documents:
            if type(document) is kind and document.digest == content_digest:
                return document
        raise TaskAlongError("policy_unresolved", "The exact policy content and type are unavailable.", exit_code=3)


def read_task_spec(document: dict) -> TaskSpec | TaskSpecV2 | DriverTaskSpec | OllamaTaskSpec | CursorTaskSpec | AntigravityTaskSpec | TrialTaskSpec:
    """Select only an explicit version; never upgrade or rewrite legacy bytes."""
    if document.get("schema_version") == "1.0":
        return TaskSpec.from_dict(document)
    if document.get("schema_version") == "2.2":
        return TaskSpecV2.from_dict(document)
    if document.get("schema_version") == "2.3":
        return DriverTaskSpec.from_dict(document)
    if document.get("schema_version") == "2.4":
        return OllamaTaskSpec.from_dict(document)
    if document.get("schema_version") == "2.5":
        return CursorTaskSpec.from_dict(document)
    if document.get("schema_version") == "2.6":
        return AntigravityTaskSpec.from_dict(document)
    if document.get("schema_version") == "2.10":
        from .artifact_handoff import ArtifactTaskSpec
        return ArtifactTaskSpec.from_dict(document)
    if document.get("schema_version") == "2.7":
        from .steps import OrderedTaskSpec
        return OrderedTaskSpec.from_dict(document)
    if document.get("schema_version") == "2.9":
        from .muse_handoff import MuseTaskSpec
        return MuseTaskSpec.from_dict(document)
    if document.get("schema_version") == "2.8":
        from .trial import TrialTaskSpec
        return TrialTaskSpec.from_dict(document)
    raise TaskAlongError("unknown_schema_version", "The task specification version is unsupported.")
