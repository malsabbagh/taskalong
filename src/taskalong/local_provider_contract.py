"""Passive contracts for configured adapters; none authorizes a process effect.

Adapters project native inputs and observations. The shared owner retains
admission, claims, capture, cancellation, recovery and independent acceptance.
Legacy HarnessDriver/fixture contracts are deliberately unchanged.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import re
from typing import Any, Literal, Mapping, Protocol, TypedDict

from .errors import TaskAlongError
from .validation import canonical_bytes, loads

SUPPORT_STATES = frozenset({"supported", "unsupported", "unqualified", "unknown"})
CONTEXT_POLICIES = frozenset({"include", "exclude", "native-only"})
STREAMS = frozenset({"stdout", "stderr", "result"})


def _invalid(message: str) -> None:
    raise TaskAlongError("local_provider_contract_invalid", message, exit_code=3)


def _integer(value: Any, minimum: int, maximum: int, name: str) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        _invalid(f"{name} must be an explicit bounded integer.")


def _text(value: Any, name: str, maximum: int = 256) -> None:
    if (type(value) is not str or not value or len(value.encode("utf-8")) > maximum
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        _invalid(f"{name} must be bounded nonempty text.")


@dataclass(frozen=True, slots=True)
class ProviderLimits:
    """Finite local limits, separate from a submission grant or account cap."""

    attempt_seconds: int = 720
    max_output_bytes: int = 4 * 1024 * 1024
    max_protocol_records: int = 8192
    max_record_bytes: int = 1024 * 1024
    max_proposal_bytes: int = 65536
    max_controller_submissions: int = 1

    def __post_init__(self):
        _integer(self.attempt_seconds, 1, 1440, "attempt_seconds")
        _integer(self.max_output_bytes, 1, 64 * 1024 * 1024, "max_output_bytes")
        _integer(self.max_protocol_records, 1, 8192, "max_protocol_records")
        _integer(self.max_record_bytes, 1, min(self.max_output_bytes, 1024 * 1024), "max_record_bytes")
        _integer(self.max_proposal_bytes, 1, 65536, "max_proposal_bytes")
        _integer(self.max_controller_submissions, 1, 1, "max_controller_submissions")

    @classmethod
    def from_dict(cls, value: dict) -> ProviderLimits:
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            _invalid("A complete closed local budget is required.")
        return cls(**value)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PreparedProviderTask:
    """Immutable owner-supplied JSON, not a bearer token or proof of admission.

    Read/write snapshots remain distinct. Copies returned to an adapter cannot
    mutate the owner's binding. Source truth and dispatch authority are checked
    by the owner, never inferred from construction of this value.
    """

    payload_json: bytes

    def __post_init__(self):
        if type(self.payload_json) is not bytes:
            _invalid("Prepared task storage must be immutable canonical bytes.")
        value = loads(self.payload_json)
        required = {"provider", "backend", "run_id", "attempt_id", "operation_key",
                    "request_digest", "configuration_digest", "read_context", "writable_outputs",
                    "workspace", "control_root", "prompt_file", "result_file", "absolute_deadline",
                    "remaining_budget", "context_policy", "requested_model", "requested_effort"}
        if type(value) is not dict or set(value) != required or canonical_bytes(value) != self.payload_json:
            _invalid("The prepared task must use the closed canonical owner contract.")
        for key in ("provider", "run_id", "attempt_id", "operation_key", "requested_model"):
            _text(value[key], key)
        for key in ("backend", "requested_effort"):
            if value[key] is not None:
                _text(value[key], key)
        for key in ("request_digest", "configuration_digest"):
            if type(value[key]) is not str or not re.fullmatch(r"[a-f0-9]{64}", value[key]):
                _invalid("Prepared task digests must be exact SHA256 values.")
        if type(value["read_context"]) is not dict or type(value["writable_outputs"]) is not dict or not value["writable_outputs"]:
            _invalid("Read-only context and nonempty writable outputs must be separate maps.")
        for key in ("workspace", "control_root", "prompt_file", "result_file"):
            if key == "result_file" and value[key] is None:
                continue
            _text(value[key], key, 4096)
            if not Path(value[key]).is_absolute() or ".." in Path(value[key]).parts:
                _invalid("Owned process locations must be literal absolute paths.")
        _integer(value["absolute_deadline"], 1, 2**63 - 1, "absolute_deadline")
        ProviderLimits.from_dict(value["remaining_budget"])
        if type(value["context_policy"]) is not str or value["context_policy"] not in CONTEXT_POLICIES:
            _invalid("An explicit supported context-policy name is required.")

    @classmethod
    def from_dict(cls, value: dict) -> PreparedProviderTask:
        return cls(canonical_bytes(value))

    def to_dict(self) -> dict:
        return loads(self.payload_json)


class PrivateCaptureSink(Protocol):
    """Owned bounded sink; callbacks neither grant authority nor settle usage."""

    def write(self, stream: Literal["stdout", "stderr", "result"], chunk: bytes) -> None: ...

    def observe(self, event: Mapping[str, Any]) -> None: ...


class ProviderObservation(TypedDict):
    """Native report only; the owner adds all process/effect observations."""

    provider: str
    backend: str | None
    session_id: str | None
    turn_id: str | None
    requested_model: str
    reported_model: str | None
    requested_effort: str | None
    effective_effort: str | None
    terminal_status: Literal["completed", "failed", "cancelled", "incomplete", "unknown"]
    structured_result: dict | None
    reported_usage: dict
    tool_denials: list[dict]
    protocol_errors: list[str]
    diagnostics: dict


class ProviderDecoder(Protocol):
    """Return normalized data; the owner independently validates the proposal."""

    def feed(self, stream: Literal["stdout", "stderr", "result"], chunk: bytes) -> None: ...

    def finish(self, exit_code: int | None) -> ProviderObservation: ...


class ConfiguredProviderAdapter(Protocol):
    """Pure adapter surface. Existing Codex execution stays in CodexCLI.run.

    No method here launches, retries, applies changes, resolves credentials or
    writes State. Shared owner admission chooses the closed execution driver.
    """

    provider_id: str

    def validate_configuration(self, value: dict, *, runtime_observation: dict | None = None) -> dict: ...

    def capabilities(self, configuration: dict) -> dict: ...

    def build_invocation(self, configuration: dict, prepared: Mapping[str, Any]) -> dict: ...

    def new_decoder(self, binding: Mapping[str, Any], limits: ProviderLimits) -> ProviderDecoder: ...
