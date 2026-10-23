"""The provider-neutral executor protocol; no acceptance or publication powers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Literal, Protocol


@dataclass(frozen=True, slots=True)
class ExecutorCapabilities:
    structured_result: bool = True
    native_resume: bool = True
    local_group_cancel: bool = True
    provider_start_lookup: bool = False
    interactive_approval: bool = False
    hard_cost_cap: bool = False
    hard_token_cap: bool = False


@dataclass(frozen=True, slots=True)
class ExecutionHandle:
    adapter: str
    version: str
    invocation_id: str


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    """References to validated documents; no worker authority is admitted here."""

    run_id: str
    attempt_id: str
    spec_digest: str
    packet: bytes
    workspace: Path
    output_dir: Path
    lease_generation: int
    profile_digest: str
    authority_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ExecutionLookup:
    handle: ExecutionHandle | None = None
    operation_key: str | None = None


@dataclass(frozen=True, slots=True)
class ResumeRequest:
    request: ExecutionRequest
    thread_id: str
    checkpoint_digest: str
    mode: Literal["native", "restart"] = "native"


@dataclass(frozen=True, slots=True)
class ExecutionObservation:
    state: Literal["prepared", "starting", "running", "completed", "failed", "cancel_pending", "cancelled", "unknown"]
    observed_at: str
    handle: ExecutionHandle | None = None
    result_ref: str | None = None
    checkpoint_ref: str | None = None
    error_code: str | None = None
    usage_json: bytes = b'{"input_tokens":null,"output_tokens":null,"cost_usd":null}'


@dataclass(frozen=True, slots=True)
class OperationResult:
    operation_key: str
    request_digest: str
    disposition: Literal["accepted", "rejected", "unsupported", "unknown"]
    observation: ExecutionObservation
    handle: ExecutionHandle | None = None


class AgentExecutor(Protocol):
    def capabilities(self) -> ExecutorCapabilities: ...
    def start(self, request: ExecutionRequest, *, operation_key: str) -> OperationResult: ...
    def status(self, lookup: ExecutionLookup) -> ExecutionObservation: ...
    def cancel(self, handle: ExecutionHandle, *, operation_key: str) -> OperationResult: ...
    def resume(self, request: ResumeRequest, *, operation_key: str) -> OperationResult: ...


class HarnessDriver(Protocol):
    """Internal v1 driver used after durable intent and authority admission.

    This is not a second public lifecycle API. The core owns process effects,
    attempt identity, persistence and acceptance; command checks have their own
    sandbox seam. Concrete drivers retain bounded protocol/process handling.
    """
    def preflight(self, *, qualification: str, budget: dict) -> None: ...

    def run(self, packet: dict, *, workspace: str | Path, output_dir: str | Path,
            git_common_dir: str | Path | None = None, control_dir: str | Path | None = None,
            cancel_requested: Callable[[], bool] | None = None,
            heartbeat: Callable[[], None] | None = None,
            on_spawn: Callable | None = None, mode: str = "start", thread_id: str | None = None) -> dict: ...

    def doctor(self, *, workspace: str | Path | None = None,
               git_common_dir: str | Path | None = None, control_dir: str | Path | None = None) -> dict: ...
