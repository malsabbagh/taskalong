"""Explicit Mac foreground experiments; never production cessation evidence."""
from __future__ import annotations

import dataclasses
from pathlib import Path
import sys
from typing import Callable, Mapping, Sequence

from .process import ProcessBoundaryError, ProcessReceipt, run_bounded

FOREGROUND_EXPERIMENT = "darwin-foreground-experiment/1"


@dataclasses.dataclass(frozen=True)
class ForegroundExperimentResult:
    root_exit_code: int | None
    root_exit_observed: bool
    group_termination_confirmed: bool
    fork_observed: bool
    tracking_errors: tuple[str, ...]
    stdout: bytes
    stderr: bytes
    timed_out: bool
    cancelled: bool
    output_limited: bool
    receipt: ProcessReceipt
    duration_ms: int
    output_bytes: int
    lifetime_backend: str
    protocol_error: str | None
    failure_code: str | None
    boundary_failures: tuple[tuple[str, int | None], ...]
    effect_outcome: str
    mode: str = dataclasses.field(default=FOREGROUND_EXPERIMENT, init=False)
    descendant_cessation: str = dataclasses.field(default="unknown", init=False)
    termination_confirmed: bool = dataclasses.field(default=False, init=False)
    production_dispatch_allowed: bool = dataclasses.field(default=False, init=False)
    workspace_reuse_allowed: bool = dataclasses.field(default=False, init=False)
    acceptance_allowed: bool = dataclasses.field(default=False, init=False)

    def to_dict(self) -> dict:
        value = dataclasses.asdict(self)
        value["stdout"] = self.stdout.decode("utf-8", "replace")
        value["stderr"] = self.stderr.decode("utf-8", "replace")
        return value


def run_foreground_experiment(
    argv: Sequence[str], *, mode: str, cwd: str | Path, stdin: bytes = b"",
    timeout_seconds: int | float = 30, max_output_bytes: int = 65536,
    env: Mapping[str, str] | None = None,
    cancel_requested: Callable[[], bool] | None = None,
    heartbeat: Callable[[], None] | None = None,
    on_spawn: Callable[[ProcessReceipt], None] | None = None,
    on_stdout_line: Callable[[bytes], None] | None = None,
    secrets: Sequence[str | bytes] = (), signal_grace_seconds: float = .5,
) -> ForegroundExperimentResult:
    """Run once through the existing gate, bounds, cancellation and group owner.

    Selecting this mode acknowledges weaker observation; it grants no provider,
    data, credential or spending authority. This is not an executor registration
    or RunService handoff. Even a clean non-forking observation remains an
    experimental result with no acceptance or workspace-reuse permission.

    No process-list reconstruction, daemon, saved-PID signal or retry is added.
    A root that exits before group cleanup can lose owned signal authority;
    report that group's actual state instead of claiming it was stopped.
    """
    if type(mode) is not str or mode != FOREGROUND_EXPERIMENT or sys.platform != "darwin":
        raise ProcessBoundaryError("explicit Darwin foreground experiment mode is required",
                                   code="foreground_experiment_unsupported", effect_outcome="not_sent")
    observations = {}
    failure_code = None
    boundary_failures = ()
    effect_outcome = "uncertain"
    try:
        result = run_bounded(argv, cwd=cwd, stdin=stdin, timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes, env=env, cancel_requested=cancel_requested,
            heartbeat=heartbeat, on_spawn=on_spawn, on_stdout_line=on_stdout_line,
            secrets=secrets, signal_grace_seconds=signal_grace_seconds,
            _lifetime_observations=observations)
    except ProcessBoundaryError as error:
        if error.process_result is None:
            raise
        result = error.process_result
        failure_code = error.code
        boundary_failures = error.boundary_failures
        effect_outcome = error.effect_outcome
    return ForegroundExperimentResult(
        result.exit_code, result.exit_code is not None, result.group_termination_confirmed,
        observations.get("fork_observed", False), observations.get("tracking_errors", ()),
        result.stdout, result.stderr, result.timed_out, result.cancelled, result.output_limited,
        result.receipt, result.duration_ms, result.output_bytes, result.lifetime_backend,
        result.protocol_error, failure_code, boundary_failures, effect_outcome)
