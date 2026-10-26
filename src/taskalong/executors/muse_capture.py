"""Private Muse plain-output preparation through the existing owned supervisor.

Unregistered and synthetic-only. This is not a HarnessDriver: plain text cannot
provide the immutable structured worker result required by Workflow acceptance.
No new authority, lifecycle, native continuation or provider lookup is supplied.
"""
from dataclasses import asdict, dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
from uuid import UUID

from ..errors import TaskAlongError
from ..process import ProcessBoundaryError, ProcessResult, fingerprint, minimal_environment, run_bounded
from ..validation import canonical_bytes, loads
from .base import ExecutionRequest, ExecutorCapabilities
from .muse_protocol import project_plain_exec_argv


@dataclass(frozen=True)
class MuseCaptureConfig:
    executable: str
    executable_sha256: str
    build: str
    requested_model: str
    permission_profile: str
    max_model_steps: int


@dataclass(frozen=True)
class MuseCaptureResult:
    directory: Path
    receipt_json: bytes
    process: ProcessResult | None
    original: tuple[bytes, bytes] | None
    error: str | None
    status: str

    def observation(self):
        """Return private metadata, never worker text or acceptance authority."""
        return loads(self.receipt_json)


def capabilities():
    return ExecutorCapabilities(structured_result=False, native_resume=False,
                                provider_start_lookup=False)


def _refuse(code):
    raise TaskAlongError(code, "The offline Muse capture prerequisites were not satisfied.",
                         exit_code=3, effect_outcome="not_sent")


def _sha(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _save(directory, name, value):
    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def _sync(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _prompt_unchanged(path, expected):
    """Bounded check without following a replacement symlink or blocking FIFO."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            observed = os.fstat(stream.fileno())
            return (stat.S_ISREG(observed.st_mode) and observed.st_size == len(expected)
                    and stream.read(len(expected) + 1) == expected)
    except OSError:
        return False


def capture_muse_turn(request, *, config, qualification, timeout_seconds, max_output_bytes,
                      cancel_requested=None, heartbeat=None, on_spawn=None, mode="start", thread_id=None):
    """Retain one bounded synthetic invocation; an existing directory forbids replay.

    The caller's durable core still owns start keys, authority, attempts and
    reconciliation. An intent without a receipt remains uncertain, not retryable.
    This helper neither reads existing captures nor starts a second invocation.
    """
    if qualification != "synthetic":
        _refuse("runtime_policy_unsupported")
    if mode != "start" or thread_id is not None:
        _refuse("muse_native_resume_unsupported")
    if not isinstance(request, ExecutionRequest) or not isinstance(config, MuseCaptureConfig):
        _refuse("muse_capture_input_invalid")
    if (type(request.packet) is not bytes or not 1 <= len(request.packet) <= 1048576
            or not _sha(request.spec_digest) or not _sha(request.profile_digest)
            or not _sha(config.executable_sha256)
            or type(request.lease_generation) is not int or not 1 <= request.lease_generation <= 2**63 - 1
            or not isinstance(request.output_dir, (str, Path))
            or not isinstance(request.workspace, (str, Path))):
        _refuse("muse_capture_input_invalid")
    try:
        request.packet.decode("utf-8", "strict")
        if any(type(value) is not str or str(UUID(value)) != value for value in (request.run_id, request.attempt_id)):
            _refuse("muse_capture_input_invalid")
    except (UnicodeError, ValueError, AttributeError):
        _refuse("muse_capture_input_invalid")
    if (type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 60
            or type(max_output_bytes) is not int or not 1 <= max_output_bytes <= 1048576
            or any(value is not None and not callable(value) for value in (cancel_requested, heartbeat, on_spawn))):
        _refuse("muse_capture_limits_invalid")
    output = Path(request.output_dir)
    directory = output / "muse-raw"
    argv = project_plain_exec_argv(executable=config.executable, build=config.build,
        workspace=str(request.workspace), prompt_file=str(directory / "prompt.txt"),
        model=config.requested_model, permission_profile=config.permission_profile,
        max_model_steps=config.max_model_steps)
    try:
        workspace = Path(request.workspace)
        if (not output.is_absolute() or output.resolve(strict=True) != output
                or not output.is_dir() or output.stat().st_mode & 0o077
                or workspace.resolve(strict=True) != workspace or not workspace.is_dir()
                or output.is_relative_to(workspace) or workspace.is_relative_to(output)):
            _refuse("muse_capture_path_unsafe")
        if fingerprint(config.executable) != config.executable_sha256:
            _refuse("muse_executable_changed")
    except (OSError, ProcessBoundaryError):
        _refuse("muse_runtime_unavailable")
    binding = {"run_id": request.run_id, "attempt_id": request.attempt_id,
        "spec_digest": request.spec_digest, "profile_digest": request.profile_digest,
        "lease_generation": request.lease_generation,
        "prompt_sha256": hashlib.sha256(request.packet).hexdigest(),
        "configuration_sha256": hashlib.sha256(canonical_bytes(asdict(config))).hexdigest(),
        "argv_sha256": hashlib.sha256(canonical_bytes(list(argv))).hexdigest(),
        "executable_sha256": config.executable_sha256}
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        _refuse("muse_capture_exists")
    except OSError:
        _refuse("muse_capture_path_unsafe")
    try:
        _save(directory, "intent.json", canonical_bytes({"binding": binding, "requested": asdict(config)}))
        _save(directory, "input.bin", request.packet)
        _save(directory, "prompt.txt", request.packet)
        _sync(directory)
        _sync(output)
    except OSError:
        _refuse("muse_capture_write_failed")

    def recheck_inputs():
        try:
            actual = fingerprint(config.executable)
        except (OSError, ProcessBoundaryError):
            _refuse("muse_runtime_unavailable")
        if actual != config.executable_sha256:
            _refuse("muse_executable_changed")
        if not _prompt_unchanged(directory / "prompt.txt", request.packet):
            _refuse("muse_prompt_changed")

    def spawned(receipt):
        if receipt.executable_sha256 != config.executable_sha256:
            _refuse("muse_executable_changed")
        recheck_inputs()
        try:
            _save(directory, "spawn.json", canonical_bytes({"binding": binding, "process_receipt": receipt.to_dict()}))
            _sync(directory)
        except OSError:
            _refuse("muse_capture_write_failed")
        if on_spawn is not None:
            on_spawn(receipt.to_dict())
        # A trusted persistence/admission callback can still change local state.
        # Recheck before the existing owned gate is allowed to release target.
        recheck_inputs()

    original = None
    def capture_original(stdout, stderr):
        nonlocal original
        original = (stdout, stderr)

    process, primary_error, boundary_outcome, failures = None, None, None, ()
    try:
        process = run_bounded(argv, cwd=request.workspace, timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes, env=minimal_environment(), on_spawn=spawned,
            cancel_requested=cancel_requested, heartbeat=heartbeat,
            _capture_private_output=capture_original)
    except ProcessBoundaryError as error:
        process, primary_error = error.process_result, error.code
        boundary_outcome, failures = error.effect_outcome, error.boundary_failures
    except OSError:
        # An unstructured supervisor exception can happen after gate release.
        # Only its explicit boundary proof may establish not_sent.
        primary_error, boundary_outcome = "muse_supervisor_error", "uncertain"

    summary = process.to_dict() if process is not None else None
    if summary is not None:
        summary.pop("stdout")
        summary.pop("stderr")
    confirmed = (process is not None and process.termination_confirmed is True
                 and process.group_termination_confirmed is True and process.unaccounted_descendants is False)
    prompt_unchanged = _prompt_unchanged(directory / "prompt.txt", request.packet)
    status, error = "failed", primary_error
    if process is None:
        status = "not_sent" if boundary_outcome == "not_sent" else "unknown"
    elif not confirmed:
        status, error = "unknown", primary_error or "muse_termination_unconfirmed"
    elif primary_error:
        status = "not_sent" if boundary_outcome == "not_sent" else "failed"
    elif not prompt_unchanged:
        error = "muse_prompt_changed"
    elif original is None:
        error = "muse_capture_missing"
    elif process.protocol_error:
        error = process.protocol_error
    elif process.output_limited:
        error = "muse_output_limit"
    elif process.timed_out:
        error = "muse_timeout"
    elif process.cancelled:
        status, error = "cancelled_local", "muse_cancelled_local"
    elif process.exit_code != 0:
        error = "muse_nonzero_exit"
    else:
        status = "local_turn_completed"
    receipt = {"kind": "muse_private_raw_capture", "version": 1, "binding": binding,
        "requested": asdict(config), "status": status, "error": error,
        "boundary_effect_outcome": boundary_outcome, "boundary_failures": list(failures),
        "owned_cessation_confirmed": confirmed, "prompt_unchanged_at_return": prompt_unchanged,
        "process": summary, "captures": None, "observed_model": None, "observed_session": None,
        "usage": {"input_tokens": None, "output_tokens": None, "cost_usd": None},
        "structured_result": None, "independently_accepted": False,
        "production_dispatch_allowed": False, "remote_cessation_proven": False}
    try:
        if original is not None:
            receipt["captures"] = {}
            for name, raw in zip(("stdout", "stderr"), original):
                _save(directory, name + ".bin", raw)
                receipt["captures"][name] = {"file": name + ".bin", "bytes": len(raw),
                                            "sha256": hashlib.sha256(raw).hexdigest()}
        raw_receipt = canonical_bytes(receipt)
        _save(directory, "receipt.json", raw_receipt)
        _sync(directory)
    except OSError:
        raise TaskAlongError("muse_capture_not_durable", "Inspect the preserved private capture before any further action.",
            exit_code=5, effect_outcome="not_sent" if status == "not_sent" else "uncertain",
            recovery=[{"action": "inspect_capture", "primary_error": error}]) from None
    return MuseCaptureResult(directory, raw_receipt, process, original, error, status)
