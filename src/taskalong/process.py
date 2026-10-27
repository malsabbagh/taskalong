"""Bounded POSIX subprocesses. Persisted PIDs are observations, never kill authority."""

from __future__ import annotations

import dataclasses
from contextlib import contextmanager
import threading
import hashlib
import json
import os
from pathlib import Path
import re
import select
import selectors
import signal
import subprocess
import time
import sys
from typing import Callable, Mapping, Sequence
import uuid


class ProcessBoundaryError(RuntimeError):
    """An invocation was invalid or a boundary callback failed."""
    def __init__(self, message: str, *, code: str = "process_boundary_failed",
                 effect_outcome: str = "uncertain", process_result: ProcessResult | None = None,
                 boundary_failures: tuple[tuple[str, int | None], ...] = ()):
        super().__init__(message)
        self.code = code
        self.effect_outcome = effect_outcome
        self.process_result = process_result
        self.boundary_failures = boundary_failures


class _DescendantTracker:
    """Kernel process identities, registered before the target may execute.

    XNU exposes NOTE_FORK without child identities and rejects NOTE_TRACK. Any
    fork therefore quarantines the invocation; a process-list snapshot cannot
    prove that all descendants exited. This conservative slice supports only
    non-forking command lifetimes on Darwin.
    """
    def __init__(self, pid: int):
        self.queue = None
        self.active = {pid}
        self.failed = False
        self.fork_observed = False
        self.tracking_errors = []
        self.backend = "unsupported"
        self.root_exit_code = None
        self.root_pgid = None
        if sys.platform == "darwin" and hasattr(select, "kqueue"):
            try:
                self.queue = select.kqueue()
                event = select.kevent(pid, filter=select.KQ_FILTER_PROC,
                    flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR,
                    fflags=select.KQ_NOTE_EXIT | select.KQ_NOTE_FORK)
                self.queue.control([event], 0, 0)
                self.backend = "darwin-kqueue-no-fork"
            except OSError:
                self._tracking_error("registration")
        else:
            self._tracking_error("unsupported_platform")

    def _tracking_error(self, code: str) -> None:
        self.failed = True
        if code not in self.tracking_errors:
            self.tracking_errors.append(code)

    def poll(self) -> None:
        if self.queue is None:
            return
        try:
            for _ in range(8):
                events = self.queue.control(None, 1024, 0)
                for event in events:
                    if event.flags & select.KQ_EV_ERROR:
                        self._tracking_error("kernel_event")
                    if event.fflags & select.KQ_NOTE_FORK:
                        self.fork_observed = True
                        self.failed = True
                    if event.fflags & select.KQ_NOTE_EXIT:
                        self.active.discard(event.ident)
                if len(events) < 1024:
                    break
            else:
                self._tracking_error("event_overflow")
        except OSError:
            self._tracking_error("poll")

    def close(self) -> None:
        if self.queue is not None:
            self.queue.close()


def _status_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate private status key")
        result[key] = value
    return result


def _status_noninteger(_value):
    raise ValueError("noninteger private status number")


class _LinuxTracker:
    """A private subreaper's bounded, versioned, target-inaccessible pipe."""
    def __init__(self, fd: int):
        self.fd = fd
        os.set_blocking(fd, False)
        self.backend = "linux-child-subreaper"
        self.active = {"wrapper-unreconciled"}
        self.failed = False
        self.ready = False
        self.eof = False
        self.buffer = bytearray()
        self.bytes_seen = 0
        self.dispatch_state = None
        self.root_exit_code = None
        self.root_pgid = None

    def _admit_status(self, value):
        if (type(value) is not dict or type(value.get("protocol_version")) is not int
                or value["protocol_version"] != 2 or self.dispatch_state is not None):
            self.failed = True
            return
        if set(value) == {"protocol_version", "ready"} and value["ready"] is True:
            if self.ready:
                self.failed = True
            self.ready = True
            return
        fields = {"protocol_version", "dispatch_state", "root_exit_code", "descendants_stopped", "root_pid", "root_pgid"}
        if not self.ready or set(value) != fields:
            self.failed = True
            return
        state = value["dispatch_state"]
        code, stopped = value["root_exit_code"], value["descendants_stopped"]
        root, root_pid = value["root_pgid"], value["root_pid"]
        if state == "not_released":
            if code is not None or root is not None or root_pid is not None or stopped is not True:
                self.failed = True
                return
            self.dispatch_state = state
            self.active = set()
        elif state == "started":
            if (type(code) is not int or not -128 <= code <= 255 or type(stopped) is not bool
                    or type(root) is not int or root <= 1 or type(root_pid) is not int or root_pid != root):
                self.failed = True
                return
            self.dispatch_state = state
            self.root_exit_code = code
            self.root_pgid = root
            self.active = set() if stopped else {"descendants-unreconciled"}
        else:
            self.failed = True

    def poll(self) -> None:
        try:
            while True:
                try:
                    data = os.read(self.fd, 4096)
                except BlockingIOError:
                    break
                if not data:
                    self.eof = True
                    if self.buffer or self.dispatch_state is None:
                        self.failed = True
                    break
                self.bytes_seen += len(data)
                if self.bytes_seen > 4096:
                    self.failed = True
                    break
                self.buffer.extend(data)
                while b"\n" in self.buffer:
                    line, _, rest = self.buffer.partition(b"\n")
                    self.buffer = bytearray(rest)
                    value = json.loads(line, object_pairs_hook=_status_object,
                                       parse_float=_status_noninteger, parse_constant=_status_noninteger)
                    self._admit_status(value)
        except (OSError, ValueError, TypeError, AttributeError, RecursionError):
            self.failed = True

    def not_released_confirmed(self, *, gate_release_attempted, wrapper_returncode, wrapper_group_ceased):
        """Parsed data alone never proves cleanup; combine owned observations."""
        return (self.ready and self.dispatch_state == "not_released" and self.eof and not self.buffer
                and not self.failed and not self.active and gate_release_attempted is False
                and type(wrapper_returncode) is int and wrapper_returncode == 0
                and wrapper_group_ceased is True)

    def wait_ready(self, process: subprocess.Popen) -> bool:
        deadline = time.monotonic() + 5
        while not self.ready and not self.failed and not self.eof and time.monotonic() < deadline:
            self.poll()
            if process.poll() is not None:
                self.poll()
                break
            if not self.ready:
                select.select([self.fd], [], [], .05)
        return self.ready and not self.failed

    def close(self) -> None:
        os.close(self.fd)


@dataclasses.dataclass(frozen=True)
class ProcessReceipt:
    invocation_id: str
    pid: int
    pgid: int
    supervisor_pid: int
    started_unix_ms: int
    executable_sha256: str

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class ProcessResult:
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    cancelled: bool
    termination_confirmed: bool
    group_termination_confirmed: bool
    output_limited: bool
    receipt: ProcessReceipt
    duration_ms: int
    output_bytes: int
    lifetime_backend: str
    unaccounted_descendants: bool
    protocol_error: str | None = None

    def to_dict(self) -> dict:
        value = dataclasses.asdict(self)
        value["stdout"] = self.stdout.decode("utf-8", "replace")
        value["stderr"] = self.stderr.decode("utf-8", "replace")
        return value


def fingerprint(path: str | Path) -> str:
    """Hash the resolved bytes of an explicitly chosen absolute executable.

    Keep the invocation path: resolving a virtualenv Python before execution
    would silently select the system environment instead of the selected venv.
    The operator owns executable selection; a task packet cannot select it.
    """
    source = Path(path)
    if not source.is_absolute() or not source.resolve(strict=True).is_file():
        raise ProcessBoundaryError("executable must be an absolute regular file")
    with source.open("rb") as stream:
        value = hashlib.file_digest(stream, "sha256").hexdigest()
    return value


def minimal_environment(*, runtime_parent: bool = False) -> dict[str, str]:
    """No GitHub/cloud tokens enter check processes. Runtime auth stays runtime-owned."""
    allowed = ("PATH", "LANG", "LC_ALL", "TZ", "SYSTEMROOT")
    env = {key: os.environ[key] for key in allowed if key in os.environ}
    env.setdefault("PATH", os.defpath)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    if runtime_parent and "HOME" in os.environ:
        # The approved Codex parent uses its existing credential store; shell tools
        # are separately denied this path by the permission profile.
        env["HOME"] = os.environ["HOME"]
    return env


def redact(data: bytes, secrets: Sequence[str | bytes] = ()) -> bytes:
    """Redact after bounded assembly, including secrets split across pipe reads."""
    result = data
    values = [x.encode() if isinstance(x, str) else x for x in secrets if x]
    for value in sorted(values, key=len, reverse=True):
        result = result.replace(value, b"[REDACTED]")
    result = re.sub(rb"(?i)(?:Bearer\s+)[A-Za-z0-9._~+/-]+=*", b"[REDACTED]", result)
    result = re.sub(rb"(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,})", b"[REDACTED]", result)
    result = re.sub(rb"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|\Z)", b"[REDACTED]", result, flags=re.S)
    return result


def _group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def receipt_is_alive(receipt: dict | ProcessReceipt | None) -> bool:
    """Conservative read-only recovery hint, never permission to signal a PID.

    True includes uncertain/malformed/reused identities. False proves only that
    the recorded PID and group are currently absent; it is not proof that an
    escaped or daemonized descendant stopped. A supervisor loss still needs
    explicit reconciliation and a durable cessation receipt before reuse.
    """
    if isinstance(receipt, ProcessReceipt):
        receipt = receipt.to_dict()
    if not isinstance(receipt, dict):
        return True
    pid, pgid = receipt.get("pid"), receipt.get("pgid")
    if type(pid) is not int or pid < 2 or type(pgid) is not int or pgid != pid:
        return True
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return _group_exists(pgid)
    except (PermissionError, OSError):
        return True


def _signal_owned(process: subprocess.Popen, sig: int) -> bool:
    # Only the still-live Popen handle created by this invocation grants signal
    # authority. This function deliberately cannot accept a receipt from disk.
    if process.poll() is not None:
        return False
    try:
        if os.getpgid(process.pid) != process.pid:
            return False
        forwarded = signal.SIGUSR1 if getattr(process, "_taskalong_subreaper", False) and sig == signal.SIGKILL else sig
        os.killpg(process.pid, forwarded)
        return True
    except ProcessLookupError:
        return False


@dataclasses.dataclass
class _Interruption:
    requested: bool = False


@contextmanager
def collect_interrupts():
    """Defer the default foreground SIGINT through owned cleanup and persistence.

    The flag is local intent, never proof of cessation. Callers must retain the
    kernel receipt before clearing an effect. Custom signal handlers and worker
    threads keep their caller-selected semantics.
    """
    interrupted = _Interruption()
    previous = signal.getsignal(signal.SIGINT)
    selected = threading.current_thread() is threading.main_thread() and previous is signal.default_int_handler
    def requested(signum, frame):
        interrupted.requested = True
    if selected:
        signal.signal(signal.SIGINT, requested)
    try:
        yield interrupted
    finally:
        if selected and signal.getsignal(signal.SIGINT) is requested:
            signal.signal(signal.SIGINT, previous)


def run_bounded(
    argv: Sequence[str], *, cwd: str | Path, stdin: bytes = b"",
    timeout_seconds: int | float = 180, max_output_bytes: int = 8 * 1024 * 1024,
    env: Mapping[str, str] | None = None,
    cancel_requested: Callable[[], bool] | None = None,
    heartbeat: Callable[[], None] | None = None,
    on_spawn: Callable[[ProcessReceipt], None] | None = None,
    on_stdout_line: Callable[[bytes], None] | None = None,
    _capture_private_output: Callable[[bytes, bytes], None] | None = None,
    secrets: Sequence[str | bytes] = (), max_line_bytes: int = 1024 * 1024,
    signal_grace_seconds: float = 0.5,
    _lifetime_observations: dict | None = None,
) -> ProcessResult:
    """Drain both pipes concurrently with output/deadline/cancellation limits.

    Callbacks run in the owning supervisor. A callback failure stops the owned
    child before propagating, preserving uncertainty if descendants escape.
    No command string, environment dump, or raw transcript is persisted here.
    """
    if os.name != "posix":
        raise ProcessBoundaryError("process supervision requires POSIX")
    if _lifetime_observations is not None and (type(_lifetime_observations) is not dict
                                             or _lifetime_observations):
        raise ProcessBoundaryError("private lifetime observation sink must be an empty dict",
                                   effect_outcome="not_sent")
    if isinstance(argv, (str, bytes)) or not argv or any(not isinstance(x, str) or not x or "\0" in x for x in argv):
        raise ProcessBoundaryError("argv must contain nonempty strings")
    if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
            or not 0 < timeout_seconds <= 3600):
        raise ProcessBoundaryError("invalid process deadline")
    if (isinstance(signal_grace_seconds, bool) or not isinstance(signal_grace_seconds, (int, float))
            or not 0 <= signal_grace_seconds <= 3600):
        raise ProcessBoundaryError("invalid signal grace period")
    if isinstance(max_output_bytes, bool) or not 1 <= max_output_bytes <= 64 * 1024 * 1024:
        raise ProcessBoundaryError("invalid output budget")
    if not isinstance(stdin, bytes) or len(stdin) > 1024 * 1024:
        raise ProcessBoundaryError("stdin exceeds packet limit")
    started = time.monotonic()
    digest = fingerprint(argv[0])
    child_env = dict(env) if env is not None else minimal_environment()
    try:
        selector = selectors.DefaultSelector()
    except OSError as exc:
        raise ProcessBoundaryError("process readiness boundary unavailable",
            code="runtime_lifecycle_unsupported", effect_outcome="not_sent") from exc
    gate_read, gate_write = os.pipe()
    # A trusted, isolated stdlib-only gate waits before execve. This closes the
    # Popen-to-kqueue registration race: the untrusted target cannot fork before
    # the kernel has begun tracking all descendants. No packet/source is argv.
    gate_code = "import os,sys;fd=int(sys.argv[1]);token=os.read(fd,1);os.close(fd);os.execve(sys.argv[2],sys.argv[2:],os.environ) if token==b'1' else sys.exit(125)"
    lifetime_read = lifetime_write = None
    if sys.platform == "linux":
        lifetime_read, lifetime_write = os.pipe()
        gate_argv = [sys.executable, "-I", "-S", str(Path(__file__).with_name("_linux_lifetime.py")),
                     str(gate_read), str(lifetime_write), *argv]
        pass_fds = (gate_read, lifetime_write)
    else:
        gate_argv = [sys.executable, "-I", "-S", "-c", gate_code, str(gate_read), *argv]
        pass_fds = (gate_read,)
    try:
        process = subprocess.Popen(gate_argv, cwd=cwd, env=child_env,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True, close_fds=True, pass_fds=pass_fds)
    except BaseException:
        os.close(gate_read)
        os.close(gate_write)
        if lifetime_read is not None:
            os.close(lifetime_read)
            os.close(lifetime_write)
        selector.close()
        raise
    os.close(gate_read)
    if lifetime_read is not None:
        os.close(lifetime_write)
        tracker = _LinuxTracker(lifetime_read)
        process._taskalong_subreaper = True
    else:
        tracker = _DescendantTracker(process.pid)
    receipt = ProcessReceipt(str(uuid.uuid4()), process.pid, process.pid, os.getpid(),
                             int(time.time() * 1000), digest)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    pending_line = bytearray()
    input_offset = 0
    total = 0
    timed_out = cancelled = output_limited = False
    protocol_error = None
    callback_error: BaseException | None = None
    termination_started: float | None = None
    forced_wrapper_stop_at: float | None = None
    gate_release_attempted = False
    signal_stage = 0
    last_heartbeat = started
    child_exit_at: float | None = None
    boundary_failures: list[tuple[str, int | None]] = []
    def remember_failure(stage: str, error: BaseException) -> None:
        # Closed stage names and bounded numeric errno only; never OS messages,
        # paths or worker text. Keep the first failure and secondary cleanup.
        number = getattr(error, "errno", None)
        if type(number) is not int or not 0 <= number <= 65535:
            number = None
        if len(boundary_failures) < 16:
            boundary_failures.append((stage, number))
    try:
        try:
            if isinstance(tracker, _LinuxTracker) and not tracker.wait_ready(process):
                raise ProcessBoundaryError("process lifetime boundary unavailable",
                    code="runtime_lifecycle_unsupported", effect_outcome="not_sent")
            if isinstance(tracker, _DescendantTracker) and tracker.failed:
                raise ProcessBoundaryError("process lifetime boundary unavailable",
                    code="runtime_lifecycle_unsupported", effect_outcome="not_sent")
            if on_spawn:
                on_spawn(receipt)
            # Mark before the write: interruption after a successful write must
            # never turn an already released target into a retryable not-sent.
            gate_release_attempted = True
            os.write(gate_write, b"1")
        except BaseException as exc:
            callback_error = exc
            termination_started = time.monotonic()
        finally:
            os.close(gate_write)
        for pipe, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        os.set_blocking(process.stdin.fileno(), False)
        if stdin:
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            process.stdin.close()
        while selector.get_map() or process.poll() is None:
            now = time.monotonic()
            tracker.poll()
            if process.poll() is not None:
                child_exit_at = child_exit_at or now
            if callback_error is None:
                try:
                    if heartbeat and now - last_heartbeat >= 0.5:
                        heartbeat()
                        last_heartbeat = now
                    if cancel_requested and cancel_requested():
                        cancelled = True
                except BaseException as exc:
                    callback_error = exc
            if now - started >= timeout_seconds:
                timed_out = True
            if timed_out or cancelled or output_limited or protocol_error or callback_error:
                termination_started = termination_started or now
                if signal_stage == 0:
                    # Closing an unreleased Linux gate already requests clean
                    # helper completion. SIGINT here can race the helper's
                    # finalizer after a valid no-target receipt and destroy its
                    # protocol exit. Keep the existing absolute TERM/KILL and
                    # hard-stop windows; ambiguous wrappers still fail closed.
                    if gate_release_attempted or not isinstance(tracker, _LinuxTracker):
                        try:
                            _signal_owned(process, signal.SIGINT)
                        except OSError as exc:
                            remember_failure("signal_int", exc)
                    signal_stage = 1
                elif signal_stage == 1 and now - termination_started >= signal_grace_seconds:
                    try:
                        _signal_owned(process, signal.SIGTERM)
                    except OSError as exc:
                        remember_failure("signal_term", exc)
                    signal_stage = 2
                elif signal_stage == 2 and now - termination_started >= signal_grace_seconds * 2:
                    try:
                        _signal_owned(process, signal.SIGKILL)
                    except OSError as exc:
                        remember_failure("signal_kill", exc)
                    signal_stage = 3
                elif (signal_stage == 3 and isinstance(tracker, _LinuxTracker)
                      and now - termination_started >= signal_grace_seconds * 3
                      and process.poll() is None):
                    # A same-UID target can stop its helper, preventing even the
                    # forwarded SIGKILL from running. This exact Popen child is
                    # still unreaped and owned here. Kill only that wrapper;
                    # its missing final can never prove descendant cessation.
                    tracker.failed = True
                    forced_wrapper_stop_at = now
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                    except OSError as exc:
                        remember_failure("wrapper_kill", exc)
                    signal_stage = 4
            # Bound draining independently of reaping: an uninterruptible
            # wrapper or descendants retaining its pipes must not extend the
            # caller's cancellation indefinitely.
            if (forced_wrapper_stop_at is not None
                    and now - forced_wrapper_stop_at >= max(1.0, signal_grace_seconds * 3)):
                break
            if (termination_started is not None and not isinstance(tracker, _LinuxTracker)
                    and now - termination_started >= signal_grace_seconds * 3 + max(1.0, signal_grace_seconds * 3)):
                # Signal delivery may be denied even for our owned child. Stop
                # draining within the existing escalation/drain allowances;
                # the bounded final waits cannot manufacture cessation.
                tracker.failed = True
                remember_failure("termination_unconfirmed", TimeoutError())
                break
            # Descendants retaining pipes after the owning parent exits cannot
            # hold this client forever. Their existence yields unconfirmed.
            if child_exit_at and now - child_exit_at > max(1.0, signal_grace_seconds * 3):
                break
            for key, _ in selector.select(0.1):
                pipe = key.fileobj
                name = key.data
                if name == "stdin":
                    try:
                        count = os.write(pipe.fileno(), stdin[input_offset:input_offset + 65536])
                        input_offset += count
                    except BlockingIOError:
                        continue
                    except (BrokenPipeError, OSError):
                        input_offset = len(stdin)
                    if input_offset >= len(stdin):
                        selector.unregister(pipe)
                        pipe.close()
                    continue
                try:
                    chunk = os.read(pipe.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(pipe)
                    pipe.close()
                    continue
                total += len(chunk)
                remaining = max(0, max_output_bytes - sum(len(x) for x in buffers.values()))
                buffers[name].extend(chunk[:remaining])
                if total > max_output_bytes:
                    output_limited = True
                if name == "stdout" and on_stdout_line and not callback_error and not protocol_error:
                    pending_line.extend(chunk)
                    while b"\n" in pending_line:
                        line, _, rest = pending_line.partition(b"\n")
                        pending_line = bytearray(rest)
                        if len(line) > max_line_bytes:
                            protocol_error = "runtime_line_too_large"
                            break
                        try:
                            on_stdout_line(bytes(line))
                        except BaseException as exc:
                            callback_error = exc
                            break
                    if len(pending_line) > max_line_bytes:
                        protocol_error = "runtime_line_too_large"
                        pending_line.clear()
        if process.poll() is None:
            if isinstance(tracker, _LinuxTracker):
                tracker.failed = True
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                except OSError as exc:
                    remember_failure("completion_wrapper_kill", exc)
            else:
                try:
                    _signal_owned(process, signal.SIGKILL)
                except OSError as exc:
                    remember_failure("completion_signal_kill", exc)
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        except OSError as exc:
            remember_failure("completion_wait", exc)
            tracker.failed = True
    except OSError as exc:
        remember_failure("observation", exc)
        tracker.failed = True
    finally:
        # Finalize before freezing the result. One cleanup failure must not skip
        # other resources or leave an already-created successful receipt behind.
        if process.poll() is None:
            if isinstance(tracker, _LinuxTracker):
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                except OSError as exc:
                    remember_failure("final_wrapper_kill", exc)
            else:
                try:
                    _signal_owned(process, signal.SIGKILL)
                except OSError as exc:
                    remember_failure("final_signal_kill", exc)
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            except OSError as exc:
                remember_failure("final_wait", exc)
                tracker.failed = True
        try:
            tracker.poll()
        except (OSError, ValueError) as exc:
            remember_failure("tracker_poll", exc)
            tracker.failed = True
        for stage, close in (("selector_close", selector.close), ("tracker_close", tracker.close)):
            try:
                close()
            except (OSError, ValueError) as exc:
                remember_failure(stage, exc)
                tracker.failed = True
        for pipe in (process.stdin, process.stdout, process.stderr):
            if pipe and not pipe.closed:
                try:
                    pipe.close()
                except (OSError, ValueError) as exc:
                    remember_failure("pipe_close", exc)
                    tracker.failed = True
    if pending_line and not protocol_error:
        protocol_error = "runtime_jsonl_truncated"
    if isinstance(tracker, _LinuxTracker) and process.returncode != 0:
        tracker.failed = True
    try:
        group_confirmed = process.poll() is not None and not _group_exists(process.pid)
        if isinstance(tracker, _LinuxTracker):
            if tracker.dispatch_state == "not_released":
                group_confirmed = tracker.not_released_confirmed(
                    gate_release_attempted=gate_release_attempted,
                    wrapper_returncode=process.returncode, wrapper_group_ceased=group_confirmed)
                if not group_confirmed:
                    tracker.failed = True
            else:
                if not tracker.eof or tracker.buffer or tracker.dispatch_state != "started":
                    tracker.failed = True
                group_confirmed = group_confirmed and tracker.root_pgid is not None and not _group_exists(tracker.root_pgid)
    except OSError as exc:
        remember_failure("group_observation", exc)
        group_confirmed = False
        tracker.failed = True
    unaccounted = tracker.failed or bool(tracker.active)
    confirmed = group_confirmed and not unaccounted
    exit_code = (tracker.root_exit_code if isinstance(tracker, _LinuxTracker)
                 else process.returncode if gate_release_attempted else None)
    # Only trusted in-process drivers can retain these bounded originals.
    # Default ProcessResult/to_dict callers still receive redacted output.
    raw_stdout, raw_stderr = bytes(buffers["stdout"]), bytes(buffers["stderr"])
    capture_error = None
    if _capture_private_output is not None:
        try:
            _capture_private_output(raw_stdout, raw_stderr)
        except Exception as exc:
            capture_error = exc
    result = ProcessResult(exit_code, redact(raw_stdout, secrets),
                           redact(raw_stderr, secrets), timed_out, cancelled,
                           confirmed, group_confirmed, output_limited, receipt, int((time.monotonic()-started)*1000), total,
                           tracker.backend, unaccounted, protocol_error)
    # Private observations for the separate experimental foreground API. They
    # cannot change the existing result, tracker decision or production format.
    if _lifetime_observations is not None:
        _lifetime_observations.update(
            fork_observed=getattr(tracker, "fork_observed", False),
            tracking_errors=tuple(getattr(tracker, "tracking_errors", ())))
    failures = tuple(boundary_failures)
    if capture_error is not None:
        # Preserve the established private-capture failure precedence.
        raise ProcessBoundaryError("private output capture callback failed", code="process_capture_failed",
            effect_outcome="uncertain" if gate_release_attempted else "not_sent",
            process_result=result, boundary_failures=failures) from None
    if callback_error:
        raise ProcessBoundaryError("process boundary callback failed",
            code=getattr(callback_error, "code", "process_callback_failed"),
            effect_outcome="uncertain" if gate_release_attempted else
                getattr(callback_error, "effect_outcome", "uncertain"), process_result=result,
            boundary_failures=failures) from callback_error
    if failures:
        code = "process_signal_failed" if "signal" in failures[0][0] or "kill" in failures[0][0] else "process_cleanup_failed"
        raise ProcessBoundaryError("owned process boundary could not complete safely", code=code,
            effect_outcome="uncertain" if gate_release_attempted else "not_sent",
            process_result=result, boundary_failures=failures) from None
    return result
