"""Private Linux subreaper for one owned process lifetime.

Run as an isolated stdlib script, not as a user-facing command.  The supervisor
supplies gate/status pipe descriptors and an already validated absolute argv.
Only this live wrapper may forward signals to the child process group.  No
persisted PID, process-list snapshot, or elapsed heartbeat grants signal authority.
"""

from __future__ import annotations

import ctypes
import errno
import json
import os
import signal
import sys
import time


_FORWARD_SIGNALS = {signal.SIGINT, signal.SIGTERM, signal.SIGUSR1}
_PR_GET_DUMPABLE = 3
_PR_SET_DUMPABLE = 4
_PR_SET_CHILD_SUBREAPER = 36
_PR_GET_CHILD_SUBREAPER = 37


def _write_status(fd: int, value: dict) -> None:
    """One bounded atomic pipe write; a lost reader cannot grant success."""
    data = (json.dumps({"protocol_version": 2, **value}, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    try:
        # Each status is far below POSIX PIPE_BUF. Never emit target data here.
        if os.write(fd, data) != len(data):
            raise OSError(errno.EIO, "short status write")
    except (BrokenPipeError, OSError):
        # The owning supervisor has gone. The wrapper must still reap its child;
        # a later reader cannot reconstruct a missing cessation receipt.
        pass


def _become_subreaper() -> bool:
    if sys.platform != "linux":
        return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.restype = ctypes.c_int
        # Same-UID targets must not reopen /proc/<wrapper>/fd/<status> or use
        # ptrace/pidfd_getfd to forge the private cessation protocol. Close-on-
        # exec alone does not protect a dumpable ancestor's descriptors.
        if prctl(ctypes.c_int(_PR_SET_DUMPABLE), ctypes.c_ulong(0),
                 ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)) != 0:
            return False
        if prctl(ctypes.c_int(_PR_GET_DUMPABLE), ctypes.c_ulong(0),
                 ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)) != 0:
            return False
        # prctl is variadic; use explicit correctly sized arguments.
        if prctl(ctypes.c_int(_PR_SET_CHILD_SUBREAPER), ctypes.c_ulong(1),
                 ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)) != 0:
            return False
        enabled = ctypes.c_int(0)
        if prctl(ctypes.c_int(_PR_GET_CHILD_SUBREAPER), ctypes.byref(enabled),
                 ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)) != 0:
            return False
        return enabled.value == 1
    except (AttributeError, OSError):
        return False


def _wait_code(status: int) -> int:
    return os.waitstatus_to_exitcode(status)


def _descendants_stopped() -> bool:
    """Reap exited adopted descendants; ECHILD is the kernel cessation proof.

    A zero result means at least one live adopted descendant exists. Preserve
    uncertainty rather than trying to discover or signal detached numeric PIDs.
    """
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return True
        except InterruptedError:
            continue
        if pid == 0:
            return False


def main(argv: list[str] | None = None) -> int:
    values = sys.argv[1:] if argv is None else argv
    if len(values) < 3:
        return 125
    try:
        gate_fd = int(values[0])
        status_fd = int(values[1])
        target_argv = values[2:]
        if gate_fd < 3 or status_fd < 3 or gate_fd == status_fd:
            return 125
        if (not isinstance(target_argv[0], str) or not target_argv[0] or not os.path.isabs(target_argv[0])
                or any(not isinstance(value, str) or "\0" in value for value in target_argv)):
            _write_status(status_fd, {"ready": False, "error": "lifetime_unsupported"})
            return 125
        for value in target_argv:
            value.encode("utf-8", errors="strict")
    except (ValueError, IndexError):
        return 125

    if not _become_subreaper():
        _write_status(status_fd, {"ready": False, "error": "lifetime_unsupported"})
        return 125

    # Reaping before clearing the root ID could otherwise permit PID reuse in a
    # signal handler. WNOHANG plus a signal mask keeps that transition atomic.
    root_pid: int | None = None
    pending_signal: int | None = None

    def forward(signum: int, _frame: object) -> None:
        nonlocal pending_signal
        forwarded = signal.SIGKILL if signum == signal.SIGUSR1 else signum
        if root_pid is None:
            pending_signal = forwarded
            return
        try:
            os.killpg(root_pid, forwarded)
        except ProcessLookupError:
            # A dead root remains unreaped while this ID is signal-authoritative.
            pass
        # The target may leave its original process group. It remains our exact
        # unreaped child, so its PID cannot be reused before the masked wait/
        # clear transition below. Group disappearance never removes that live
        # ownership, and group signaling alone would leave cancellation hanging.
        try:
            os.kill(root_pid, forwarded)
        except ProcessLookupError:
            pass

    for sig in _FORWARD_SIGNALS:
        signal.signal(sig, forward)
    _write_status(status_fd, {"ready": True})
    try:
        token = os.read(gate_fd, 1)
    except OSError:
        token = None
    finally:
        os.close(gate_fd)
    if token == b"":
        if not _descendants_stopped():
            _write_status(status_fd, {"error": "unexpected_prefork_descendant"})
            return 125
        _write_status(status_fd, {"dispatch_state": "not_released", "root_exit_code": None,
                                  "descendants_stopped": True, "root_pid": None, "root_pgid": None})
        os.close(status_fd)
        return 0
    if token != b"1":
        _write_status(status_fd, {"error": "invalid_gate_release"})
        return 125

    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, _FORWARD_SIGNALS)
    try:
        child = os.fork()
    except OSError:
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        _write_status(status_fd, {"root_exit_code": 125, "descendants_stopped": True,
                                  "root_pid": None, "root_pgid": None,
                                  "error": "dispatch_failed"})
        return 125
    if child == 0:
        # Status/gate control descriptors must never enter the untrusted target.
        os.close(status_fd)
        try:
            os.setpgid(0, 0)
            for sig in _FORWARD_SIGNALS:
                signal.signal(sig, signal.SIG_DFL)
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
            os.execve(target_argv[0], target_argv, os.environ)
        except BaseException:
            os.write(2, b"taskalong: target exec failed\n")
            os._exit(127)

    root_pid = child
    # Parent setpgid closes the fork-to-child-setpgid forwarding race. EACCES
    # means exec already completed after the child's own successful setpgid.
    try:
        os.setpgid(child, child)
    except OSError as exc:
        if exc.errno not in (errno.EACCES, errno.ESRCH):
            # Keep the root's PID reserved and reap it before any final receipt.
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
    signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
    if pending_signal is not None:
        try:
            os.killpg(child, pending_signal)
        except ProcessLookupError:
            pass
        try:
            os.kill(child, pending_signal)
        except ProcessLookupError:
            pass

    root_status: int | None = None
    while root_status is None:
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, _FORWARD_SIGNALS)
        try:
            try:
                observed, status = os.waitpid(child, os.WNOHANG)
            except InterruptedError:
                observed = 0
            except ChildProcessError:
                root_pid = None
                _write_status(status_fd, {"dispatch_state": "started", "root_exit_code": 125, "descendants_stopped": False,
                                          "root_pid": child, "root_pgid": child,
                                          "error": "root_status_unknown"})
                return 125
            if observed == child:
                root_status = status
                root_pid = None
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        if root_status is None:
            time.sleep(0.01)

    stopped = _descendants_stopped()
    code = _wait_code(root_status)
    _write_status(status_fd, {"dispatch_state": "started", "root_exit_code": code, "descendants_stopped": stopped,
                              "root_pid": child, "root_pgid": child})
    os.close(status_fd)
    # The pipe carries signed subprocess exit semantics. The wrapper's own exit
    # only reports whether its protocol completed; it does not re-label signals.
    return 0 if stopped else 125


if __name__ == "__main__":
    raise SystemExit(main())
