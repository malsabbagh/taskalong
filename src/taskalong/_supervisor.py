"""Private detached per-run driver. This is not a daemon or network service."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat
import sys
import uuid

from .errors import TaskAlongError
from .paths import private_directory


@contextmanager
def run_guard(state_dir: str | Path, run_id: str):
    """OS guard survives parent-client exit; lock files are never unlinked."""
    try:
        if str(uuid.UUID(run_id)) != run_id:
            raise ValueError("noncanonical UUID")
    except (ValueError, TypeError, AttributeError):
        raise TaskAlongError("run_id_invalid", "Supervisor requires a canonical run UUID")
    root = Path(state_dir)
    if not root.is_absolute() or root.is_symlink():
        raise TaskAlongError("state_path_unsafe", "Supervisor requires a private absolute state directory", exit_code=3)
    private_directory(root)
    guards = private_directory(root / "guards")
    path = guards / f"{run_id}.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise TaskAlongError("state_path_unsafe", "Supervisor guard permissions are unsafe", exit_code=3)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise TaskAlongError("supervisor_owned", "Another supervisor owns this run", exit_code=4)
        yield
    finally:
        os.close(fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Private TaskAlong supervisor")
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--attempt-id", required=True)
    args = parser.parse_args(argv)
    try:
        from .workflow import drive_run
        with run_guard(args.state_dir, args.run_id):
            drive_run(args.state_dir, args.run_id, args.attempt_id)
        return 0
    except TaskAlongError as exc:
        # Safe error code only. A private failed supervisor cannot claim the
        # persisted run failed or a possible worker stopped; reconcile decides.
        print(exc.code, file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
