"""Private control paths and literal repository-relative paths."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path, PurePosixPath

from .errors import TaskAlongError

_PROTECTED = {".git", ".taskalong", ".agents", ".codex", ".claude", ".project-ai", ".aws", ".ssh", ".env"}
_INSTRUCTIONS = {"agents.md", "claude.md", "gemini.md"}


def default_state_dir() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "TaskAlong"
    state_root = os.environ.get("XDG_STATE_HOME")
    if state_root and Path(state_root).is_absolute():
        return Path(state_root) / "taskalong"
    return Path.home() / ".local" / "state" / "taskalong"


def safe_relative(value: str, *, allow_directory: bool = False, allow_dot: bool = False) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096:
        raise TaskAlongError("invalid_path", "A bounded literal relative path is required.")
    if allow_dot and value == ".":
        return value
    directory = value.endswith("/")
    if directory and not allow_directory:
        raise TaskAlongError("invalid_path", "A file path cannot end with a directory separator.")
    literal = value[:-1] if directory else value
    parts = literal.split("/")
    if (
        not literal
        or literal.startswith("/")
        or "\\" in literal
        or not literal.isprintable()
        or any(c in literal for c in "*?[]")
        or any(part in {"", ".", ".."} for part in parts)
        or any(part.lower() in _PROTECTED or part.lower() in _INSTRUCTIONS for part in parts)
        or any(part.lower().startswith(".env.") for part in parts)
        or PurePosixPath(literal).is_absolute()
    ):
        raise TaskAlongError("invalid_path", "Path traversal, protected paths, and glob scope are unsupported.")
    return literal + ("/" if directory else "")


def contained_path(root: str | Path, relative: str, *, allow_dot: bool = False) -> Path:
    safe_relative(relative, allow_dot=allow_dot)
    base = Path(root).resolve(strict=True)
    target = base / relative
    # resolve() follows every existing ancestor, including a symlink whose final
    # target does not exist.  Reject symlinks even when they point inside scope.
    current = base
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            raise TaskAlongError("symlink_path", "Symlinks cannot be task inputs or outputs.", exit_code=3)
    if not target.resolve(strict=False).is_relative_to(base):
        raise TaskAlongError("path_escape", "The path escapes its owned root.", exit_code=3)
    return target


def _secure_existing(path: Path, *, directory: bool) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise TaskAlongError("insecure_state_path", "Control paths must not contain symlinks.", exit_code=3)
    if (directory and not stat.S_ISDIR(info.st_mode)) or (not directory and not stat.S_ISREG(info.st_mode)):
        raise TaskAlongError("insecure_state_path", "Control paths must have the expected type.", exit_code=3)
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise TaskAlongError("insecure_state_owner", "Control paths must belong to the current operator.", exit_code=3)
    if info.st_mode & 0o077:
        raise TaskAlongError("insecure_state_mode", "Existing control paths must have private permissions.", exit_code=3)


def private_directory(path: str | Path) -> Path:
    target = Path(path).absolute()
    # Existing *ancestors* may be public OS directories but never symlinks. The
    # actual state directory must be private; don't chmod an existing directory.
    chain = list(reversed(target.parents)) + [target]
    for ancestor in chain:
        if ancestor.is_symlink():
            raise TaskAlongError("insecure_state_path", "Control paths must not contain symlinks.", exit_code=3)
    try:
        target.mkdir(mode=0o700, parents=True, exist_ok=False)
    except FileExistsError:
        pass
    _secure_existing(target, directory=True)
    return target


def private_file(path: str | Path) -> Path:
    target = Path(path)
    if target.exists() or target.is_symlink():
        _secure_existing(target, directory=False)
    return target
