"""Bounded descriptor-relative artifact reads and fresh private staging copies.

These checks refuse observed replacement and metadata changes. They do not
prove that a transient hardlink or concurrent filesystem change never existed,
or establish isolation from another process running as the operator.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import stat

from .errors import TaskAlongError
from .paths import safe_relative

_open = os.open
_read = os.read
_write = os.write
_stat = os.stat
_CHUNK = 65536
_MESSAGE = "The artifact file is unavailable, unsafe, changed, or outside its declared bounds."


def _invalid(*, changed=False):
    return TaskAlongError("artifact_file_invalid", _MESSAGE, exit_code=3,
                          effect_outcome="uncertain" if changed else "not_sent")


def _flags():
    if (os.name != "posix" or not all(hasattr(os, name) for name in
            ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK", "getuid"))
            or os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd
            or os.stat not in os.supports_follow_symlinks):
        raise _invalid()
    return os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _identity(info):
    return info.st_dev, info.st_ino


def _file_state(info):
    return (_identity(info), info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory(info, *, owned, private):
    if (not stat.S_ISDIR(info.st_mode)
            or owned and info.st_uid != os.getuid()
            or private and info.st_mode & 0o077):
        raise _invalid()


def _regular(info, *, private, max_bytes):
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.getuid() or info.st_size < 0
            or info.st_size > max_bytes or private and info.st_mode & 0o077):
        raise _invalid()


def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


@contextmanager
def _parent(root, relative, *, private, create=False, changes=None):
    """Keep each directory alive, and retain its parent's exact entry identity."""
    directory_flags = _flags()
    if type(private) is not bool:
        raise _invalid()
    try:
        literal = safe_relative(relative)
        absolute = Path(root).absolute()
        # Preserve the Store's existing macOS OS-controlled aliases without
        # resolving an arbitrary operator/worker-controlled path component.
        for alias, destination in ((Path("/tmp"), Path("/private/tmp")), (Path("/var"), Path("/private/var"))):
            if (absolute == alias or alias in absolute.parents) and alias.is_symlink():
                info = alias.lstat()
                link = os.readlink(alias)
                if info.st_uid != 0 or link not in {str(destination), str(destination).lstrip("/")}:
                    raise _invalid()
                absolute = destination / absolute.relative_to(alias)
    except (TaskAlongError, TypeError, ValueError, UnicodeError):
        raise _invalid() from None
    if ".." in absolute.parts or len(absolute.parts) + len(literal.split("/")) > 128:
        raise _invalid()
    descriptors = []
    links = []
    try:
        descriptor = _open(absolute.anchor, os.O_RDONLY | directory_flags)
        descriptors.append(descriptor)
        for index, part in enumerate(absolute.parts[1:], start=1):
            child = _open(part, os.O_RDONLY | directory_flags, dir_fd=descriptor)
            descriptors.append(child)
            info = os.fstat(child)
            owned = index == len(absolute.parts) - 1
            _directory(info, owned=owned, private=private if owned else False)
            links.append((descriptor, part, child, _identity(info), owned, private if owned else False))
            descriptor = child
        _directory(os.fstat(descriptor), owned=True, private=private)
        parts = literal.split("/")
        for part in parts[:-1]:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                    if changes is not None:
                        changes[0] = True
                    os.fsync(descriptor)
                except FileExistsError:
                    pass
            child = _open(part, os.O_RDONLY | directory_flags, dir_fd=descriptor)
            descriptors.append(child)
            info = os.fstat(child)
            _directory(info, owned=True, private=private)
            links.append((descriptor, part, child, _identity(info), True, private))
            descriptor = child
        yield descriptor, parts[-1], links
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _unchanged_directories(links):
    for parent, name, descriptor, identity, owned, private in links:
        info = _stat(name, dir_fd=parent, follow_symlinks=False)
        _directory(info, owned=owned, private=private)
        _directory(os.fstat(descriptor), owned=owned, private=private)
        if (not stat.S_ISDIR(info.st_mode) or _identity(info) != identity
                or _identity(os.fstat(descriptor)) != identity):
            raise _invalid()


def _contents(descriptor, maximum):
    chunks = []
    remaining = maximum + 1
    while remaining:
        chunk = _read(descriptor, min(_CHUNK, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_regular(root, relative, *, max_bytes, expected_sha256=None,
                 expected_bytes=None, private=False, expected_mode=None):
    """Read one owned regular single-link file without following path links.

    ``root`` must already exist and be operator-owned. A zero byte maximum is
    valid for empty text. ``expected_mode`` optionally requires exact permission
    bits on the held inode and its directory entry. All errors use the same
    public-safe typed envelope.
    """
    if (type(max_bytes) is not int or not 0 <= max_bytes <= 2**53 - 1
            or expected_sha256 is not None and not _digest(expected_sha256)
            or expected_bytes is not None and (type(expected_bytes) is not int
                or not 0 <= expected_bytes <= max_bytes)
            or expected_mode is not None and (type(expected_mode) is not int
                or not 0 <= expected_mode <= 0o7777)):
        raise _invalid()
    try:
        with _parent(root, relative, private=private) as (parent, name, links):
            descriptor = _open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                               | getattr(os, "O_CLOEXEC", 0), dir_fd=parent)
            try:
                before = os.fstat(descriptor)
                _regular(before, private=private, max_bytes=max_bytes)
                entry_before = _stat(name, dir_fd=parent, follow_symlinks=False)
                if (_file_state(before) != _file_state(entry_before)
                        or expected_mode is not None and stat.S_IMODE(before.st_mode) != expected_mode):
                    raise _invalid()
                data = _contents(descriptor, max_bytes)
                after = os.fstat(descriptor)
                _regular(after, private=private, max_bytes=max_bytes)
                entry = _stat(name, dir_fd=parent, follow_symlinks=False)
                if (_file_state(before) != _file_state(after)
                        or _file_state(after) != _file_state(entry)
                        or expected_mode is not None and (stat.S_IMODE(after.st_mode) != expected_mode
                            or stat.S_IMODE(entry.st_mode) != expected_mode)
                        or len(data) != before.st_size or len(data) > max_bytes
                        or expected_bytes is not None and len(data) != expected_bytes
                        or expected_sha256 is not None
                        and hashlib.sha256(data).hexdigest() != expected_sha256):
                    raise _invalid()
                _unchanged_directories(links)
                return data
            finally:
                os.close(descriptor)
    except (OSError, ValueError, TypeError, NotImplementedError):
        raise _invalid() from None


def stage_regular(root, relative, data, *, expected_sha256, mode=0o400):
    """Create a fresh private copy; never overwrite or link an existing entry.

    The caller must journal the intent and reserve capacity first. On a failure
    after file/directory creation, preserve those bytes for exact reconciliation;
    the error reports an uncertain effect instead of deleting possible work.
    File modes are defense in depth, not a same-user isolation guarantee.
    """
    if (type(data) is not bytes or not _digest(expected_sha256)
            or hashlib.sha256(data).hexdigest() != expected_sha256
            or type(mode) is not int or mode not in {0o400, 0o600}):
        raise _invalid()
    changes = [False]
    try:
        with _parent(root, relative, private=True, create=True, changes=changes) as (parent, name, links):
            descriptor = _open(name, os.O_CREAT | os.O_EXCL | os.O_RDWR
                               | os.O_NOFOLLOW | os.O_NONBLOCK
                               | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=parent)
            changes[0] = True
            try:
                _regular(os.fstat(descriptor), private=True, max_bytes=len(data))
                offset = 0
                while offset < len(data):
                    written = _write(descriptor, data[offset:offset + _CHUNK])
                    if written <= 0:
                        raise _invalid(changed=True)
                    offset += written
                os.fchmod(descriptor, mode)
                os.fsync(descriptor)
                os.lseek(descriptor, 0, os.SEEK_SET)
                before = os.fstat(descriptor)
                _regular(before, private=True, max_bytes=len(data))
                observed = _contents(descriptor, len(data))
                after = os.fstat(descriptor)
                entry = _stat(name, dir_fd=parent, follow_symlinks=False)
                if (_file_state(before) != _file_state(after)
                        or _file_state(after) != _file_state(entry)
                        or observed != data or stat.S_IMODE(after.st_mode) != mode):
                    raise _invalid(changed=True)
                _unchanged_directories(links)
                os.fsync(parent)
            finally:
                os.close(descriptor)
    except (OSError, ValueError, TypeError, NotImplementedError):
        raise _invalid(changed=changes[0]) from None
    except TaskAlongError:
        if changes[0]:
            raise _invalid(changed=True) from None
        raise


def _observed(descriptor, parent, name, *, maximum, mode):
    before = os.fstat(descriptor)
    _regular(before, private=False, max_bytes=maximum)
    if stat.S_IMODE(before.st_mode) != mode:
        raise _invalid()
    os.lseek(descriptor, 0, os.SEEK_SET)
    data = _contents(descriptor, maximum)
    after = os.fstat(descriptor)
    entry = _stat(name, dir_fd=parent, follow_symlinks=False)
    _regular(after, private=False, max_bytes=maximum)
    if (_file_state(before) != _file_state(after)
            or _file_state(after) != _file_state(entry)
            or len(data) != before.st_size or len(data) > maximum):
        raise _invalid()
    return data


def apply_regular(root, relative, data, *, before_sha256, before_bytes,
                  mode="100644", allow_after=False):
    """Apply one journal-authorized exact add/modify through a held descriptor.

    ``before_sha256=None, before_bytes=None`` means a fresh add. Existing files
    must match both before-state fields and retain the declared mode. Adds only
    support mode 100644. ``allow_after`` is for a caller that already validated
    its durable journal: an exact already-after file may then settle without
    another write. This function does not create or authorize that journal.

    The caller must own a quiescent workspace and validate aggregate scope first.
    In-place writes may be partial on failure; preserve them for reconciliation.
    A renamed/replaced path cannot redirect the held-descriptor write to its
    replacement entry. Concurrent same-inode writers remain outside this proof.
    """
    adding = before_sha256 is None
    if (type(data) is not bytes or type(allow_after) is not bool
            or type(mode) is not str or mode not in {"100644", "100755"}
            or adding and (before_bytes is not None or mode != "100644")
            or not adding and (not _digest(before_sha256) or type(before_bytes) is not int
                or not 0 <= before_bytes <= 2**53 - 1)):
        raise _invalid()
    expected_mode = 0o644 if mode == "100644" else 0o755
    changes = [False]
    try:
        with _parent(root, relative, private=False, create=adding, changes=changes) as (parent, name, links):
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
            created = False
            if adding:
                try:
                    descriptor = _open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent)
                    changes[0] = created = True
                except FileExistsError:
                    if not allow_after:
                        raise
                    descriptor = _open(name, flags, dir_fd=parent)
            else:
                descriptor = _open(name, flags, dir_fd=parent)
            try:
                if not created:
                    initial = _observed(descriptor, parent, name,
                        maximum=max(before_bytes or 0, len(data)), mode=expected_mode)
                    _unchanged_directories(links)
                    if allow_after and initial == data:
                        return
                    if (adding or len(initial) != before_bytes
                            or hashlib.sha256(initial).hexdigest() != before_sha256):
                        raise _invalid()
                else:
                    _regular(os.fstat(descriptor), private=True, max_bytes=0)
                # The descriptor cannot be redirected by replacing its name.
                # Any attempted write/truncate is conservatively a possible effect.
                changes[0] = True
                os.lseek(descriptor, 0, os.SEEK_SET)
                offset = 0
                while offset < len(data):
                    written = _write(descriptor, data[offset:offset + _CHUNK])
                    if written <= 0:
                        raise _invalid(changed=True)
                    offset += written
                os.ftruncate(descriptor, len(data))
                if created:
                    os.fchmod(descriptor, expected_mode)
                os.fsync(descriptor)
                if _observed(descriptor, parent, name, maximum=len(data), mode=expected_mode) != data:
                    raise _invalid(changed=True)
                _unchanged_directories(links)
                os.fsync(parent)
            finally:
                os.close(descriptor)
    except (OSError, ValueError, TypeError, NotImplementedError):
        raise _invalid(changed=changes[0]) from None
    except TaskAlongError:
        if changes[0]:
            raise _invalid(changed=True) from None
        raise
