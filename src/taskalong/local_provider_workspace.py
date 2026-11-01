"""Fresh controller-owned Git snapshots for experimental provider workspaces.

This is a selected-file snapshot, never a copy of the source repository or its
Git/configuration directories. A receipt binds current files and metadata, not
native client trust, account state, dispatch, or permission to apply a proposal.
The caller must independently verify the original repository before dispatch.
"""
from __future__ import annotations

from contextlib import contextmanager
from functools import wraps
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import time

from .artifact_io import _parent, _unchanged_directories, read_regular, stage_regular
from .errors import TaskAlongError
from .local_provider_tasks import MAX_FILE_BYTES, validate_plan
from .process import ProcessBoundaryError, fingerprint, run_bounded
from .validation import canonical_bytes, digest

_FORMAT = "configured-provider-workspace/1"
_BRANCH = "taskalong-snapshot"
_MAX_ENTRIES = 1024
_MAX_INVENTORY_BYTES = 4 * 1048576
_clock = time.monotonic
_FIELDS = {"format", "plan_digest", "intent_digest", "source_base_commit", "source_base_tree",
           "workspace", "control_root", "git", "head", "tree", "files", "inventory", "digest"}
_OPTIONS = ("-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
            "-c", "core.attributesFile=/dev/null", "-c", "core.excludesFile=/dev/null",
            "-c", "core.autocrlf=false", "-c", "core.safecrlf=false",
            "-c", "core.untrackedCache=false", "-c", "core.splitIndex=false",
            "-c", "gc.auto=0", "-c", "maintenance.auto=false",
            "-c", "commit.gpgSign=false", "-c", "protocol.allow=never")


def _close_all_once(descriptors):
    owned = tuple(descriptors)
    descriptors.clear()
    primary, cleanup = sys.exc_info()[1], None
    for fd in reversed(owned):
        try:
            os.close(fd)
        except OSError as exc:
            cleanup = cleanup or exc
    if cleanup is not None:
        if primary is not None:
            raise primary from cleanup
        raise cleanup


def _fail():
    raise TaskAlongError("provider_workspace_invalid",
        "The owned snapshot workspace is unavailable, changed, unsafe, or outside its finite bounds. Preserve partial local files; no provider request is authorized.",
        exit_code=3, effect_outcome="not_sent")


def _path(value):
    if not isinstance(value, (str, Path)):
        _fail()
    path = Path(value)
    try:
        literal = str(path)
        literal.encode("utf-8")
        if (not path.is_absolute() or ".." in path.parts or not literal.isprintable()
                or len(literal.encode("utf-8")) > 4096 or type(value) is str and literal != value):
            _fail()
    except (UnicodeError, ValueError):
        _fail()
    return path


def _identity(info, *, timestamps=False):
    result = {"device": str(info.st_dev), "inode": str(info.st_ino), "owner": info.st_uid,
              "mode": stat.S_IMODE(info.st_mode)}
    if timestamps:
        result.update(mtime_ns=str(info.st_mtime_ns), ctime_ns=str(info.st_ctime_ns))
    return result


@contextmanager
def _roots(workspace, control):
    with _parent(workspace, "owned-workspace-guard", private=True) as (work_fd, _, work_links), \
            _parent(control, "owned-workspace-guard", private=True) as (control_fd, _, control_links):
        actual_work, actual_control = workspace.resolve(strict=True), control.resolve(strict=True)
        if actual_work.is_relative_to(actual_control) or actual_control.is_relative_to(actual_work):
            _fail()
        yield work_fd, control_fd
        _unchanged_directories(work_links)
        _unchanged_directories(control_links)


def _git_identity():
    # No task or ambient PATH chooses a launcher. This does not install Git.
    executable = shutil.which("git", path=os.defpath)
    if executable is None:
        _fail()
    path = Path(executable).resolve(strict=True)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
        _fail()
    return {"path": str(path), "sha256": fingerprint(path), "identity": _identity(info, timestamps=True)}


def _env(control):
    # Build from scratch: no inherited GIT_*, loaders, credentials, HOME or config.
    return {"PATH": os.defpath, "HOME": str(control), "XDG_CONFIG_HOME": str(control),
            "LC_ALL": "C", "TZ": "UTC", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull, "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_ATTR_NOSYSTEM": "1",
            "GIT_LITERAL_PATHSPECS": "1", "GIT_ALLOW_PROTOCOL": "",
            "GIT_AUTHOR_NAME": "TaskAlong Snapshot", "GIT_AUTHOR_EMAIL": "snapshot@example.invalid",
            "GIT_COMMITTER_NAME": "TaskAlong Snapshot", "GIT_COMMITTER_EMAIL": "snapshot@example.invalid",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+0000", "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+0000"}


class _GitOwner:
    """Each fixed local operation starts from the preceding closed inventory."""

    def __init__(self, executable, workspace, control, work_fd, *, deadline):
        self.executable, self.workspace, self.control, self.work_fd = executable, workspace, control, work_fd
        self.inventory = _inventory(work_fd, private=False)
        self.root_state = _identity(os.fstat(work_fd), timestamps=True)
        self.deadline = deadline

    def __call__(self, *args, data=b""):
        remaining = self.deadline - _clock()
        if remaining <= 0:
            _fail()
        executable, workspace = self.executable, self.workspace
        with _parent(workspace, "owned-workspace-guard", private=True) as (fd, _, links):
            if (canonical_bytes(self.inventory) != canonical_bytes(_inventory(self.work_fd, private=False))
                    or self.root_state != _identity(os.fstat(fd), timestamps=True)
                    or executable["sha256"] != fingerprint(executable["path"])):
                _fail()
            remaining = self.deadline - _clock()
            if remaining <= 0:
                _fail()
            result = run_bounded([executable["path"], *_OPTIONS,
                "--git-dir=" + str(workspace / ".git"), "--work-tree=" + str(workspace), *args],
                cwd=workspace, stdin=data, env=_env(self.control), timeout_seconds=min(15, remaining), max_output_bytes=1048576)
            if (_clock() > self.deadline or result.exit_code != 0 or result.timed_out or result.cancelled or result.output_limited
                    or result.protocol_error
                    or result.receipt.executable_sha256 != executable["sha256"]
                    or fingerprint(executable["path"]) != executable["sha256"]):
                _fail()
            _unchanged_directories(links)
            self.inventory = _inventory(self.work_fd, private=False)
            self.root_state = _identity(os.fstat(self.work_fd), timestamps=True)
            return result.stdout


def _oid(raw):
    value = raw.decode("ascii").strip()
    if re.fullmatch(r"[a-f0-9]{40}", value) is None:
        _fail()
    return value


def _selected(plan):
    return {path: (role, snapshot) for role in ("read_context", "writable_outputs")
            for path, snapshot in plan[role].items()}


def _inventory(root_fd, *, private=True):
    """Observe all entries through held descriptors, refusing aliases and extras."""
    entries, total = {}, 0
    root_state = _identity(os.fstat(root_fd), timestamps=True)
    def walk(fd, prefix, depth):
        nonlocal total
        if depth > 128:
            _fail()
        for name in sorted(os.listdir(fd)):
            relative = prefix + name
            if (len(entries) >= _MAX_ENTRIES or not name.isprintable()
                    or len(relative.encode("utf-8")) > 4096):
                _fail()
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if before.st_uid != os.getuid() or private and before.st_mode & 0o077:
                _fail()
            if stat.S_ISDIR(before.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    if _identity(os.fstat(child), timestamps=True) != _identity(before, timestamps=True):
                        _fail()
                    entries[relative] = {"kind": "directory", **_identity(before, timestamps=True)}
                    walk(child, relative + "/", depth + 1)
                    if (_identity(before, timestamps=True) != _identity(os.fstat(child), timestamps=True)
                            or _identity(before, timestamps=True) != _identity(os.stat(name, dir_fd=fd, follow_symlinks=False), timestamps=True)):
                        _fail()
                finally:
                    os.close(child)
            elif stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 1048576:
                file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                try:
                    held = os.fstat(file_fd)
                    if _identity(held, timestamps=True) != _identity(before, timestamps=True):
                        _fail()
                    chunks, size = [], 0
                    while True:
                        chunk = os.read(file_fd, 65536)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > before.st_size or total + size > _MAX_INVENTORY_BYTES:
                            _fail()
                        chunks.append(chunk)
                    after = os.fstat(file_fd)
                    entry = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if (size != before.st_size or after.st_size != size or after.st_nlink != 1 or entry.st_nlink != 1
                            or _identity(before, timestamps=True) != _identity(after, timestamps=True)
                            or _identity(after, timestamps=True) != _identity(entry, timestamps=True)):
                        _fail()
                    total += size
                    entries[relative] = {"kind": "file", "bytes": size,
                        "sha256": hashlib.sha256(b"".join(chunks)).hexdigest(), **_identity(after, timestamps=True)}
                finally:
                    os.close(file_fd)
            else:
                _fail()
    walk(root_fd, "", 0)
    # Hashing later files must not bless an earlier file changed during the scan.
    # This collective metadata/name fence detects persistent changes; it is not
    # an atomic filesystem snapshot or isolation from the operator account.
    children = {}
    for path in entries:
        parent, _, name = path.rpartition("/")
        children.setdefault(parent, set()).add(name)
    def fence(fd, prefix, depth):
        if depth > 128 or set(os.listdir(fd)) != children.get(prefix, set()):
            _fail()
        for name in sorted(children.get(prefix, set())):
            path = prefix + "/" + name if prefix else name
            item = entries[path]
            expected = {key: item[key] for key in _identity(os.fstat(fd), timestamps=True)}
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if _identity(info, timestamps=True) != expected:
                _fail()
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if item["kind"] == "directory":
                flags |= os.O_DIRECTORY
            child = os.open(name, flags, dir_fd=fd)
            try:
                held = os.fstat(child)
                if (_identity(held, timestamps=True) != expected or held.st_nlink != info.st_nlink
                        or item["kind"] == "file" and (held.st_nlink != 1 or held.st_size != item["bytes"])):
                    _fail()
                if item["kind"] == "directory":
                    fence(child, path, depth + 1)
                if (_identity(os.fstat(child), timestamps=True) != expected
                        or _identity(os.stat(name, dir_fd=fd, follow_symlinks=False), timestamps=True) != expected):
                    _fail()
            finally:
                os.close(child)
    fence(root_fd, "", 0)
    if _identity(os.fstat(root_fd), timestamps=True) != root_state:
        _fail()
    return entries


def _files(plan, workspace, inventory):
    selected = _selected(plan)
    expected_files = {path for path, (_, snapshot) in selected.items() if snapshot is not None}
    expected_dirs = {str(parent) for path in expected_files for parent in Path(path).parents if str(parent) != "."}
    actual_files = {path for path, item in inventory.items() if item["kind"] == "file" and not path.startswith(".git/")}
    actual_dirs = {path for path, item in inventory.items() if item["kind"] == "directory" and path != ".git" and not path.startswith(".git/")}
    if actual_files != expected_files or actual_dirs != expected_dirs or inventory.get(".git", {}).get("kind") != "directory":
        _fail()
    files = {}
    for path, (role, snapshot) in sorted(selected.items()):
        if snapshot is None:
            if path in inventory:
                _fail()
            files[path] = {"role": role, "snapshot": None}
        else:
            mode = 0o500 if snapshot["git_mode"] == "100755" else 0o400
            raw = read_regular(workspace, path, max_bytes=MAX_FILE_BYTES, expected_sha256=snapshot["sha256"],
                               expected_bytes=snapshot["bytes"], expected_mode=mode, private=True)
            files[path] = {"role": role, "snapshot": {"sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw), "git_mode": snapshot["git_mode"], "identity": inventory[path]}}
    return files


def _message(plan):
    return ("TaskAlong selected source snapshot\n\nPlan " + plan["digest"] + "\n").encode()


def _tree_bytes(plan):
    rows = []
    for path, (_, snapshot) in sorted(_selected(plan).items()):
        if snapshot is not None:
            raw = snapshot["content"].encode("utf-8")
            oid = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            rows.append(snapshot["git_mode"].encode() + b" blob " + oid.encode() + b"\t" + path.encode() + b"\0")
    return b"".join(rows)


def _observe(plan, workspace, control, work_fd, control_fd, executable, *, deadline):
    before = _inventory(work_fd)
    files = _files(plan, workspace, before)
    git = _GitOwner(executable, workspace, control, work_fd, deadline=deadline)
    head = _oid(git("rev-parse", "--verify", "HEAD^{commit}"))
    tree = _oid(git("rev-parse", "--verify", "HEAD^{tree}"))
    commit = ("tree " + tree + "\nauthor TaskAlong Snapshot <snapshot@example.invalid> 946684800 +0000\n"
              "committer TaskAlong Snapshot <snapshot@example.invalid> 946684800 +0000\n\n").encode() + _message(plan)
    if (git("cat-file", "commit", "HEAD") != commit
            or git("symbolic-ref", "HEAD").strip() != ("refs/heads/" + _BRANCH).encode()
            or git("ls-tree", "-r", "-z", "--full-tree", "HEAD") != _tree_bytes(plan)
            or canonical_bytes(before) != canonical_bytes(_inventory(work_fd))):
        _fail()
    return {"format": _FORMAT, "plan_digest": plan["digest"], "intent_digest": plan["intent_digest"],
            "source_base_commit": plan["base_commit"], "source_base_tree": plan["base_tree"],
            "workspace": {"path": str(workspace), "identity": _identity(os.fstat(work_fd), timestamps=True)},
            "control_root": {"path": str(control), "identity": _identity(os.fstat(control_fd))},
            "git": executable, "head": head, "tree": tree, "files": files, "inventory": before}


def _freeze(workspace, work_fd, initial):
    for path, item in sorted(initial.items(), key=lambda pair: pair[0].count("/"), reverse=True):
        if item["kind"] != "directory" and not path.startswith(".git/"):
            continue
        mode = 0o500 if item["kind"] == "directory" else 0o400
        # Git metadata is deliberately outside safe_relative's public task scope.
        # Traverse only entries from the just-observed inventory, with no links.
        fds, links = [os.dup(work_fd)], []
        try:
            parts = path.split("/")
            for name in parts[:-1]:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1])
                links.append((fds[-1], name, child, _identity(os.fstat(child), timestamps=True)))
                fds.append(child)
            name = parts[-1]
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if item["kind"] == "directory":
                flags |= os.O_DIRECTORY
            target = os.open(name, flags, dir_fd=fds[-1])
            try:
                info = os.fstat(target)
                if _identity(info, timestamps=True) != {key: item[key] for key in _identity(info, timestamps=True)}:
                    _fail()
                os.fchmod(target, mode)
                if _identity(os.fstat(target), timestamps=True) != _identity(os.stat(name, dir_fd=fds[-1], follow_symlinks=False), timestamps=True):
                    _fail()
            finally:
                os.close(target)
            for parent, name, child, identity in links:
                if (identity != _identity(os.fstat(child), timestamps=True)
                        or identity != _identity(os.stat(name, dir_fd=parent, follow_symlinks=False), timestamps=True)):
                    _fail()
        finally:
            _close_all_once(fds)
    os.fchmod(work_fd, 0o500)
    frozen = _inventory(work_fd)
    def stable(entries):
        return {path: {key: value for key, value in item.items() if key not in {"mode", "ctime_ns"}}
                for path, item in entries.items()}
    if canonical_bytes(stable(initial)) != canonical_bytes(stable(frozen)):
        _fail()


def _safe(method):
    @wraps(method)
    def call(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except (OSError, ValueError, TypeError, UnicodeError, ProcessBoundaryError, KeyError):
            _fail()
    return call


@_safe
def prepare_owned_workspace(plan, *, workspace, control_root, remaining_seconds=120):
    """Materialize only selected snapshots in an existing empty private directory."""
    validate_plan(plan)
    if type(remaining_seconds) not in (int, float) or not 0 < remaining_seconds <= 1440:
        _fail()
    deadline = _clock() + min(120, remaining_seconds)
    workspace, control = _path(workspace), _path(control_root)
    with _roots(workspace, control) as (work_fd, control_fd):
        if os.listdir(work_fd) or stat.S_IMODE(os.fstat(work_fd).st_mode) != 0o700:
            _fail()
        executable = _git_identity()
        for path, (_, snapshot) in sorted(_selected(plan).items()):
            if snapshot is not None:
                stage_regular(workspace, path, snapshot["content"].encode(), expected_sha256=snapshot["sha256"])
                if snapshot["git_mode"] == "100755":
                    with _parent(workspace, path, private=True) as (fd, name, links):
                        target = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                        try:
                            info = os.fstat(target)
                            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o400
                                    or info.st_size != snapshot["bytes"]):
                                _fail()
                            os.fchmod(target, 0o500)
                            if _identity(os.fstat(target), timestamps=True) != _identity(os.stat(name, dir_fd=fd, follow_symlinks=False), timestamps=True):
                                _fail()
                            _unchanged_directories(links)
                        finally:
                            os.close(target)
        git = _GitOwner(executable, workspace, control, work_fd, deadline=deadline)
        git("init", "--template=", "--initial-branch=" + _BRANCH, "--object-format=sha1")
        snapshots = [(path, snapshot) for path, (_, snapshot) in sorted(_selected(plan).items()) if snapshot is not None]
        index = []
        if snapshots:
            hashes = git("hash-object", "--no-filters", "-w", "--stdin-paths",
                         data=b"".join(path.encode() + b"\n" for path, _ in snapshots)).splitlines()
            if len(hashes) != len(snapshots):
                _fail()
            for (path, snapshot), raw_oid in zip(snapshots, hashes):
                oid = _oid(raw_oid)
                raw = snapshot["content"].encode()
                if oid != hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest():
                    _fail()
                index.append(snapshot["git_mode"].encode() + b" " + oid.encode() + b"\t" + path.encode() + b"\0")
        git("update-index", "-z", "--index-info", data=b"".join(index))
        tree = _oid(git("write-tree"))
        head = _oid(git("commit-tree", tree, data=_message(plan)))
        git("update-ref", "refs/heads/" + _BRANCH, head)
        # Freeze private metadata and source copies; no native tool write is needed.
        initial = _inventory(work_fd, private=False)
        if (canonical_bytes(initial) != canonical_bytes(git.inventory)
                or _identity(os.fstat(work_fd), timestamps=True) != git.root_state):
            _fail()
        _freeze(workspace, work_fd, initial)
        receipt = _observe(plan, workspace, control, work_fd, control_fd, executable, deadline=deadline)
        receipt["digest"] = digest(receipt)
        canonical_bytes(receipt)
        return receipt


@_safe
def verify_owned_workspace(plan, *, workspace, receipt, remaining_seconds=120):
    """Recheck the exact current snapshot and closed Git metadata before dispatch."""
    validate_plan(plan)
    if type(remaining_seconds) not in (int, float) or not 0 < remaining_seconds <= 1440:
        _fail()
    deadline = _clock() + min(120, remaining_seconds)
    if (type(receipt) is not dict or set(receipt) != _FIELDS or receipt.get("format") != _FORMAT
            or receipt.get("digest") != digest(receipt)):
        _fail()
    workspace, control = _path(workspace), _path(receipt["control_root"]["path"])
    executable = _git_identity()
    if (receipt["plan_digest"] != plan["digest"] or receipt["intent_digest"] != plan["intent_digest"]
            or receipt["source_base_commit"] != plan["base_commit"] or receipt["source_base_tree"] != plan["base_tree"]
            or receipt["workspace"]["path"] != str(workspace)
            or canonical_bytes(executable) != canonical_bytes(receipt["git"])):
        _fail()
    with _roots(workspace, control) as (work_fd, control_fd):
        # Check the previously closed inventory before allowing Git to interpret it.
        if (canonical_bytes(_inventory(work_fd)) != canonical_bytes(receipt["inventory"])
                or canonical_bytes(_identity(os.fstat(work_fd), timestamps=True)) != canonical_bytes(receipt["workspace"]["identity"])
                or canonical_bytes(_identity(os.fstat(control_fd))) != canonical_bytes(receipt["control_root"]["identity"])):
            _fail()
        fresh = _observe(plan, workspace, control, work_fd, control_fd, executable, deadline=deadline)
        fresh["digest"] = digest(fresh)
        if canonical_bytes(fresh) != canonical_bytes(receipt):
            _fail()
