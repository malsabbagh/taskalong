"""Owned Git workspaces and deterministic, scope-bound candidate objects.

All code in this module is original to TaskAlong.  The database caller owns the
lease/fencing transaction and must persist each returned intent before dispatch.
The common-directory marker is a second, OS-serialized ownership boundary; it is
never an authority record supplied by a worker.
"""

from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any, Iterator

from .errors import TaskAlongError
from .paths import safe_relative

_OID = re.compile(r"[0-9a-f]{40}\Z")
_MAX_FILE_BYTES = 1024 * 1024
_MAX_CANDIDATE_BYTES = 8 * 1024 * 1024
_SCRATCH = ".taskalong-scratch"
_GIT_ENV_BLOCK = {
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_CONFIG",
    "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_EXTERNAL_DIFF",
    "GIT_DIFF_OPTS", "GIT_TEMPLATE_DIR", "GIT_SSH_COMMAND",
}


def _fail(code: str, message: str, *, conflict: bool = False) -> None:
    raise TaskAlongError(code, message, exit_code=4 if conflict else 3)


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _env(overrides: dict[str, str] | None = None) -> dict[str, str]:
    result = {k: v for k, v in os.environ.items() if k not in _GIT_ENV_BLOCK and not k.startswith("GIT_CONFIG_KEY_") and not k.startswith("GIT_CONFIG_VALUE_")}
    result.update({"LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
    if overrides:
        result.update(overrides)
    return result


def _git(path: str | Path, *args: str, data: bytes | None = None, env: dict[str, str] | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    command = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-C", str(path), *args]
    try:
        result = subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_env(env), timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        _fail("git_unavailable", "The bounded Git operation could not complete.")
    if len(result.stdout) > 32 * 1024 * 1024 or len(result.stderr) > 1024 * 1024:
        _fail("git_output_limit", "The repository exceeds the supported Git output bound.")
    if check and result.returncode:
        _fail("git_operation_failed", "The bounded Git operation failed; preserve the workspace for inspection.")
    return result


def git(path: str | Path, *args: str, binary: bool = False) -> str | bytes:
    """Core-only bounded Git observation with the same hook/argv discipline."""
    result = _git(path, *args)
    return result.stdout if binary else _text(result)


def _text(result: subprocess.CompletedProcess[bytes]) -> str:
    try:
        return result.stdout.decode("utf-8", "strict").strip()
    except UnicodeError:
        _fail("unsupported_git_path", "Git output must contain bounded UTF-8 paths.")


def _oid(value: str) -> str:
    if not isinstance(value, str) or not _OID.fullmatch(value):
        _fail("invalid_git_oid", "A full lowercase SHA-1 Git object identity is required.")
    return value


def _no_symlinks(path: Path) -> Path:
    absolute = path.absolute()
    for item in [*reversed(absolute.parents), absolute]:
        if item.is_symlink():
            _fail("symlink_path", "Repository and workspace control paths cannot contain symlinks.")
    return absolute


def _private_dir(path: Path) -> Path:
    _no_symlinks(path)
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
    except FileExistsError:
        pass
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        _fail("insecure_workspace_control", "Workspace control directories must be private and operator-owned.")
    return path


def _read_private(path: Path) -> dict[str, Any]:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        _fail("insecure_workspace_control", "The workspace ownership record could not be opened safely.")
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 1024 * 1024:
            _fail("insecure_workspace_control", "Workspace ownership records must be bounded private regular files.")
        payload = stream.read(1024 * 1024 + 1)
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result
    def reject_number(_):
        raise ValueError("noncanonical number")
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=unique_pairs, parse_float=reject_number, parse_constant=reject_number)
    except (ValueError, UnicodeError, RecursionError):
        _fail("workspace_marker_corrupt", "The workspace ownership record is corrupt; preserve it.")
    if not isinstance(value, dict) or len(payload) > 1024 * 1024:
        _fail("workspace_marker_corrupt", "The workspace ownership record is corrupt; preserve it.")
    return value


def _write_private(path: Path, value: dict[str, Any], *, exclusive: bool = False) -> None:
    payload = _json_bytes(value)
    if exclusive:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            _fail("workspace_marker_conflict", "An ownership record already exists for this workspace.", conflict=True)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    else:
        fd, temporary = tempfile.mkstemp(prefix=".marker-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _policy(path: Path, common_dir: Path) -> None:
    # Reading configuration is not executing a hook. Reject execution-capable
    # configuration before any worktree checkout or object operation.
    result = subprocess.run(["git", "-C", str(path), "config", "--null", "--list"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_env(), timeout=10, check=False)
    if result.returncode or len(result.stdout) > 1024 * 1024:
        _fail("repository_policy_unsupported", "Repository configuration could not be safely inspected.")
    for entry in result.stdout.split(b"\0"):
        if not entry:
            continue
        key_raw, _, value_raw = entry.partition(b"\n")
        key = key_raw.decode("utf-8", "replace").lower()
        value = value_raw.decode("utf-8", "replace").lower()
        if key.startswith("filter."):
            _fail("repository_policy_unsupported", "Configured Git filters need separate qualification before checkout.")
        if key in {"core.hookspath", "core.attributesfile"} and value:
            _fail("repository_policy_unsupported", "External hook and attribute paths need separate qualification.")
        if key == "core.fsmonitor":
            if value and value not in {"false", "0"}:
                _fail("repository_policy_unsupported", "Hooks, filters, external attributes, and fsmonitor configuration need separate qualification.")
        if key == "commit.gpgsign" and value not in {"false", "0", "no", "off"}:
            _fail("signing_policy_unsupported", "The repository requires signing; this candidate producer is not qualified to satisfy that policy.")
        if key in {"core.autocrlf", "core.safecrlf"} and value not in {"false", "0", "no", "off"}:
            _fail("repository_policy_unsupported", "Automatic worktree text conversion is not supported in the first slice.")
    hooks = common_dir / "hooks"
    if hooks.is_symlink():
        _fail("repository_policy_unsupported", "Symlinked Git hooks are unsupported.")
    if hooks.is_dir():
        for item in hooks.iterdir():
            if not item.name.endswith(".sample") and (item.is_symlink() or item.stat().st_mode & 0o111):
                _fail("repository_policy_unsupported", "Active repository hooks must be declared as independent verifier commands.")
    attributes = common_dir / "info" / "attributes"
    if attributes.exists() and attributes.read_bytes().strip():
        _fail("repository_policy_unsupported", "Private Git attributes need separate qualification.")


def _tree(path: Path, commit: str) -> dict[str, tuple[str, str]]:
    raw = _git(path, "ls-tree", "-rz", "--full-tree", _oid(commit)).stdout
    result: dict[str, tuple[str, str]] = {}
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        metadata, sep, name = entry.partition(b"\t")
        if not sep:
            _fail("unsupported_git_tree", "The Git tree entry cannot be interpreted safely.")
        mode, object_type, oid = metadata.decode("ascii").split(" ")
        try:
            relative = name.decode("utf-8", "strict")
        except UnicodeError:
            _fail("unsupported_git_path", "Git paths must be UTF-8.")
        if any(ord(char) < 32 or ord(char) == 127 for char in relative):
            _fail("unsupported_git_path", "Control characters in Git paths are unsupported.")
        if object_type != "blob" or mode not in {"100644", "100755"}:
            _fail("unsupported_git_tree", "Submodules and symlinks are unsupported in the first workspace slice.")
        if relative.endswith(".gitattributes"):
            attributes = _git(path, "cat-file", "blob", oid).stdout
            if any(token in attributes for token in (b"filter", b"working-tree-encoding", b"ident", b"eol", b"text")):
                _fail("repository_policy_unsupported", "Worktree-transforming attributes need separate qualification.")
        result[relative] = (mode, oid)
        if len(result) > 4096:
            _fail("repository_size_limit", "The first slice supports at most 4096 repository files.")
    return result


def inspect_repository(path: str | Path, *, require_clean: bool = True) -> dict[str, Any]:
    root = _no_symlinks(Path(path))
    if not root.is_dir():
        _fail("invalid_repository", "A local non-bare repository directory is required.")
    bare = _text(_git(root, "rev-parse", "--is-bare-repository"))
    if bare != "false":
        _fail("bare_repository_unsupported", "A non-bare primary checkout is required.")
    top = Path(_text(_git(root, "rev-parse", "--show-toplevel"))).resolve()
    if root.resolve() != top:
        _fail("repository_root_required", "Register the exact repository worktree root.")
    common = Path(_text(_git(root, "rev-parse", "--path-format=absolute", "--git-common-dir"))).resolve()
    _no_symlinks(common)
    object_format = _text(_git(root, "rev-parse", "--show-object-format"))
    if object_format != "sha1":
        _fail("unsupported_git_object_format", "Only SHA-1 Git repositories are qualified.")
    _policy(root, common)
    head = _oid(_text(_git(root, "rev-parse", "--verify", "HEAD^{commit}")))
    _tree(root, head)
    if require_clean and _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=matching").stdout:
        _fail("dirty_repository", "The registered primary checkout must be clean; no stash or reset is performed.")
    identity = _digest({"common_dir": str(common), "device": common.stat().st_dev, "inode": common.stat().st_ino})
    return {"path": str(top), "repository_path": str(top), "common_dir": str(common), "identity": identity, "repository_identity": identity, "object_format": object_format, "head": head}


@contextlib.contextmanager
def repository_guard(repository_or_common: str | Path | dict[str, Any], store_uuid: str) -> Iterator[dict[str, Any]]:
    """Lock the immutable common-dir path and bind it to one private store.

    The lock inode is retained forever. Expired DB leases never bypass this
    binding, and this function performs no takeover or destructive cleanup.
    """
    try:
        uuid.UUID(store_uuid)
    except (ValueError, TypeError, AttributeError):
        _fail("invalid_store_identity", "A valid state-store UUID is required.")
    if isinstance(repository_or_common, dict):
        repository = repository_or_common
    else:
        supplied = Path(repository_or_common)
        if (supplied / "objects").is_dir() and (supplied / "HEAD").is_file():
            repository = {"common_dir": str(supplied)}
        else:
            repository = inspect_repository(supplied, require_clean=False)
    common = _no_symlinks(Path(repository["common_dir"]))
    control = _private_dir(common / "taskalong")
    lock_path = control / "control.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(lock_path, flags, 0o600)
    except OSError:
        _fail("insecure_workspace_control", "The repository guard could not be opened safely.")
    try:
        lock_info = os.fstat(fd)
        if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.getuid() or lock_info.st_mode & 0o077:
            _fail("insecure_workspace_control", "The repository guard must be a private operator-owned file.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            _fail("repository_busy", "Another owner holds the repository allocation guard.", conflict=True)
        binding_path = control / "store.json"
        if binding_path.exists() or binding_path.is_symlink():
            binding = _read_private(binding_path)
            if binding != {"store_uuid": store_uuid, "version": 1}:
                _fail("repository_store_conflict", "This Git common directory belongs to another state store.", conflict=True)
        else:
            _write_private(binding_path, {"store_uuid": store_uuid, "version": 1}, exclusive=True)
        yield repository
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _uuid(value: str) -> str:
    try:
        return str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        _fail("invalid_workspace_identity", "A UUID is required for the run and workspace identity.")


class WorkspaceManager:
    """One operator-registered repository, no shared mutable worktree reuse."""

    def __init__(self, repository_path: str | Path, store_uuid: str):
        self.repository = inspect_repository(repository_path)
        self.store_uuid = _uuid(store_uuid)
        self.root = Path(self.repository["path"])
        self.control = Path(self.repository["common_dir"]) / "taskalong"

    def _marker(self, workspace_id: str) -> Path:
        return self.control / "workspaces" / (_uuid(workspace_id) + ".json")

    def prepare(self, run_id: str, workspace_path: str | Path, base_commit: str, *, generation: int = 1) -> dict[str, Any]:
        run_id = _uuid(run_id)
        _oid(base_commit)
        if type(generation) is not int or generation < 1:
            _fail("invalid_lease_generation", "A positive lease fencing generation is required.")
        target = _no_symlinks(Path(workspace_path))
        if target.is_relative_to(self.root) or self.root.is_relative_to(target) or target.is_relative_to(Path(self.repository["common_dir"])):
            _fail("workspace_path_conflict", "An owned workspace must be separate from the primary checkout and Git control directory.")
        branch = "taskalong/" + run_id
        with repository_guard(self.repository, self.store_uuid):
            inspect_repository(self.root)
            _tree(self.root, base_commit)
            if target.exists() or target.is_symlink():
                _fail("workspace_occupied", "The intended workspace path is already occupied.", conflict=True)
            existing = _git(self.root, "show-ref", "--verify", "--quiet", "refs/heads/" + branch, check=False)
            if existing.returncode == 0:
                _fail("branch_occupied", "The intended owned branch already exists.", conflict=True)
            return {"version": 1, "workspace_id": str(uuid.uuid4()), "run_id": run_id,
                    "repository_identity": self.repository["identity"], "repository_path": str(self.root),
                    "common_dir": self.repository["common_dir"], "store_uuid": self.store_uuid,
                    "path": str(target), "branch": branch, "base_commit": base_commit,
                    "initial_head": base_commit, "generation": generation, "lease_generation": generation,
                    "scratch_relative": _SCRATCH + "/", "state": "prepared"}

    def _same_owner(self, record: dict[str, Any], marker: dict[str, Any]) -> None:
        fields = ("version", "workspace_id", "run_id", "repository_identity", "repository_path", "common_dir", "store_uuid", "path", "branch", "base_commit", "initial_head", "generation", "lease_generation", "scratch_relative")
        if _json_bytes({field: record.get(field) for field in fields}) != _json_bytes({field: marker.get(field) for field in fields}) or record.get("store_uuid") != self.store_uuid or record.get("repository_identity") != self.repository["identity"]:
            _fail("workspace_ownership_conflict", "The workspace marker does not match this exact owner and fence.", conflict=True)

    def _validate_unlocked(self, record: dict[str, Any], generation: int | None = None, *, allow_prepared: bool = False) -> dict[str, Any]:
        marker_path = self._marker(record["workspace_id"])
        if not marker_path.exists():
            _fail("workspace_unowned", "The workspace has no owned marker; it cannot be adopted.", conflict=True)
        marker = _read_private(marker_path)
        self._same_owner(record, marker)
        _policy(self.root, Path(self.repository["common_dir"]))
        if generation is not None and (record["generation"] != generation or marker["generation"] != generation):
            _fail("stale_lease", "The workspace fence is stale.", conflict=True)
        if marker.get("state") not in ({"prepared", "owned"} if allow_prepared else {"owned"}):
            _fail("workspace_unreconciled", "The workspace allocation has not been reconciled.")
        target = _no_symlinks(Path(record["path"]))
        if not target.is_dir():
            _fail("workspace_missing", "The owned workspace is missing; no replacement is created.")
        git_file = target / ".git"
        info = git_file.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4096:
            _fail("workspace_identity_changed", "The owned worktree Git pointer is no longer a bounded regular file.", conflict=True)
        pointer = git_file.read_text(encoding="utf-8")
        if not pointer.startswith("gitdir: ") or "\n" in pointer.rstrip("\n"):
            _fail("workspace_identity_changed", "The owned worktree Git pointer is malformed.", conflict=True)
        git_dir = _no_symlinks(Path(pointer[len("gitdir: "):].strip()))
        if not git_dir.is_relative_to(Path(self.repository["common_dir"]) / "worktrees"):
            _fail("workspace_identity_changed", "The Git pointer escaped the registered linked-worktree control directory.", conflict=True)
        backlink = git_dir / "gitdir"
        if backlink.is_symlink() or not backlink.is_file() or Path(backlink.read_text(encoding="utf-8").strip()) != git_file:
            _fail("workspace_identity_changed", "The linked-worktree control pointer does not point back to its exact owned path.", conflict=True)
        common = _text(_git(target, "rev-parse", "--path-format=absolute", "--git-common-dir"))
        branch = _text(_git(target, "symbolic-ref", "--quiet", "--short", "HEAD"))
        if Path(common).resolve() != Path(self.repository["common_dir"]) or branch != record["branch"]:
            _fail("workspace_identity_changed", "The worktree no longer has the owned common directory and branch.", conflict=True)
        scratch = target / _SCRATCH
        if scratch.is_symlink() or (scratch.exists() and not scratch.is_dir()) or (not scratch.exists() and not (allow_prepared and marker.get("state") == "prepared")):
            _fail("workspace_scratch_changed", "The owned workspace scratch directory is missing or unsafe.")
        return marker

    def create(self, intent: dict[str, Any]) -> dict[str, Any]:
        with repository_guard(self.repository, self.store_uuid):
            marker_path = self._marker(intent["workspace_id"])
            _private_dir(marker_path.parent)
            if marker_path.exists() or marker_path.is_symlink():
                marker = _read_private(marker_path)
                self._same_owner(intent, marker)
                if Path(intent["path"]).exists():
                    marker = self._validate_unlocked(intent, allow_prepared=True)
                    _private_dir(Path(intent["path"]) / _SCRATCH)
                    marker["state"] = "owned"
                    _write_private(marker_path, marker)
                    return marker
                _fail("workspace_creation_uncertain", "An earlier allocation intent has no proven no-dispatch receipt; reconcile before retry.")
            if Path(intent["path"]).exists() or Path(intent["path"]).is_symlink():
                _fail("workspace_occupied", "The intended workspace path is occupied by unowned data.", conflict=True)
            if _git(self.root, "show-ref", "--verify", "--quiet", "refs/heads/" + intent["branch"], check=False).returncode == 0:
                _fail("branch_occupied", "The owned branch name is already occupied.", conflict=True)
            self._same_owner(intent, intent)
            _private_dir(Path(intent["path"]).parent)
            _write_private(marker_path, intent, exclusive=True)
            _git(self.root, "worktree", "add", "--no-track", "-b", intent["branch"], intent["path"], intent["base_commit"])
            _private_dir(Path(intent["path"]) / _SCRATCH)
            marker = self._validate_unlocked(intent, allow_prepared=True)
            if _text(_git(intent["path"], "rev-parse", "HEAD")) != intent["base_commit"]:
                _fail("workspace_base_changed", "The newly allocated worktree has an unexpected base.")
            marker["state"] = "owned"
            _write_private(marker_path, marker)
            return marker

    def reconcile(self, intent: dict[str, Any]) -> dict[str, Any]:
        with repository_guard(self.repository, self.store_uuid):
            marker = self._validate_unlocked(intent, allow_prepared=True)
            if marker["state"] == "prepared" and _text(_git(intent["path"], "rev-parse", "HEAD")) != intent["base_commit"]:
                _fail("workspace_creation_uncertain", "The pending worktree no longer matches its allocation base.")
            _private_dir(Path(intent["path"]) / _SCRATCH)
            marker["state"] = "owned"
            _write_private(self._marker(intent["workspace_id"]), marker)
            return marker

    def validate(self, record: dict[str, Any], generation: int | None = None) -> dict[str, Any]:
        with repository_guard(self.repository, self.store_uuid):
            return self._validate_unlocked(record, generation)

    def retirement_subject(self, record: dict[str, Any], generation: int) -> dict[str, Any]:
        """Observe the retained workspace without editing its marker or bytes.

        The caller has already established kernel-confirmed process cessation
        and holds every run operation guard. This observation does not grant a
        replacement owner access to the old worktree.
        """
        with repository_guard(self.repository, self.store_uuid):
            self._validate_unlocked(record, generation)
            return {"workspace_id": record["workspace_id"], "generation": generation,
                    "head_commit": _oid(_text(_git(record["path"], "rev-parse", "HEAD"))),
                    "branch": record["branch"]}

    def refence(self, record: dict[str, Any], generation: int) -> dict[str, Any]:
        """Advance only after the caller proved process cessation under its DB guard."""
        if type(generation) is not int or generation != record["generation"] + 1:
            _fail("stale_lease", "A reacquired workspace must advance the fence exactly once.", conflict=True)
        with repository_guard(self.repository, self.store_uuid):
            marker = self._validate_unlocked(record)
            marker["generation"] = marker["lease_generation"] = generation
            _write_private(self._marker(record["workspace_id"]), marker)
            return marker

    def _recovery_generation_unlocked(self, record: dict[str, Any], expected_generation: int, new_generation: int) -> dict[str, Any]:
        if (type(expected_generation) is not int or type(new_generation) is not int
                or record.get("generation") != expected_generation or new_generation != expected_generation + 1):
            _fail("stale_lease", "Recovery must name exactly one durable fence advancement.", conflict=True)
        marker = _read_private(self._marker(record["workspace_id"]))
        observed = marker.get("generation")
        if type(observed) is not int or observed not in {expected_generation, new_generation}:
            _fail("stale_lease", "The workspace has an unexpected generation; preserve it.", conflict=True)
        expected = {**record, "generation": observed, "lease_generation": observed}
        return self._validate_unlocked(expected, observed)

    def observe_generation(self, record: dict[str, Any], expected_generation: int, new_generation: int) -> dict[str, Any]:
        """Read only the exact old/new marker named by a durable reacquire intent."""
        with repository_guard(self.repository, self.store_uuid):
            return self._recovery_generation_unlocked(record, expected_generation, new_generation)

    def reconcile_generation(self, record: dict[str, Any], expected_generation: int, new_generation: int) -> dict[str, Any]:
        """Complete one known fence write after caller proves no worker dispatch."""
        with repository_guard(self.repository, self.store_uuid):
            marker = self._recovery_generation_unlocked(record, expected_generation, new_generation)
            if marker["generation"] == expected_generation:
                marker["generation"] = marker["lease_generation"] = new_generation
                _write_private(self._marker(record["workspace_id"]), marker)
            return marker

    def advance_generation(self, record: dict[str, Any], expected_generation: int, new_generation: int) -> dict[str, Any]:
        if record.get("generation") != expected_generation:
            _fail("stale_lease", "The supplied workspace fence is stale.", conflict=True)
        return self.refence(record, new_generation)

    def reacquire(self, record: dict[str, Any], new_generation: int) -> dict[str, Any]:
        return self.refence(record, new_generation)

    def _snapshot_unlocked(self, record: dict[str, Any], scope: dict[str, Any], expected_head: str | None) -> dict[str, Any]:
        self._validate_unlocked(record)
        target = Path(record["path"])
        head = _oid(_text(_git(target, "rev-parse", "HEAD")))
        if expected_head is not None and head != expected_head:
            _fail("worker_commit_detected", "Worker-created or foreign commits cannot be adopted as candidates.")
        baseline = _tree(target, record["base_commit"])
        allowed = [safe_relative(value, allow_directory=True) for value in scope["files"]]
        operations = set(scope["operations"])
        files: dict[str, dict[str, Any]] = {}
        total = 0
        file_count = 0
        directory_count = 0
        for directory, dirs, names in os.walk(target, followlinks=False):
            current = Path(directory)
            relative_dir = current.relative_to(target)
            directory_count += 1
            if directory_count > 4096 or len(relative_dir.parts) > 64:
                _fail("repository_size_limit", "The workspace directory count or depth exceeds the first-slice bound.")
            for name in list(dirs):
                item = current / name
                relative = item.relative_to(target).as_posix()
                if relative == _SCRATCH:
                    if item.is_symlink():
                        _fail("symlink_path", "The owned scratch directory cannot be replaced by a symlink.")
                    dirs.remove(name)
                elif item.is_symlink():
                    _fail("symlink_path", "Workspace directory symlinks are unsupported.")
            for name in names:
                relative = (relative_dir / name).as_posix()
                if relative == ".git":
                    continue
                item = current / name
                file_count += 1
                if file_count > 4096:
                    _fail("repository_size_limit", "The first slice supports at most 4096 workspace files.")
                info = item.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    _fail("unsupported_file_type", "Workspace candidates contain only ordinary unlinked regular files.")
                mode = "100755" if info.st_mode & 0o111 else "100644"
                if info.st_size > _MAX_FILE_BYTES:
                    _fail("candidate_size_limit", "A candidate file exceeds the first-slice byte limit.")
                payload = item.read_bytes()
                total += len(payload)
                if total > 32 * 1024 * 1024:
                    _fail("repository_size_limit", "The workspace exceeds the first-slice snapshot bound.")
                data_digest = hashlib.sha256(payload).hexdigest()
                original = baseline.get(relative)
                # hash-object without -w does not mutate the repository or invoke filters.
                blob_oid = _text(_git(target, "hash-object", "--stdin", data=payload))
                changed = original != (mode, blob_oid)
                if changed:
                    safe_relative(relative)
                    if not any(relative == entry or (entry.endswith("/") and relative.startswith(entry)) for entry in allowed):
                        _fail("scope_violation", "Actual workspace bytes include an undeclared path.")
                    operation = "modify" if original else "add"
                    if operation not in operations:
                        _fail("scope_violation", "The actual change operation is not permitted.")
                    if original and mode != original[0]:
                        _fail("file_mode_change_unsupported", "Executable mode changes need separate qualification.")
                    try:
                        payload.decode("utf-8", "strict")
                    except UnicodeError:
                        _fail("binary_change_unsupported", "Only UTF-8 text additions and modifications are supported.")
                    if b"\0" in payload:
                        _fail("binary_change_unsupported", "NUL-containing text changes are unsupported.")
                    if len(files) >= 256:
                        _fail("candidate_size_limit", "The first slice supports at most 256 changed files.")
                    # The durable candidate intent binds bytes by digest. It
                    # does not duplicate source as base64 in a control document.
                    files[relative] = {"path": relative, "mode": mode, "sha256": data_digest, "bytes": len(payload), "git_blob": blob_oid, "operation": operation}
        # Missing baseline paths cannot be smuggled in as renames or deletion.
        for relative in baseline:
            if not (target / relative).exists():
                _fail("delete_unsupported", "Deletion and rename changes are unsupported.")
        if sum(value["bytes"] for value in files.values()) > _MAX_CANDIDATE_BYTES:
            _fail("candidate_size_limit", "The candidate exceeds the aggregate byte limit.")
        manifest = [{key: item[key] for key in ("path", "operation", "mode", "sha256", "bytes")} for _, item in sorted(files.items())]
        # Manifest hashes bind bytes/modes including added and ignored files.
        diff = _git(target, "diff", "--no-ext-diff", "--no-textconv", "--binary", record["base_commit"], "--").stdout
        return {"head": head, "manifest": manifest, "content_digest": _digest(manifest), "changed_files": [{"path": item["path"], "operation": item["operation"]} for item in manifest], "files": [value for _, value in sorted(files.items())], "diff_sha256": hashlib.sha256(diff).hexdigest(), "diff_bytes": diff}

    def snapshot(self, record: dict[str, Any], scope: dict[str, Any], *, expected_head: str | None = None) -> dict[str, Any]:
        with repository_guard(self.repository, self.store_uuid):
            return self._snapshot_unlocked(record, scope, expected_head)

    def candidate_intent(self, record: dict[str, Any], scope: dict[str, Any], base_commit: str, timestamp: str, message: str = "TaskAlong candidate") -> dict[str, Any]:
        with repository_guard(self.repository, self.store_uuid):
            if _oid(base_commit) != record["base_commit"]:
                _fail("candidate_base_mismatch", "Candidate parent must equal the resolved task base.")
            snapshot = self._snapshot_unlocked(record, scope, record["initial_head"])
            if not snapshot["manifest"]:
                _fail("empty_candidate", "No actual scoped text change was produced.")
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", timestamp):
                _fail("invalid_candidate_timestamp", "The candidate requires a fixed UTC second timestamp.")
            if not isinstance(message, str) or not message or len(message.encode("utf-8")) > 4096 or "\0" in message:
                _fail("invalid_candidate_message", "The candidate commit message must be bounded text.")
            return {"version": 1, "kind": "candidate", "workspace": record, "scope": scope,
                    "parent": base_commit, "expected_old": record["initial_head"],
                    "timestamp": timestamp, "author_name": "TaskAlong", "author_email": "taskalong@localhost",
                    "message": message, "content_digest": snapshot["content_digest"], "files": snapshot["files"]}

    def freeze(self, intent: dict[str, Any]) -> dict[str, Any]:
        record = intent["workspace"]
        with repository_guard(self.repository, self.store_uuid):
            self._validate_unlocked(record)
            target = Path(record["path"])
            snapshot = self._snapshot_unlocked(record, intent["scope"], None)
            metadata_files = [{key: value for key, value in entry.items() if key != "data_b64"} for entry in intent["files"]]
            if snapshot["content_digest"] != intent["content_digest"] or _json_bytes(snapshot["files"]) != _json_bytes(metadata_files):
                _fail("candidate_content_changed", "Candidate bytes changed after the durable freeze intent.")
            metadata = {"GIT_AUTHOR_NAME": intent["author_name"], "GIT_AUTHOR_EMAIL": intent["author_email"],
                        "GIT_COMMITTER_NAME": intent["author_name"], "GIT_COMMITTER_EMAIL": intent["author_email"],
                        "GIT_AUTHOR_DATE": intent["timestamp"], "GIT_COMMITTER_DATE": intent["timestamp"]}
            with tempfile.TemporaryDirectory(prefix="candidate-", dir=self.control) as directory:
                metadata["GIT_INDEX_FILE"] = str(Path(directory) / "index")
                _git(target, "read-tree", intent["parent"], env=metadata)
                updates = bytearray()
                for entry in intent["files"]:
                    path = target / safe_relative(entry["path"])
                    try:
                        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                        with os.fdopen(descriptor, "rb") as source:
                            info = os.fstat(source.fileno())
                            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > _MAX_FILE_BYTES:
                                _fail("candidate_content_changed", "A candidate file changed type or exceeded its bound after intent capture.")
                            data = source.read(_MAX_FILE_BYTES + 1)
                    except OSError:
                        _fail("candidate_content_changed", "A candidate file became unavailable after intent capture.")
                    if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                        _fail("candidate_intent_corrupt", "The candidate intent content digest does not match its bytes.")
                    if "data_b64" in entry:
                        # Compatibility for an already-persisted private v1
                        # intent. Embedded bytes grant no recovery shortcut:
                        # they must equal the exact current, digest-bound file.
                        try:
                            legacy_data = base64.b64decode(entry["data_b64"], validate=True)
                        except (ValueError, TypeError):
                            _fail("candidate_intent_corrupt", "Legacy candidate bytes are malformed.")
                        if legacy_data != data:
                            _fail("candidate_intent_corrupt", "Legacy candidate bytes disagree with the current immutable intent subject.")
                    oid = _text(_git(target, "hash-object", "-w", "--stdin", data=data))
                    if oid != entry["git_blob"]:
                        _fail("candidate_intent_corrupt", "The candidate intent does not match its Git blob identity.")
                    updates.extend((entry["mode"] + " " + oid + "\t" + entry["path"]).encode("utf-8") + b"\0")
                _git(target, "update-index", "-z", "--index-info", data=bytes(updates), env=metadata)
                tree = _oid(_text(_git(target, "write-tree", env=metadata)))
                commit = _oid(_text(_git(target, "commit-tree", tree, "-p", intent["parent"], data=(intent["message"] + "\n").encode("utf-8"), env=metadata)))
            current = _oid(_text(_git(target, "rev-parse", "HEAD")))
            if current not in {intent["expected_old"], commit}:
                _fail("worker_commit_detected", "The owned branch moved outside the candidate compare-and-swap intent.")
            if current != commit:
                _git(target, "update-ref", "refs/heads/" + record["branch"], commit, intent["expected_old"])
            _git(target, "read-tree", commit)
            diff = _git(target, "diff", "--no-ext-diff", "--no-textconv", "--binary", intent["parent"], commit, "--").stdout
            return {"commit": commit, "tree": tree, "base_commit": intent["parent"], "diff_sha256": hashlib.sha256(diff).hexdigest()}

    def assert_candidate(self, record: dict[str, Any], candidate: dict[str, Any], scope: dict[str, Any]) -> dict[str, Any]:
        with repository_guard(self.repository, self.store_uuid):
            snapshot = self._snapshot_unlocked(record, scope, candidate["commit"])
            tree = _text(_git(record["path"], "rev-parse", candidate["commit"] + "^{tree}"))
            diff = _git(record["path"], "diff", "--no-ext-diff", "--no-textconv", "--binary", candidate["base_commit"], candidate["commit"], "--").stdout
            if tree != candidate["tree"] or hashlib.sha256(diff).hexdigest() != candidate["diff_sha256"]:
                _fail("candidate_subject_changed", "The candidate object or immutable diff identity changed.")
            # Compare the complete current tree byte-for-byte against the commit.
            expected = _tree(Path(record["path"]), candidate["commit"])
            for path, (mode, oid) in expected.items():
                target = Path(record["path"]) / path
                if not target.is_file() or target.is_symlink():
                    _fail("candidate_subject_changed", "The candidate worktree changed during verification.")
                actual_mode = "100755" if target.stat().st_mode & 0o111 else "100644"
                if actual_mode != mode or _text(_git(record["path"], "hash-object", "--stdin", data=target.read_bytes())) != oid:
                    _fail("candidate_subject_changed", "The candidate worktree changed during verification.")
            baseline = _tree(Path(record["path"]), candidate["base_commit"])
            if set(item["path"] for item in snapshot["manifest"]) != {path for path in expected if baseline.get(path) != expected[path]}:
                _fail("candidate_subject_changed", "Unexpected candidate paths appeared during verification.")
            return snapshot

    def diff_bytes(self, record: dict[str, Any], candidate: dict[str, Any]) -> bytes:
        self.validate(record)
        return _git(record["path"], "diff", "--no-ext-diff", "--no-textconv", "--binary", candidate["base_commit"], candidate["commit"], "--").stdout
