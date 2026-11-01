"""Observed, scope-bound task plans, without dispatch or application authority.

Read-only context never implicitly grants edit permission. Plan integrity is not
an authorization token. The owner supplies the registered repository again when
rechecking a plan; no untrusted document chooses a filesystem root.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re

from .artifact_io import read_regular, require_absent
from .errors import TaskAlongError
from .paths import contained_path
from .supervised_pilot import _path
from .validation import canonical_bytes, digest, screen_sensitive

FORMAT = "configured-provider-task-plan/1"
ARTIFACT_FORMATS = frozenset({"file-replacements/1", "unified-diff/1"})
MAX_FILE_BYTES = 262144
MAX_SNAPSHOT_BYTES = 524288
_FIELDS = {"format", "repository_identity", "base_commit", "base_tree", "task", "provider",
           "backend", "model", "reasoning_effort", "context_policy", "artifact_format",
           "read_context", "writable_outputs", "snapshot_provenance",
           "manual_application_required", "automatic_retry_allowed", "intent_digest", "digest"}


def _fail(code, message):
    raise TaskAlongError(code, message, exit_code=3, effect_outcome="not_sent")


def _text(value, name, maximum=256):
    try:
        size = len(value.encode("utf-8")) if type(value) is str else maximum + 1
    except UnicodeError:
        size = maximum + 1
    if (type(value) is not str or not value.strip() or size > maximum
            or any(ord(c) < 32 and c not in "\n\t" or ord(c) == 127 for c in value)):
        _fail("provider_task_invalid", f"{name} must be explicit bounded text.")


def _paths(values):
    if type(values) not in (list, tuple) or len(values) > 32:
        _fail("provider_task_scope_invalid", "Select at most 32 literal paths for each role.")
    for value in values:
        try:
            _path(value)
        except UnicodeError:
            _fail("provider_task_scope_invalid", "Scope paths must be bounded supported Unicode text.")
    return sorted(values)


def _scope(read_paths, writable_paths):
    reads, writes = _paths(read_paths), _paths(writable_paths)
    if not writes:
        _fail("provider_task_outputs_missing", "Declare writable output paths, including new files, before dispatch.")
    folded = [p.casefold() for p in reads + writes]
    if len(set(folded)) != len(folded) or any(a.startswith(b + "/") for a in folded for b in folded if a != b):
        _fail("provider_task_scope_alias", "A path has one role; duplicate, case and ancestor aliases are forbidden.")
    return reads, writes


def _repository(repository):
    """Read metadata without the legacy workspace's whole-tree qualification.

    Unselected files, assets and submodules are not task inputs. Commands use
    the existing no-hook/no-fsmonitor/no-prompt Git boundary; quiet checks never
    invoke external diff or text conversion. No registration/ownership is made.
    """
    from .workspace import _git, _no_symlinks, git
    root = _no_symlinks(Path(repository))
    if not root.is_dir() or git(root, "rev-parse", "--is-bare-repository") != "false":
        _fail("provider_task_repository_invalid", "Select a non-bare worktree root.")
    if root.resolve() != Path(git(root, "rev-parse", "--show-toplevel")).resolve():
        _fail("provider_task_repository_invalid", "Select the exact worktree root.")
    if git(root, "rev-parse", "--show-object-format") != "sha1":
        _fail("provider_task_repository_invalid", "This task-plan version supports SHA-1 repositories.")
    common = _no_symlinks(Path(git(root, "rev-parse", "--path-format=absolute", "--git-common-dir")))
    head = git(root, "rev-parse", "--verify", "HEAD^{commit}")
    result = _git(root, "diff-index", "--quiet", "--no-ext-diff", "--no-textconv",
                  "--ignore-submodules=all", head, "--", check=False)
    if result.returncode != 0:
        _fail("provider_task_repository_dirty", "Tracked changes must be reconciled before planning; no reset is performed.")
    identity = digest({"common_dir": str(common), "device": common.stat().st_dev, "inode": common.stat().st_ino})
    return {"path": str(root.resolve()), "head": head, "identity": identity}


def _snapshot(root, commit, relative, *, writable):
    from .workspace import git
    path = contained_path(root, relative)
    raw = git(root, "ls-tree", "-z", commit, "--", ":(literal)" + relative, binary=True)
    if not raw:
        if not writable or path.exists() or path.is_symlink():
            _fail("provider_task_snapshot_missing", "Read inputs must be tracked; new outputs must actually be absent.")
        require_absent(root, relative)
        return None
    records = raw.split(b"\0")
    if len(records) != 2 or records[-1]:
        _fail("provider_task_snapshot_invalid", "A selected path must name one Git blob.")
    header, name = records[0].split(b"\t", 1)
    mode, kind, oid = header.decode("ascii").split(" ")
    if name.decode("utf-8") != relative or kind != "blob" or mode not in {"100644", "100755"}:
        _fail("provider_task_snapshot_invalid", "Only regular tracked text blobs are supported.")
    size = int(git(root, "cat-file", "-s", oid))
    if not 0 <= size <= MAX_FILE_BYTES:
        _fail("provider_task_snapshot_limit", "A selected blob exceeds the bounded source snapshot limit.")
    data = git(root, "cat-file", "blob", oid, binary=True)
    if len(data) != size or hashlib.sha1(b"blob " + str(size).encode("ascii") + b"\0" + data).hexdigest() != oid:
        _fail("provider_task_snapshot_changed", "Git blob size changed during observation.")
    sha = hashlib.sha256(data).hexdigest()
    actual = read_regular(root, relative, max_bytes=MAX_FILE_BYTES, expected_sha256=sha, expected_bytes=size,
                          expected_mode=int(mode, 8) & 0o7777)
    try:
        text = actual.decode("utf-8")
    except UnicodeError:
        _fail("provider_task_snapshot_invalid", "Snapshots must be UTF-8 text.")
    if any(ord(c) < 32 and c not in "\n\t" or ord(c) == 127 for c in text):
        _fail("provider_task_snapshot_invalid", "Binary/control content is not a text snapshot.")
    return {"content": text, "sha256": sha, "bytes": size, "git_blob": oid, "git_mode": mode}


def _intent(plan):
    # Transport format and budget changes cannot manufacture a new task identity.
    return digest({key: plan[key] for key in ("repository_identity", "base_commit", "task", "provider",
        "backend", "model", "reasoning_effort", "context_policy", "read_context", "writable_outputs")})


def prepare_task(repository, *, base_commit, task, provider, model, reasoning_effort,
                 writable_paths, read_paths=(), backend=None, context_policy="include",
                 artifact_format="file-replacements/1"):
    """Observe clean selected Git text and explicit outputs; perform no writes."""
    if os.name != "posix":
        _fail("provider_task_observer_unsupported", "The current owned Git observer supports POSIX hosts.")
    if type(base_commit) is not str or not re.fullmatch(r"[a-f0-9]{40}", base_commit):
        _fail("provider_task_base_invalid", "An exact existing commit is required.")
    _text(task, "task", 16384)
    for name, value in (("provider", provider), ("model", model), ("reasoning_effort", reasoning_effort)):
        _text(value, name)
    if backend is not None:
        _text(backend, "backend")
    if type(context_policy) is not str or context_policy not in {"include", "exclude", "native-only"}:
        _fail("provider_task_invalid", "Select an explicit context policy.")
    if type(artifact_format) is not str or artifact_format not in ARTIFACT_FORMATS:
        _fail("provider_task_artifact_unsupported", "Select a versioned proposal representation.")
    reads, writes = _scope(read_paths, writable_paths)
    from .workspace import git
    observed = _repository(repository)
    if observed["head"] != base_commit:
        _fail("provider_task_base_changed", "The selected checkout differs from the intended base commit.")
    root = Path(observed["path"])
    before = {p: _snapshot(root, base_commit, p, writable=False) for p in reads}
    outputs = {p: _snapshot(root, base_commit, p, writable=True) for p in writes}
    if sum(x["bytes"] for x in [*before.values(), *outputs.values()] if x is not None) > MAX_SNAPSHOT_BYTES:
        _fail("provider_task_snapshot_limit", "Combined snapshots exceed their finite limit.")
    if _repository(root) != observed:
        _fail("provider_task_base_changed", "Repository identity changed during snapshot observation.")
    plan = {"format": FORMAT, "repository_identity": observed["identity"], "base_commit": base_commit,
        "base_tree": git(root, "rev-parse", base_commit + "^{tree}"), "task": task, "provider": provider,
        "backend": backend, "model": model, "reasoning_effort": reasoning_effort, "context_policy": context_policy,
        "artifact_format": artifact_format, "read_context": before, "writable_outputs": outputs,
        "snapshot_provenance": "observed-selected-git", "manual_application_required": True,
        "automatic_retry_allowed": False}
    screen_sensitive({k: v for k, v in plan.items() if k != "repository_identity"})
    plan["intent_digest"] = _intent(plan)
    plan["digest"] = digest(plan)
    canonical_bytes(plan)
    return plan


def validate_plan(plan):
    """Validate shape/integrity only, without trusting a document's source claims."""
    if (type(plan) is not dict or set(plan) != _FIELDS or plan.get("format") != FORMAT
            or plan.get("manual_application_required") is not True or plan.get("automatic_retry_allowed") is not False
            or plan.get("snapshot_provenance") != "observed-selected-git"):
        _fail("provider_task_plan_invalid", "A closed versioned task plan is required.")
    canonical_bytes(plan)
    for key in ("read_context", "writable_outputs"):
        if type(plan[key]) is not dict:
            _fail("provider_task_plan_invalid", "Snapshot roles must be explicit maps.")
    _scope(list(plan["read_context"]), list(plan["writable_outputs"]))
    for key in ("repository_identity", "intent_digest", "digest"):
        if type(plan[key]) is not str or not re.fullmatch(r"[a-f0-9]{64}", plan[key]):
            _fail("provider_task_plan_invalid", "Exact plan SHA256 identities are required.")
    for key in ("base_commit", "base_tree"):
        if type(plan[key]) is not str or not re.fullmatch(r"[a-f0-9]{40}", plan[key]):
            _fail("provider_task_plan_invalid", "Exact source identities are required.")
    _text(plan["task"], "task", 16384)
    for key in ("provider", "model", "reasoning_effort"):
        _text(plan[key], key)
    if plan["backend"] is not None:
        _text(plan["backend"], "backend")
    if type(plan["context_policy"]) is not str or plan["context_policy"] not in {"include", "exclude", "native-only"}:
        _fail("provider_task_plan_invalid", "Unknown context policy.")
    if type(plan["artifact_format"]) is not str or plan["artifact_format"] not in ARTIFACT_FORMATS:
        _fail("provider_task_plan_invalid", "Unknown artifact format.")
    total = 0
    for role in ("read_context", "writable_outputs"):
        for snapshot in plan[role].values():
            if snapshot is None and role == "writable_outputs":
                continue
            if type(snapshot) is not dict or set(snapshot) != {"content", "sha256", "bytes", "git_blob", "git_mode"}:
                _fail("provider_task_plan_invalid", "A complete source snapshot is required.")
            content = snapshot["content"]
            if type(content) is not str:
                _fail("provider_task_plan_invalid", "Source content must be text.")
            raw = content.encode("utf-8")
            if (type(snapshot["bytes"]) is not int or snapshot["bytes"] != len(raw) or len(raw) > MAX_FILE_BYTES
                    or snapshot["sha256"] != hashlib.sha256(raw).hexdigest()
                    or type(snapshot["git_blob"]) is not str or not re.fullmatch(r"[a-f0-9]{40}", snapshot["git_blob"])
                    or type(snapshot["git_mode"]) is not str or snapshot["git_mode"] not in {"100644", "100755"}
                    or any(ord(c) < 32 and c not in "\n\t" or ord(c) == 127 for c in content)):
                _fail("provider_task_plan_invalid", "Source snapshot content/hash/size/role disagrees.")
            total += len(raw)
    if total > MAX_SNAPSHOT_BYTES:
        _fail("provider_task_snapshot_limit", "Combined snapshots exceed their finite limit.")
    if plan["digest"] != digest(plan) or plan["intent_digest"] != _intent(plan):
        _fail("provider_task_plan_changed", "Task-plan integrity changed; no submission is authorized.")
    return plan


def verify_task(plan, *, repository):
    """Reobserve the owner-selected repository instead of trusting sealed JSON."""
    validate_plan(plan)
    fresh = prepare_task(repository, base_commit=plan["base_commit"], task=plan["task"], provider=plan["provider"],
        backend=plan["backend"], model=plan["model"], reasoning_effort=plan["reasoning_effort"],
        writable_paths=list(plan["writable_outputs"]), read_paths=list(plan["read_context"]),
        context_policy=plan["context_policy"], artifact_format=plan["artifact_format"])
    if canonical_bytes(fresh) != canonical_bytes(plan):
        _fail("provider_task_plan_changed", "The actual repository/snapshots differ from the reviewed plan.")
    return fresh


def render_prompt(plan):
    """Render data roles; no local account/control paths are disclosed here."""
    validate_plan(plan)
    rule = ("Return one JSON object with bundle_digest and changes (declared writable paths mapped to complete LF text or null)."
            if plan["artifact_format"] == "file-replacements/1" else
            "Return one JSON object with bundle_digest and patch (a bounded unified diff for declared writable paths only).")
    public = {k: plan[k] for k in ("base_commit", "base_tree", "task", "provider", "backend", "model",
        "reasoning_effort", "context_policy", "artifact_format", "read_context", "writable_outputs")}
    return (rule + " Do not run tools, commands, grant access, retry or apply changes. Read_context is read-only reference data; "
            "only writable_outputs may change, including null baselines for new files. A human independently reviews/tests/applies proposals.\n"
            + canonical_bytes({"bundle_digest": plan["digest"], "request": public}).decode("utf-8") + "\n").encode("utf-8")
