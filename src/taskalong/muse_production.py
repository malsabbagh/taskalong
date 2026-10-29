"""Production Muse intent registration. No driver, qualification grant or spawn.

Additive content-addressed settings deliberately do not enter legacy profiles,
runs or document history. No database format upgrade is needed. Older readers
ignore these settings and reject v2.11 documents rather than reinterpret them.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat

from .errors import TaskAlongError
from .validation import canonical_bytes, digest, seal_versioned, validate_versioned

VERSION = "2.11"
BLOCKERS = ["muse_effective_policy_unqualified", "muse_lifetime_unqualified",
            "muse_output_contract_unqualified", "muse_recovery_unqualified",
            "muse_real_reviewer_unqualified", "muse_runtime_unqualified"]


def _error(code, message):
    return TaskAlongError(code, message, exit_code=3, effect_outcome="not_sent")


def _fingerprint(value, *, executable=False):
    return _observe_file(value, executable=executable)["sha256"]


def _observe_file(value, *, executable=False, max_bytes=None):
    """Bounded local identity observation, not executable-closure qualification."""
    if type(value) is not str or not 1 <= len(value) <= 4096 or "\x00" in value:
        raise _error("muse_path_unsupported", "Use a canonical absolute local path.")
    path = Path(value)
    if not path.is_absolute() or str(path) != value or ".." in path.parts:
        raise _error("muse_path_unsupported", "Use a canonical absolute local path.")
    # Reject symlink components and final symlinks; no PATH/updater resolution.
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise _error("muse_path_unsupported", "Use a direct file without symlink components.")
    try:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or (executable and not os.access(path, os.X_OK)):
                raise _error("muse_file_unsupported", "A regular readable file with the required mode is needed.")
            limit = max_bytes if max_bytes is not None else (512 * 1024 * 1024 if executable else 1048576)
            if before.st_size > limit:
                raise _error("muse_file_unsupported", "The identity input exceeds its bounded size.")
            sha = hashlib.sha256()
            remaining = limit + 1
            while remaining:
                block = stream.read(min(65536, remaining))
                if not block:
                    break
                sha.update(block)
                remaining -= len(block)
            after = os.fstat(stream.fileno())
        current = path.lstat()
        identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if remaining == 0 or identity(before) != identity(after) or identity(after) != identity(current):
            raise _error("muse_file_changed", "The identity input changed during observation.")
        return {"path": value, "sha256": sha.hexdigest(), "bytes": after.st_size,
                "mode": stat.S_IMODE(after.st_mode)}
    except OSError as exc:
        raise _error("muse_file_unavailable", "The bound local file cannot be observed.") from exc


def _immutable(store, key, document):
    # One transaction makes same-ID concurrent registration deterministic.
    with store.transaction() as db:
        previous = store.setting(key)
        if previous is not None and previous != document:
            raise _error("muse_registration_immutable", "Changed intent requires a new identity.")
        db.execute("INSERT OR IGNORE INTO settings VALUES (?,?)", (key, canonical_bytes(document).decode()))
    return document


def _profile(store, profile_id):
    document = store.setting("muse-production-profile:" + profile_id)
    if document is None:
        raise _error("muse_profile_missing", "Register the exact production Muse profile first.")
    return validate_versioned("runtime-profile", document, expected_version=VERSION)


def _observe_profile(profile):
    if _fingerprint(profile["executable_path"], executable=True) != profile["executable_sha256"]:
        raise _error("muse_executable_changed", "The executable no longer matches its registered identity.")


def register_profile(store, document):
    profile = seal_versioned("runtime-profile", document, version=VERSION)
    _observe_profile(profile)
    return _immutable(store, "muse-production-profile:" + profile["profile_id"], profile)


def configure(store, document):
    config = seal_versioned("driver-config", document, version=VERSION)
    profile = _profile(store, config["profile_id"])
    _check_config(profile, config)
    return _immutable(store, "muse-production-config:" + config["digest"], config)


def _check_config(profile, config):
    if profile["digest"] != config["profile_digest"] or profile["profile_id"] != config["profile_id"]:
        raise _error("muse_profile_mismatch", "Configuration must bind the exact registered profile.")
    _observe_profile(profile)
    if config["permission_policy_sha256"] != profile["permission_policy"]["policy_sha256"]:
        raise _error("muse_policy_mismatch", "Configuration must bind the profile's policy identity.")
    if _fingerprint(config["permission_policy_path"]) != config["permission_policy_sha256"]:
        raise _error("muse_configuration_changed", "The policy file no longer matches its bound identity.")


def readiness(store, profile_id, configuration_digest):
    profile = _profile(store, profile_id)
    config = store.setting("muse-production-config:" + configuration_digest)
    if config is None:
        raise _error("muse_configuration_missing", "Register the exact production Muse configuration first.")
    config = validate_versioned("driver-config", config, expected_version=VERSION)
    if config["digest"] != configuration_digest:
        raise _error("muse_configuration_mismatch", "The stored configuration identity differs.")
    _check_config(profile, config)
    return {"schema_version": VERSION, "profile_id": profile_id, "profile_digest": profile["digest"],
            "configuration_digest": config["digest"], "model": profile["model"],
            "reasoning_effort": profile["reasoning_effort"], "document_supported": True,
            "local_identity_matches": True, "effective_model_observed": False,
            "effective_policy_qualified": False, "process_lifetime_qualified": False,
            "production_dispatch_allowed": False, "acceptance_allowed": False,
            "reason_codes": list(BLOCKERS),
            "next_actions": [{"action": "implement_and_qualify_muse_runtime"}]}


def assess_task(store, document):
    spec = seal_versioned("task-spec", document, version=VERSION)
    execution = spec["execution"]
    view = readiness(store, execution["profile_id"], execution["configuration_digest"])
    profile = _profile(store, execution["profile_id"])
    if execution["profile_digest"] != profile["digest"] or spec["permissions"]["inference_destination_id"] != profile["inference_destination_id"]:
        raise _error("muse_profile_mismatch", "Task must bind the exact profile and destination.")
    repository = store.repository(spec["repository"]["registration_id"])
    from .workspace import git, inspect_repository
    if inspect_repository(repository["path"])["identity"] != repository["identity"]:
        raise _error("repository_identity_changed", "Registered Git identity has changed.")
    resolved = git(repository["path"], "rev-parse", "--verify", spec["repository"]["base_commit"] + "^{commit}").strip()
    if isinstance(resolved, bytes):
        resolved = resolved.decode()
    if resolved != spec["repository"]["base_commit"]:
        raise _error("base_commit_mismatch", "Task base must be an existing full commit.")
    return {"valid": True, "schema_version": VERSION, "spec_digest": spec["digest"], "readiness": view}
