"""Durable production input measurements; no launch or qualification authority.

Private content-addressed settings preserve v2.11's intent-only semantics. The
preparation binds local files and the intended base tree, not effective runtime
closure, containment, account identity, or a future owned attempt/workspace.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

from .muse_production import _error, _immutable, _observe_file, _profile, assess_task
from .validation import canonical_bytes, digest, seal_versioned, validate_versioned
from .workspace import _tree, git

FORMAT = "muse-production-preparation/1"
PREFIX = "muse-production-preparation:"
_INPUT_KEYS = {"instructions_path", "tools_path", "dependency_paths"}
_MAX_DEPENDENCY_BYTES = 128 * 1024 * 1024


def _inputs(document):
    if type(document) is not dict or set(document) != _INPUT_KEYS:
        raise _error("muse_preparation_inputs_invalid", "Select exactly instruction, tool and declared dependency paths.")
    paths = document["dependency_paths"]
    if (type(paths) is not list or len(paths) > 32
            or any(type(p) is not str or not 1 <= len(p) <= 4096 for p in paths)
            or len(set(paths)) != len(paths)):
        raise _error("muse_preparation_inputs_invalid", "Use at most 32 distinct bounded dependency paths.")
    for key in ("instructions_path", "tools_path"):
        if type(document[key]) is not str or not 1 <= len(document[key]) <= 4096:
            raise _error("muse_preparation_inputs_invalid", "Instruction and tool inputs require direct absolute file paths.")
    return {**document, "dependency_paths": sorted(paths)}


def _projection(profile):
    # Symbolic core bindings are deliberately not executable argv. No worktree,
    # prompt or lease exists until a future qualified durable attempt allocates it.
    from .executors.muse_protocol import project_production_exec_argv
    workspace, prompt = "/__taskalong_owned_workspace__", "/__taskalong_owned_attempt__/prompt.txt"
    argv = project_production_exec_argv(executable=profile["executable_path"],
        build=profile["runtime_version"], workspace=workspace, prompt_file=prompt,
        model=profile["model"], reasoning_effort=profile["reasoning_effort"],
        permission_profile=profile["permission_policy"]["permission_profile"], max_model_steps=1)
    planned = list(argv)
    planned[planned.index("--workspace") + 1] = {"core_binding": "owned_workspace"}
    planned[planned.index("--prompt-file") + 1] = {"core_binding": "prepared_prompt"}
    return planned


def _measure(store, spec, inputs):
    # Reuse all existing exact profile/config/repository checks. Those checks
    # observe Git but never invoke the selected Muse executable or its updater.
    readiness = assess_task(store, spec)["readiness"]
    profile = _profile(store, spec["execution"]["profile_id"])
    config = store.setting("muse-production-config:" + spec["execution"]["configuration_digest"])
    config = validate_versioned("driver-config", config, expected_version="2.11")
    executable = _observe_file(profile["executable_path"], executable=True)
    policy = _observe_file(config["permission_policy_path"])
    instruction = _observe_file(inputs["instructions_path"])
    tools = _observe_file(inputs["tools_path"])
    for observation, expected, code in (
        (executable, profile["executable_sha256"], "muse_executable_changed"),
        (policy, config["permission_policy_sha256"], "muse_configuration_changed"),
        (instruction, profile["permission_policy"]["instructions_sha256"], "muse_instructions_changed"),
        (tools, profile["permission_policy"]["tools_sha256"], "muse_tools_changed"),
    ):
        if observation["sha256"] != expected:
            raise _error(code, "The selected input no longer matches its registered identity.")
    dependencies, total = [], 0
    for path in inputs["dependency_paths"]:
        item = _observe_file(path, max_bytes=64 * 1024 * 1024)
        total += item["bytes"]
        if total > _MAX_DEPENDENCY_BYTES:
            raise _error("muse_dependency_limit", "Declared dependencies exceed the 128 MiB observation bound.")
        dependencies.append(item)
    repository = store.repository(spec["repository"]["registration_id"])
    base = spec["repository"]["base_commit"]
    # _tree applies existing limits and rejects symlinks, gitlinks and transforms.
    files = [{"path": path, "mode": mode, "git_blob": oid}
             for path, (mode, oid) in sorted(_tree(Path(repository["path"]), base).items())]
    source = {"registration_id": repository["registration_id"], "repository_identity": repository["identity"],
              "base_commit": base, "tree": git(repository["path"], "rev-parse", base + "^{tree}"),
              "files": files, "exposure_contained": False}
    source["digest"] = digest(source)
    # Explicit measured/unknown separation: user-supplied paths cannot claim the
    # inventory is complete or that Muse consumes only these inputs.
    return {"format": FORMAT, "spec_digest": spec["digest"],
        "canonical_task_sha256": hashlib.sha256(canonical_bytes(spec)).hexdigest(),
        "profile_digest": profile["digest"], "configuration_digest": config["digest"],
        "executable": executable, "policy_input": policy, "instruction_input": instruction, "tool_input": tools,
        "declared_dependencies": dependencies, "dependency_closure_qualified": False,
        "source": source, "argv_template": _projection(profile), "launch_arguments_complete": False,
        "requested_budget": spec["budget"], "total_inference_bound_qualified": False,
        "effective_inputs_observed": False, "account_endpoint_observed": False,
        "process_lifetime_qualified": False, "durable_execution_qualified": False,
        "independent_review_qualified": False, "production_dispatch_allowed": False, "acceptance_allowed": False,
        "reason_codes": readiness["reason_codes"],
        "next_actions": [{"action": "qualify_effective_runtime_and_containment"}]}


def prepare(store, document, *, inputs):
    """Measure once and commit one immutable record; this is not a dispatch intent."""
    spec = seal_versioned("task-spec", document, version="2.11")
    selected = _inputs(inputs)
    assessment = _measure(store, spec, selected)
    record = {"format": FORMAT, "spec": spec, "inputs": selected, "assessment": assessment}
    record["digest"] = digest(record)
    # Enforce the normal bounded canonical document envelope before any write.
    canonical_bytes(record)
    _immutable(store, PREFIX + record["digest"], record)
    return assessment | {"preparation_digest": record["digest"]}


def observe(store, content_digest):
    """Verify a retained preparation and reobserve its inputs without refreshing it."""
    if type(content_digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", content_digest):
        raise _error("muse_preparation_digest_invalid", "Select an exact preparation SHA-256 digest.")
    record = store.setting(PREFIX + content_digest)
    if record is None:
        raise _error("muse_preparation_missing", "The selected production preparation is not recorded.")
    if (type(record) is not dict or set(record) != {"format", "spec", "inputs", "assessment", "digest"}
            or record["format"] != FORMAT or record["digest"] != content_digest or digest(record) != content_digest):
        raise _error("muse_preparation_corrupt", "The retained production preparation failed its integrity check.")
    spec = validate_versioned("task-spec", record["spec"], expected_version="2.11")
    selected = _inputs(record["inputs"])
    fresh = _measure(store, spec, selected)
    # JSON booleans and integers are distinct even though Python equality
    # equates False with 0. Retained inputs must also be canonical already.
    if selected != record["inputs"] or canonical_bytes(fresh) != canonical_bytes(record["assessment"]):
        raise _error("muse_preparation_stale", "Preparation inputs changed; preserve the original and prepare a new subject.")
    return fresh | {"preparation_digest": content_digest}
