"""One durable, supervised configured-provider owner.

This experimental route stages proposals for manual review. A local deadline,
capture closure or native terminal record is never remote settlement, complete
descendant cessation, independent acceptance or permission to retry.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import time

from .artifact_io import read_regular, _parent, _unchanged_directories
from .errors import TaskAlongError
from .local_provider_artifacts import validate_response
from .local_provider_capture import PrivateCapture
from .local_provider_contract import ProviderLimits
from .local_provider_tasks import prepare_task, render_prompt, verify_task
from .process import ProcessBoundaryError, fingerprint, minimal_environment, run_bounded
from .store import identifier, now
from .supervised_pilot import _destination, _write
from .validation import canonical_bytes, digest, loads, screen_sensitive

PROVIDERS = frozenset({"codex", "antigravity", "claude-code"})
_FORMAT = "configured-provider-profile/1"


def _fail(code, message, *, uncertain=False):
    raise TaskAlongError(code, message, exit_code=4 if uncertain else 3,
                         effect_outcome="uncertain" if uncertain else "not_sent")


def _adapters():
    from . import local_provider_adapters
    return local_provider_adapters


def _passive(config):
    return {k:v for k,v in config.items() if k != "digest"}


def _native_roots(config):
    """Observe only selected directory identities; never read native contents."""
    if config["provider"] != "codex":
        return {}
    roots = config.get("native_roots", {})
    if "CODEX_HOME" in os.environ and "CODEX_HOME" not in roots:
        _fail("provider_native_root_unsupported", "Select CODEX_HOME explicitly with profile/3 before submission.")
    observed = {}
    try:
        for key, path in roots.items():
            # Reuse held no-follow traversal without creating or opening a file.
            with _parent(path, "native-root-observation", private=False) as (fd, _, links):
                info = os.fstat(fd)
                observed[key] = {"path": path, "device": info.st_dev, "inode": info.st_ino, "owner": info.st_uid}
                _unchanged_directories(links)
    except (TaskAlongError, OSError):
        _fail("provider_native_root_unavailable", "The selected native directory is unavailable or unsafe.")
    return observed


def _check_native_roots(store, config, bound=None):
    observed = _native_roots(config)
    if config["provider"] != "codex" or config["format"] != "configured-provider-profile/3":
        return
    if bound is None:
        pointer = store.setting("provider-native-roots:" + config["digest"])
        if (type(pointer) is not dict or pointer.get("digest") != digest(pointer)
                or pointer.get("configuration_digest") != config["digest"]
                or type(pointer.get("observation_digest")) is not str):
            _fail("provider_native_root_changed", "The selected native directory binding is unavailable.")
        bound = store.setting("provider-native-root-observation:" + pointer["observation_digest"])
    if (type(bound) is not dict or bound.get("digest") != digest(bound)
            or bound.get("configuration_digest") != config["digest"] or bound.get("roots") != observed
            or store.setting("provider-native-root-observation:" + bound["digest"]) != bound):
        _fail("provider_native_root_changed", "The selected native directory binding changed; configure it again.")
    return bound


def configure(store, provider, value):
    if type(provider) is not str or provider not in PROVIDERS:
        _fail("provider_unavailable", "Select an implemented configured provider.")
    screen_sensitive(value)
    config = _adapters().normalize_configuration(provider, value)
    _check_executables(config)
    roots = _native_roots(config)
    config["digest"] = digest(config)
    with store.transaction() as db:
        raw = canonical_bytes(config).decode()
        db.execute("INSERT OR IGNORE INTO settings VALUES (?,?)", ("provider-config:" + config["digest"], raw))
        if config["format"] == "configured-provider-profile/3":
            binding = {"configuration_digest": config["digest"], "roots": roots}
            binding["digest"] = digest(binding)
            name = "provider-native-root-observation:" + binding["digest"]
            existing = store.setting(name)
            if existing is not None and existing != binding:
                _fail("provider_native_root_changed", "Retained native directory evidence conflicts.")
            db.execute("INSERT OR IGNORE INTO settings VALUES (?,?)", (name, canonical_bytes(binding).decode()))
            pointer = {"configuration_digest": config["digest"], "observation_digest": binding["digest"]}
            pointer["digest"] = digest(pointer)
            db.execute("INSERT INTO settings VALUES (?,?) ON CONFLICT(name) DO UPDATE SET document=excluded.document",
                       ("provider-native-roots:" + config["digest"], canonical_bytes(pointer).decode()))
        db.execute("INSERT INTO settings VALUES (?,?) ON CONFLICT(name) DO UPDATE SET document=excluded.document",
                   ("provider:" + provider, raw))
    return _view(config)


def _configuration(store, provider):
    if provider not in PROVIDERS:
        _fail("provider_unavailable", "Select an implemented configured provider.")
    stored = store.setting("provider:" + provider)
    if stored is None:
        _fail("provider_not_configured", "Configure the selected local provider first.")
    if stored.get("digest") != digest(stored):
        _fail("provider_configuration_changed", "The sealed local configuration changed.")
    unsigned = {k:v for k,v in stored.items() if k != "digest"}
    if _adapters().normalize_configuration(provider, unsigned) != unsigned:
        _fail("provider_configuration_changed", "The current adapter does not recognize this configuration.")
    return stored


def _view(config):
    inner = config["adapter_configuration"]
    return {"provider": config["provider"], "configured": True, "experimental": True,
            "configuration_digest": config["digest"], "model": inner["model"],
            "reasoning_effort": inner.get("effort"), "context": inner["context"],
            "backend": inner.get("backend"), "activation_required": False,
            "limits": config["limits"],
            "capabilities": _adapters().capabilities(_passive(config))}


def providers(store):
    return [_view(_configuration(store, name)) for name in sorted(PROVIDERS)
            if store.setting("provider:" + name) is not None]


def _check_executables(config):
    """Bind the declared executable closure without executing any of it."""
    try:
        for value in _adapters().executable_descriptors(_passive(config)):
            if fingerprint(value["path"]) != value["sha256"]:
                _fail("provider_executable_changed", "A selected runtime component changed; configure it again.")
        inner = config["adapter_configuration"]
        closure = inner["runtime_closure"]
        if closure["kind"] == "ollama-launch":
            settings = closure["settings_file"]
            home = os.environ.get("HOME")
            if not home or str(Path(home) / ".ollama/config.json") != settings["path"]:
                _fail("provider_backend_home_mismatch", "Bind the existing Ollama settings under the effective HOME.")
            source = Path(settings["path"])
            raw = read_regular(source.parent, source.name, max_bytes=65536,
                expected_sha256=settings["sha256"])
            _adapters().validate_saved_model(_passive(config), raw)
            if Path(closure["claude_on_path"]["path"]).resolve(strict=True) != Path(inner["executable"]["path"]).resolve(strict=True):
                _fail("provider_backend_path_mismatch", "The launcher PATH must resolve the selected existing Claude executable.")
    except (OSError, ProcessBoundaryError):
        _fail("provider_executable_unavailable", "The selected runtime closure is unavailable.")


def prepare(store, provider, *, request):
    """Observe explicit source roles. No output, claim or provider subprocess."""
    config = _configuration(store, provider)
    if type(request) is not dict:
        _fail("provider_task_invalid", "Supply a scoped repository task request.")
    required = {"repository", "base_commit", "task", "writable_paths"}
    optional = {"read_paths", "artifact_format"}
    if not required <= set(request) or set(request) - required - optional:
        _fail("provider_task_invalid", "Declare repository, base, task and writable paths; reference paths remain read-only.")
    inner = config["adapter_configuration"]
    plan = prepare_task(request["repository"], base_commit=request["base_commit"], task=request["task"],
        provider=provider, backend=inner.get("backend"), model=inner["model"],
        reasoning_effort=inner.get("effort"), context_policy=inner["context"],
        writable_paths=request["writable_paths"], read_paths=request.get("read_paths", []),
        artifact_format=request.get("artifact_format", "file-replacements/1"))
    return plan


def budget(store, provider, *, request):
    config = _configuration(store, provider)
    _check_native_roots(store, config)
    plan = prepare(store, provider, request=request)
    prompt = render_prompt(plan)
    limits = ProviderLimits.from_dict(config["limits"])
    if len(prompt) > 1048576:
        _fail("provider_prompt_too_large", "The bounded native stdin packet exceeds one MiB; select less context.")
    return {"provider": provider, "model_free": True, "controller_submissions": 0,
            "plan_digest": plan["digest"], "intent_digest": plan["intent_digest"],
            "prompt_bytes": len(prompt), "limits": limits.to_dict(),
            "response_fit_guaranteed": False, "input_echo_contract": "unknown"}


def _event(store, record, root, state, **values):
    value = {**record, **values, "state": state, "revision": record["revision"] + 1, "at": now()}
    value.pop("digest", None)
    value["digest"] = digest(value)
    _write(root, f"events/{value['revision']:04d}.json", canonical_bytes(value))
    # The filesystem event precedes the SQLite pointer. A crash leaves an
    # observable orphan, which controls refuse instead of replaying its effect.
    with store.transaction() as db:
        previous = store.setting("provider-run:" + value["run_id"])
        if previous is not None and previous != record:
            _fail("provider_history_conflict", "The owner revision changed; preserve retained evidence.", uncertain=True)
        db.execute("INSERT INTO settings VALUES (?,?) ON CONFLICT(name) DO UPDATE SET document=excluded.document",
                   ("provider-run:" + value["run_id"], canonical_bytes(value).decode()))
    return value


def _claim(store, record, plan):
    key = "configured-provider-claim:" + plan["intent_digest"]
    with store.transaction() as db:
        if store.setting(key) is not None:
            _fail("provider_already_submitted", "This logical task has a consumed or uncertain claim; inspect it without redispatch.")
        db.execute("INSERT INTO settings VALUES (?,?)", (key, canonical_bytes({
            "format": "configured-provider-claim/1", "run_id": record["run_id"],
            "plan_digest": plan["digest"], "intent_digest": plan["intent_digest"],
            "configuration_digest": record["configuration_digest"],
            "reserved_controller_submissions": 1, "remote_usage": "unknown",
            "automatic_retry_allowed": False}).decode()))


def _cancelled(store, record, control):
    marker = control / "cancel-request.json"
    if not marker.exists() and not marker.is_symlink():
        return False
    value = loads(read_regular(control, marker.name, max_bytes=1048576, private=True, expected_mode=0o400))
    slot = store.setting("provider-control:cancel:" + record["run_id"])
    intent = store.setting(slot.get("operation", "")) if type(slot) is dict else None
    if (type(intent) is not dict or intent.get("digest") != digest(intent)
            or slot.get("intent_digest") != intent["digest"]
            or value.get("digest") != digest(value) or value.get("format") != "configured-provider-cancel/1"
            or value.get("intent_digest") != intent["digest"] or value.get("binding") != intent.get("binding")
            or value.get("automatic_retry_allowed") is not False):
        _fail("provider_control_marker_conflict", "Cancellation evidence conflicts; stop the owned child and preserve evidence.", uncertain=True)
    binding = value["binding"]
    if (any(binding.get(k) != record.get(k) for k in ("run_id", "provider", "configuration_digest", "request_digest"))
            or type(binding.get("revision")) is not int or binding["revision"] > record["revision"]
            or binding.get("process_receipt") is not None and binding["process_receipt"] != record.get("process_receipt")):
        _fail("provider_control_marker_conflict", "Cancellation belongs to a different owned process.", uncertain=True)
    return True


def _process(config, prepared, invocation, *, output_chunk, cancelled, spawned):
    """Existing POSIX owner, never saved-PID recovery or a second Codex driver."""
    limits = prepared["remaining_budget"]
    remaining_seconds = (prepared["absolute_deadline"] - time.time()*1000) / 1000
    if remaining_seconds <= 0:
        _fail("provider_deadline_expired", "The bound local deadline expired before target launch.")
    timeout = min(limits["attempt_seconds"], remaining_seconds)
    env = minimal_environment(runtime_parent=True)
    env.update(invocation["env_overrides"])
    if sys.platform == "darwin":
        from .experimental_process import FOREGROUND_EXPERIMENT, run_foreground_experiment
        result = run_foreground_experiment(invocation["argv"], mode=FOREGROUND_EXPERIMENT,
            cwd=prepared["workspace"], stdin=invocation["stdin"], env=env,
            timeout_seconds=timeout, max_output_bytes=limits["max_output_bytes"],
            cancel_requested=cancelled, on_spawn=spawned, _on_output_chunk=output_chunk)
        summary = result.to_dict()
    else:
        failure_code, failures, effect = None, (), "uncertain"
        try:
            result = run_bounded(invocation["argv"], cwd=prepared["workspace"], stdin=invocation["stdin"], env=env,
                timeout_seconds=timeout, max_output_bytes=limits["max_output_bytes"],
                cancel_requested=cancelled, on_spawn=spawned, _on_output_chunk=output_chunk)
        except ProcessBoundaryError as exc:
            if exc.process_result is None:
                raise
            result = exc.process_result
            failure_code, failures, effect = exc.code, exc.boundary_failures, exc.effect_outcome
        summary = result.to_dict()
        summary.update(root_exit_code=result.exit_code, root_exit_observed=result.exit_code is not None,
                       descendant_cessation="unknown", production_dispatch_allowed=False, acceptance_allowed=False,
                       failure_code=failure_code, boundary_failures=failures, effect_outcome=effect)
    summary.pop("stdout", None)
    summary.pop("stderr", None)
    summary["observed_output_bytes"] = result.output_bytes
    # dataclasses.asdict preserves tuple-valued experimental diagnostics;
    # persisted strict JSON requires arrays, including the failure path.
    return loads(json.dumps(summary))


def _execute_codex(config, prepared, *, workspace, output_dir, owner, mode, thread_id):
    """Versioned CodexCLI.run handoff; legacy production admission is untouched."""
    if (config.get("provider") != "codex" or prepared.get("provider") != "codex"
            or mode != "start" or thread_id is not None or not callable(owner)
            or str(workspace) != prepared.get("workspace") or str(output_dir) != prepared.get("control_root")
            or prepared.get("configuration_digest") != config.get("digest")):
        _fail("runtime_owner_invalid", "Codex requires the current configured owner and one fresh bound turn.")
    return owner()


def run(store, provider, *, request, output=None):
    if sys.platform not in {"darwin", "linux"}:
        _fail("provider_platform_unsupported", "The configured process owner currently supports macOS and Linux.")
    config = _configuration(store, provider)
    native_binding = _check_native_roots(store, config)
    plan = prepare(store, provider, request=request)
    prompt = render_prompt(plan)
    if len(prompt) > 1048576:
        _fail("provider_prompt_too_large", "The explicit stdin packet exceeds one MiB; select less context.")
    limits = ProviderLimits.from_dict(config["limits"])
    _check_executables(config)
    # Budget or artifact-format changes do not create fresh dispatch authority.
    if store.setting("configured-provider-claim:" + plan["intent_digest"]) is not None:
        _fail("provider_already_submitted", "This logical task already has a claim; inspect the prior run.")
    run_id, attempt = identifier(), identifier()
    if output is None:
        parent = store.root / "provider-output"
        parent.mkdir(mode=0o700, exist_ok=True)
        output = str(parent / run_id)
    root = _destination(output)
    control, workspace = root / "control", root / "workspace"
    prepared = {"provider": provider, "backend": plan["backend"], "run_id": run_id, "attempt_id": attempt,
        "operation_key": run_id, "request_digest": plan["digest"], "bundle_digest": plan["digest"],
        "configuration_digest": config["digest"], "read_context": plan["read_context"],
        "writable_outputs": plan["writable_outputs"], "workspace": str(workspace), "control_root": str(control),
        "prompt_file": str(control / "prompt.txt"), "result_file": str(control / "result.json"),
        "absolute_deadline": int(time.time()*1000) + limits.attempt_seconds*1000,
        "remaining_budget": limits.to_dict(), "context_policy": plan["context_policy"],
        "requested_model": plan["model"], "requested_effort": plan["reasoning_effort"],
        "artifact_format": plan["artifact_format"]}
    if native_binding is not None:
        prepared["native_root_binding"] = native_binding
    # Adapter projection and unsupported feature checks precede any claim.
    invocation = _adapters().adapter_invocation(_passive(config), prepared, prompt)
    decoder = _adapters().decoder(_passive(config), prepared, limits)
    root.mkdir(mode=0o700)
    control.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    _write(control, "prompt.txt", prompt)
    _write(control, "plan.json", canonical_bytes(plan))
    if provider == "codex":
        _write(control, "proposal-schema.json", canonical_bytes(_adapters().proposal_schema(_passive(config), prepared)))
    record = {"format": "configured-provider-run/1", "provider": provider, "backend": plan["backend"],
        "run_id": run_id, "revision": 0, "request_digest": plan["digest"], "intent_digest": plan["intent_digest"],
        "configuration_digest": config["digest"], "output": str(root), "control_root": str(control),
        "controller_submissions": 0, "remote_usage": "not_sent", "native_internal_retries": "unknown",
        "descendant_cessation": "unknown", "automatic_retry_allowed": False, "patch_applied": False,
        "acceptance_allowed": False, "production_dispatch_allowed": False, "experimental": True,
        "limits": limits.to_dict()}
    if native_binding is not None:
        record["native_root_binding"] = native_binding
    record = _event(store, record, root, "preflight")
    capture = PrivateCapture(control / "capture", max_output_bytes=limits.max_output_bytes,
                             max_records=max(2, limits.max_protocol_records))
    claimed = False
    process = None
    closure = None
    decoder_error = None
    try:
        verify_task(plan, repository=request["repository"])
        _check_executables(config)
        _check_native_roots(store, config, native_binding)
        _claim(store, record, plan)
        claimed = True
        record = _event(store, record, root, "starting", controller_submissions=1, remote_usage="unknown")

        def spawned(receipt):
            nonlocal record
            _check_executables(config)
            _check_native_roots(store, config, native_binding)
            verify_task(plan, repository=request["repository"])
            read_regular(control, "prompt.txt", max_bytes=len(prompt), expected_sha256=hashlib.sha256(prompt).hexdigest(),
                         private=True, expected_mode=0o400)
            if time.time()*1000 >= prepared["absolute_deadline"]:
                _fail("provider_deadline_expired", "The local deadline expired before target gate release.")
            record = _event(store, record, root, "running", process_receipt=receipt.to_dict())
            if _cancelled(store, record, control):
                _fail("cancel_pending", "Cancellation was requested before target gate release.")
            if time.time()*1000 >= prepared["absolute_deadline"]:
                _fail("provider_deadline_expired", "The local deadline expired before target gate release.")

        def chunk(stream, data):
            nonlocal decoder_error
            capture.write(stream, data)
            if not capture.limited and decoder_error is None:
                try:
                    decoder.feed(stream, data)
                except TaskAlongError as exc:
                    # Parser rejection stops inference, not durable pipe drain.
                    decoder_error = exc.code

        owner = lambda: _process(config, prepared, invocation, output_chunk=chunk,
            cancelled=lambda: bool(decoder_error or capture.limited or _cancelled(store, record, control)), spawned=spawned)
        if provider == "codex":
            from .executors.codex_cli import CodexCLI
            process = CodexCLI(config).run(prepared, workspace=workspace, output_dir=control,
                                          _configured_owner=owner)
        else:
            process = owner()
        # Codex's schema-bound result file is part of the same aggregate cap.
        result_bytes = 0
        if provider == "codex" and (control / "result.json").exists():
            remaining = max(0, limits.max_output_bytes - process["observed_output_bytes"])
            raw = read_regular(control, "result.json", max_bytes=min(remaining, limits.max_record_bytes), private=True)
            result_bytes = len(raw)
            chunk("result", raw)
        closure = capture.finalize()
        observed_pipes = sum(closure["streams"][s]["observed_bytes"] for s in ("stdout", "stderr"))
        process["process_stream_complete"] = observed_pipes == process["observed_output_bytes"]
        process["observed_pipe_bytes"] = process["observed_output_bytes"]
        process["observed_result_bytes"] = result_bytes
        process["observed_output_bytes"] += result_bytes
        process["retained_output_bytes"] = sum(closure["streams"][s]["retained_bytes"] for s in ("stdout", "stderr", "result"))
        _write(root, "process.json", canonical_bytes(process))
        observation = decoder.finish(process["root_exit_code"])
        capture_failure = capture.limited or process.get("output_limited")
        if (process["root_exit_code"] != 0 or process.get("timed_out") or process.get("cancelled")
                or capture_failure or process.get("failure_code") or observation["terminal_status"] != "completed"
                or observation["protocol_errors"] or not process["process_stream_complete"]):
            return _event(store, record, root, "failed", process=process, observation=observation,
                          error="provider_local_or_protocol_failure", capture=closure)
        response = observation["structured_result"]
        screen_sensitive(response)
        artifact = validate_response(plan, response, max_proposal_bytes=limits.max_proposal_bytes)
        _write(root, "proposed.patch", artifact.patch_bytes)
        _write(root, "proposal.json", artifact.manifest_json)
        return _event(store, record, root, "proposal_ready", process=process, observation=observation,
            capture=closure, proposal_path=str(root / "proposed.patch"), proposal=artifact.to_dict())
    except (TaskAlongError, ProcessBoundaryError, OSError) as exc:
        # Preserve a cleaned-up owner's result even when a sink/decoder failed.
        if isinstance(exc, ProcessBoundaryError) and exc.process_result is not None:
            process = exc.process_result.to_dict()
            process.pop("stdout", None)
            process.pop("stderr", None)
            process.update(root_exit_code=exc.process_result.exit_code,
                root_exit_observed=exc.process_result.exit_code is not None, descendant_cessation="unknown")
            if not (root / "process.json").exists():
                _write(root, "process.json", canonical_bytes(process))
        if process is not None and not (root / "process.json").exists():
            # A result-file/capture failure occurs after owned cleanup. Keep
            # that authentic process observation even though no proposal exists.
            _write(root, "process.json", canonical_bytes(process))
        if closure is None:
            try:
                closure = capture.finalize()
            except (TaskAlongError, OSError):
                # A poisoned sink remains partial evidence, never byte closure.
                closure = None
        code = getattr(exc, "code", "provider_local_io")
        record = _event(store, record, root, "failed" if claimed else "blocked", error=code,
                        remote_usage="unknown" if claimed else "not_sent", process=process, capture=closure)
        _fail(code, "The provider attempt stopped; inspect retained evidence without redispatch.", uncertain=claimed)
    except KeyboardInterrupt:
        _event(store, record, root, "interrupted", remote_usage="unknown" if claimed else "not_sent")
        raise
    finally:
        capture.close()


def inspect(store, run_id):
    record = store.setting("provider-run:" + run_id) if type(run_id) is str else None
    if type(record) is not dict or record.get("format") != "configured-provider-run/1":
        return None
    from .local_provider_controls import inspect_run
    observation = inspect_run(store, run_id)
    return {**record, "runtime_observation": observation}
