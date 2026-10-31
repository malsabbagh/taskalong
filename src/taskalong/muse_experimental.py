"""Configured local Muse provider: experimental, one submission, manual patch review.

Configuration enables the ordinary provider API. Production proof contracts stay
separate. Native retries, descendants and remote accounting are observations or
unknowns, never inferred guarantees. No credential value enters configuration.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from . import supervised_pilot as pilot
from .artifact_io import read_regular
from .errors import TaskAlongError
from .experimental_process import FOREGROUND_EXPERIMENT, run_foreground_experiment
from .muse_production import _observe_file
from .process import ProcessBoundaryError, minimal_environment, redact
from .store import identifier, now
from .supervised_muse_runner import _uuid7
from .validation import canonical_bytes, digest, loads, screen_sensitive

_CONFIG = "provider:muse"
_EFFORTS = {"none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra"}
_CONTEXT = {"include", "native-only", "exclude"}
_KEYS = {"executable", "account_home", "muse_home", "model", "reasoning_effort", "context", "catalog_digest", "public_context_hashes", "context_hashes", "native_roots", "attempt_seconds", "max_output_bytes", "max_proposal_bytes"}


def _fail(code, message, *, outcome="not_sent", recovery=None):
    raise TaskAlongError(code, message, exit_code=3, effect_outcome=outcome, recovery=recovery)


def configure(store, value):
    if type(value) is not dict or not {"executable"}.issubset(value) or set(value) - _KEYS:
        _fail("provider_config_invalid", "Configure Muse with an executable and supported local options; credentials are managed by Muse.")
    screen_sensitive(value)
    home = pilot._root(value.get("account_home", str(Path.home())))
    root_keys = {"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"}
    overrides = value.get("native_roots", {})
    if type(overrides) is not dict or set(overrides) - root_keys:
        _fail("provider_config_invalid", "Native roots may override only supported XDG directory paths.")
    native_roots = {k:v for k,v in os.environ.items() if k in root_keys and v}
    native_roots.update(overrides)
    for path in native_roots.values(): pilot._root(path)
    default_data = Path(native_roots.get("XDG_DATA_HOME", str(home / ".local/share")))
    muse_home = pilot._root(value.get("muse_home", str(default_data / "muse")))
    if muse_home.name != "muse":
        _fail("provider_config_invalid", "muse_home must be the native muse directory under its XDG data root.")
    native_roots["XDG_DATA_HOME"] = str(muse_home.parent)
    if not home.is_dir():
        _fail("provider_config_invalid", "Select the existing account HOME directory.")
    model = value.get("model", "muse-wonder-full-1.0")
    effort = value.get("reasoning_effort", "high")
    context = value.get("context", "include")
    seconds = value.get("attempt_seconds", 20); maximum = value.get("max_output_bytes", 65536)
    proposal_maximum = value.get("max_proposal_bytes", 65536)
    catalog_digest = value.get("catalog_digest")
    if (type(model) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", model)
            or type(effort) is not str or effort not in _EFFORTS
            or type(context) is not str or context not in _CONTEXT
            or type(seconds) is not int or not 1 <= seconds <= 720
            or type(maximum) is not int or not 1024 <= maximum <= 1048576
            or type(proposal_maximum) is not int or not 1024 <= proposal_maximum <= 262144
            or catalog_digest is not None and (type(catalog_digest) is not str or not re.fullmatch(r"[a-f0-9]{64}", catalog_digest))):
        _fail("provider_config_invalid", "Select valid model, effort, context and finite local limits.")
    public_hashes = value.get("public_context_hashes", {})
    if (type(public_hashes) is not dict or set(public_hashes) - {"capability_policy", "security_mode", "meta_context_note"}
            or any(type(v) is not str or not re.fullmatch(r"[a-f0-9]{64}", v) for v in public_hashes.values())):
        _fail("provider_config_invalid", "Context template fingerprints must be SHA-256 values for supported public messages.")
    context_hashes = value.get("context_hashes", {})
    if (type(context_hashes) is not dict or set(context_hashes) - {"capability_policy", "security_mode", "meta_context_note", "rules_file", "skills_catalog"}
            or any(type(v) is not str or not re.fullmatch(r"[a-f0-9]{64}", v) for v in context_hashes.values())
            or any(k in public_hashes and public_hashes[k] != v for k, v in context_hashes.items())):
        _fail("provider_config_invalid", "Context fingerprints must bind supported stable startup messages with SHA-256 values.")
    binary = _observe_file(value["executable"], executable=True)
    with Path(binary["path"]).open("rb") as stream:
        if stream.read(2) == b"#!":
            _fail("provider_native_binary_required", "Select the installed direct native binary, not an updater or shell wrapper.")
    config = {"format": "local-muse-provider/3", "provider": "muse", "experimental": True,
              "binary": binary, "account_home": str(home), "muse_home": str(muse_home), "native_roots": native_roots, "model": model,
              "reasoning_effort": effort, "context": context, "catalog_digest": catalog_digest, "public_context_hashes": public_hashes, "context_hashes": context_hashes,
              "attempt_seconds": seconds, "max_output_bytes": maximum, "max_proposal_bytes": proposal_maximum}
    config["digest"] = digest(config)
    with store.transaction() as db:
        db.execute("INSERT OR IGNORE INTO settings VALUES (?,?)", ("provider-config:" + config["digest"], canonical_bytes(config).decode()))
        db.execute("INSERT INTO settings VALUES (?,?) ON CONFLICT(name) DO UPDATE SET document=excluded.document", (_CONFIG, canonical_bytes(config).decode()))
    return {"provider": "muse", "configured": True, "experimental": True, "configuration_digest": config["digest"],
            "context": context, "model": model, "reasoning_effort": effort, "activation_required": False}


def providers(store):
    value = store.setting(_CONFIG)
    return {"providers": [] if value is None else [{"provider": "muse", "configured": True, "experimental": True,
        "model": value["model"], "reasoning_effort": value["reasoning_effort"], "context": value["context"], "activation_required": False}]}


def _configuration(store):
    config = store.setting(_CONFIG)
    if config is None:
        _fail("provider_not_configured", "Configure the local Muse provider before running a task.")
    return _checked_configuration(config)


def _checked_configuration(config):
    if type(config) is not dict or config.get("format") not in ("local-muse-provider/1", "local-muse-provider/2", "local-muse-provider/3") or config.get("digest") != digest(config):
        _fail("provider_configuration_changed", "The local provider configuration is inconsistent; configure it again.")
    ceiling = 720 if config["format"] == "local-muse-provider/3" else 60
    if type(config.get("attempt_seconds")) is not int or not 1 <= config["attempt_seconds"] <= ceiling:
        _fail("provider_configuration_changed", "The provider deadline is invalid for its configuration format.")
    if type(config.get("max_output_bytes")) is not int or not 1024 <= config["max_output_bytes"] <= 1048576:
        _fail("provider_configuration_changed", "The whole-protocol capture limit is invalid.")
    if config["format"] != "local-muse-provider/1" and (type(config.get("max_proposal_bytes")) is not int or not 1024 <= config["max_proposal_bytes"] <= 262144):
        _fail("provider_configuration_changed", "This provider configuration requires an explicit finite proposal limit; configure it again.")
    if _observe_file(config["binary"]["path"], executable=True) != config["binary"]:
        _fail("provider_executable_changed", "The configured binary changed; configure the installed provider again.")
    return config


def _argv(config, *, provider, workspace, prompt, session):
    argv = [config["binary"]["path"], "exec", "--json", "--provider", provider, "--session-id", session,
            "--preset", "empty", "--permission-profile", ":read-only", "--workspace", str(workspace),
            "--prompt-file", str(prompt), "--max-model-steps", "1", "--disable-reminders", "--disable-web-tools",
            "--disable-write", "--disable-shell", "--disable-request-user-input", "--contributor-mode", "off"]
    if config["context"] == "native-only": argv.append("--no-foreign-personal-context")
    if provider == "meta":
        argv += ["--model", config["model"], "--reasoning-effort", config["reasoning_effort"], "--no-parallel-tool-calls"]
    return argv


def _native_json(raw):
    # Preserve native decimal observations as text, not invented rounded totals.
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError("duplicate native key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_float=str, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))


def _journal_source(config, session, *, started_unix_ms=None):
    home = pilot._root(config["muse_home"])
    candidates = []
    try:
        if started_unix_ms is None:
            instant = datetime.datetime.now(datetime.timezone.utc)
        else:
            if type(started_unix_ms) is not int or started_unix_ms <= 0: raise ValueError()
            instant = datetime.datetime.fromtimestamp(started_unix_ms / 1000, datetime.timezone.utc)
        days = {instant.astimezone().date(), instant.date()}
    except (ValueError, OverflowError, OSError):
        _fail("provider_journal_invalid", "The native session timestamp is invalid.", outcome="uncertain")
    for day in {d + datetime.timedelta(days=n) for d in days for n in (-1, 0, 1)}:
        relative = f"sessions/{day:%Y/%m/%d}/{session}/session.jsonl"
        if (home / relative).exists(): candidates.append(relative)
    if len(candidates) != 1:
        _fail("provider_journal_unavailable", "The newly created native session journal is unavailable; inspect retained captures.", outcome="uncertain")
    raw = read_regular(home, candidates[0], max_bytes=4*1048576)
    return raw, candidates[0]


def _journal_rows(raw):
    try: rows = [_native_json(line) for line in raw.splitlines() if line]
    except (ValueError, UnicodeError, RecursionError):
        _fail("provider_journal_invalid", "The new native session journal could not be interpreted.", outcome="uncertain")
    if any(type(v) is not dict or type(v.get("payload", {})) is not dict
           or type(v.get("payload", {}).get("event", {})) is not dict
           or type(v.get("payload", {}).get("record", {})) is not dict for v in rows):
        _fail("provider_journal_invalid", "The new native journal has an unsupported record shape.", outcome="uncertain")
    configured = [v.get("payload", {}).get("event", {}) for v in rows if v.get("payload", {}).get("event", {}).get("kind") == "model_request_configured"]
    metadata = [v.get("payload", {}).get("record", {}) for v in rows if v.get("payload", {}).get("kind") == "metadata"]
    return rows, configured, metadata[-1] if metadata else {}


def _journal(config, session):
    raw, _ = _journal_source(config, session)
    return _journal_rows(raw)


def _personal(messages):
    entries = []
    for message in messages:
        if message.get("source") == "skills":
            text = message.get("text", "")
            for block in re.findall(r"<skill\s[^>]*>.*?</skill>", text, flags=re.S):
                attrs = dict(re.findall(r'(\w+)="([^"]*)"', block.partition(">")[0]))
                if attrs.get("scope") != "bundled":
                    entries.append({"id": attrs.get("id"), "scope": attrs.get("scope"), "path": attrs.get("path"), "catalog_entry": block})
    return entries


def _summary(result):
    value = result.to_dict(); value.pop("stdout", None); value.pop("stderr", None)
    # The owner keeps bounded buffers while continuing to count/drain during
    # shutdown. These counts describe buffers before persistence redaction.
    value.update(observed_output_bytes=value.get("output_bytes"),
                 retained_stdout_bytes=len(result.stdout), retained_stderr_bytes=len(result.stderr),
                 retained_output_bytes=len(result.stdout) + len(result.stderr))
    return loads(json.dumps(value).encode())


def _task_model(config, request):
    if request["provider"] != "muse":
        _fail("provider_task_invalid", "This task selects a different provider.")
    models = {config["model"]}
    if config["model"] == "muse-wonder-full-1.0": models.add("wonder-full")
    if request["model"] not in models or request["reasoning_effort"] != config["reasoning_effort"]:
        _fail("provider_task_model_mismatch", "The task and configured model/effort disagree.")


def _budget(config, prompt):
    # Supported schema-1 session output echoes the complete prompt in BOTH
    # turn.input.user and run.lifecycle.started. Count minimal JSON frames,
    # including UTF-8 and JSON string escaping. Omitted native metadata, stderr,
    # output deltas and the final response can only require additional space.
    text = prompt.decode("utf-8")
    minimum = sum(len(json.dumps({"payload_type": kind, "payload": {"prompt": text}},
        ensure_ascii=False, separators=(",", ":")).encode("utf-8")) + 1
        for kind in ("turn.input.user", "run.lifecycle.started"))
    maximum = config["max_output_bytes"]
    return {"provider": "muse", "model_free": True, "controller_submissions": 0,
            "prompt_bytes": len(prompt), "input_echo_contract": "muse-session-input-echo/1",
            "minimum_input_echo_bytes": minimum, "max_output_bytes": maximum,
            "max_proposal_bytes": config.get("max_proposal_bytes", 65536),
            "input_echoes_fit": minimum < maximum,
            "remaining_after_minimum_echo_bytes": max(0, maximum - minimum),
            "response_fit_guaranteed": False}


def budget(store, *, request):
    """Pure local measurement: no native process, claim, output directory or run."""
    config = _configuration(store)
    pilot._request(request); screen_sensitive(request); _task_model(config, request)
    manifest, prompt = pilot._manifest(request)
    return {**_budget(config, prompt), "bundle_digest": manifest["digest"]}


def _environment(config, root):
    env = minimal_environment()
    env.update(config.get("native_roots", {}))
    env.update(HOME=config["account_home"], TMPDIR=str(root / "tmp"))
    env["XDG_DATA_HOME"] = str(Path(config["muse_home"]).parent)
    return env


def _owner_failed(result):
    return bool(getattr(result, "failure_code", None) or _summary(result).get("boundary_failures"))


def _preflight(config, root):
    if config["context"] == "exclude":
        _fail("provider_context_exclusion_unsupported", "This Muse client cannot fully exclude existing personal context while preserving its login. Choose include, explicit native-only partial exclusion, or another supported client configuration. No provider request was sent.")
    probe = root / "context-check"; probe.mkdir(mode=0o700)
    workspace = root / "workspace"; session = _uuid7()
    pilot._write(probe, "prompt.txt", b"TaskAlong local model-free context check.\n")
    env = _environment(config, root)
    result = run_foreground_experiment(_argv(config, provider="echo", workspace=workspace, prompt=probe/"prompt.txt", session=session),
        mode=FOREGROUND_EXPERIMENT, cwd=workspace, env=env, timeout_seconds=5, max_output_bytes=131072)
    pilot._write(probe, "stdout.bin", redact(result.stdout)); pilot._write(probe, "stderr.bin", redact(result.stderr))
    pilot._write(probe, "process.json", canonical_bytes(_summary(result)))
    if result.root_exit_code != 0 or result.timed_out or result.output_limited or result.cancelled or _owner_failed(result):
        _fail("provider_context_check_failed", "The local model-free context check failed; inspect its captures. No Meta request was sent.")
    rows, configured, _ = _journal(config, session)
    if len(configured) != 1:
        _fail("provider_context_check_failed", "The local check reported an unexpected request count. No Meta request was sent.")
    event = configured[0]
    if type(event.get("toolset")) is not dict or type(event.get("reminder_roster")) is not dict:
        _fail("provider_context_check_failed", "The native check has no usable tool/reminder metadata.")
    if event.get("toolset", {}).get("active_tools") != [] or event.get("reminder_roster", {}).get("agents") != []:
        _fail("provider_controls_changed", "The empty-tool/reminder settings were not observed. No Meta request was sent.")
    messages = event.get("run_context_messages", [])
    if type(messages) is not list or any(type(m) is not dict or type(m.get("text")) is not str for m in messages):
        _fail("provider_context_check_failed", "The native startup context has an unsupported shape.")
    screen_sensitive(messages)
    if config["catalog_digest"] is not None:
        known = {"workspace_identity", "capability_policy", "security_mode", "skills_catalog", "meta_context_note", "session_identity", "rules_file"}
        if any(m.get("id") not in known for m in messages):
            _fail("provider_context_changed", "An additional startup context message appeared; inspect it before sending this scoped task.")
    for message_id, expected in {**config["public_context_hashes"], **config.get("context_hashes", {})}.items():
        matching = [m for m in messages if m.get("id") == message_id]
        if len(matching) != 1 or hashlib.sha256(matching[0]["text"].encode()).hexdigest() != expected:
            _fail("provider_context_changed", "A pinned startup message is missing, duplicated or changed; inspect it before sending this scoped task.")
    entries = _personal(messages); content_digest = hashlib.sha256(canonical_bytes(entries)).hexdigest()
    pilot._write(probe, "context.json", canonical_bytes({"messages": messages, "personal_catalog": entries}))
    observation = {"context": config["context"], "catalog_digest": content_digest, "catalog_entries": len(entries),
                   "model_free": True, "process": _summary(result), "review_file": str(probe / "context.json")}
    pilot._write(probe, "observation.json", canonical_bytes(observation))
    if config["catalog_digest"] is not None and config["catalog_digest"] != content_digest:
        _fail("provider_context_changed", "The selected context catalog changed. Review the local snapshot before sending this task.",
              recovery=[{"action":"review_context","file":str(probe/"context.json"),"catalog_digest":content_digest}])
    if any("hook" in v.get("payload", {}).get("event", {}).get("kind", "").lower() for v in rows):
        _fail("provider_hooks_observed", "Startup hook activity was observed in the local check; inspect it before this text-only task.")
    return observation



def context_snapshot(store, *, output):
    """Inspect configured startup context locally; never construct a Meta call."""
    config = _configuration(store)
    if sys.platform != "darwin":
        _fail("provider_platform_unsupported", "The current native Muse owner supports macOS.")
    root = pilot._destination(output)
    root.mkdir(mode=0o700)
    (root / "workspace").mkdir(mode=0o700)
    (root / "tmp").mkdir(mode=0o700)
    return _preflight(config, root)


def _session_records(raw, session):
    try:
        rows = [_native_json(line) for line in raw.splitlines() if line]
        if not 1 <= len(rows) <= 2048: raise ValueError()
        run = None; sequence = 0
        for row in rows:
            if (type(row) is not dict or type(row.get("schema_version")) is not int or row["schema_version"] != 1
                    or row.get("stream") != {"kind":"session","id":session}
                    or type(row.get("sequence")) is not int or row["sequence"] <= sequence): raise ValueError()
            sequence = row["sequence"]; payload = row.get("payload", {})
            if type(payload) is not dict or type(row.get("payload_type", "")) is not str: raise ValueError()
            reference = payload.get("run_stream")
            if reference is not None:
                if type(reference) is not dict or reference.get("kind") != "run" or type(reference.get("id")) is not str: raise ValueError()
                if run is None: run = reference["id"]
                if reference["id"] != run: raise ValueError()
        if run is None: raise ValueError()
        return rows, run
    except (ValueError, TypeError, AttributeError, KeyError, UnicodeError, RecursionError):
        _fail("provider_response_unrecognized", "The captured native output has no unambiguous completed response; preserve it without redispatch.", outcome="uncertain")


def _decode(raw, session, *, max_proposal_bytes=65536):
    try:
        rows, run = _session_records(raw, session)
        terminal = []
        for row in rows:
            payload = row["payload"]
            if row.get("payload_type", "").startswith("run.terminal."):
                if payload.get("kind") != "run_terminal" or payload.get("terminal") != "completed" or type(payload.get("text")) is not str: raise ValueError()
                terminal.append(payload["text"])
        if len(terminal) != 1 or run is None: raise ValueError()
        text = terminal[0].strip()
        if text.startswith("```json\n") and text.endswith("\n```"):
            text = text[8:-4].strip()
        response = loads(text)
        if len(canonical_bytes(response)) > max_proposal_bytes:
            _fail("provider_proposal_too_large", "The decoded proposal exceeds its separate configured byte limit; preserve captures without redispatch.", outcome="uncertain")
        return response, run
    except (ValueError, TypeError, AttributeError, KeyError, UnicodeError, RecursionError):
        _fail("provider_response_unrecognized", "The captured native output has no unambiguous completed response; preserve it without redispatch.", outcome="uncertain")


def _event(store, record, root, state, **values):
    value = {**record, **values, "state": state, "revision": record["revision"] + 1, "at": now()}
    value.pop("digest", None); value["digest"] = digest(value)
    pilot._write(root, f"events/{value['revision']:04d}.json", canonical_bytes(value))
    store.set_setting("provider-run:" + value["run_id"], value)
    return value


def _claim(store, bundle_root, manifest, record):
    key = "provider-claim:muse:" + manifest["digest"]
    with store.transaction() as db:
        if db.execute("SELECT 1 FROM settings WHERE name=?", (key,)).fetchone():
            _fail("provider_already_submitted", "This prepared task already reserved a provider submission. Inspect its existing result; automatic redispatch is forbidden.")
        db.execute("INSERT INTO settings VALUES (?,?)", (key, canonical_bytes({"run_id":record["run_id"],"bundle_digest":manifest["digest"],"output":record["output"]}).decode()))
        pilot._write(bundle_root, "provider-submission.json", canonical_bytes({"provider":"muse","run_id":record["run_id"],"bundle_digest":manifest["digest"]}))


def run(store, *, bundle=None, request=None, output=None, _successor=None):
    config = _configuration(store)
    if sys.platform != "darwin":
        _fail("provider_platform_unsupported", "The current native Muse owner supports macOS.")
    if (bundle is None) == (request is None):
        _fail("provider_task_invalid", "Select one prepared bundle or explicit task request.")
    if config["context"] == "exclude":
        _fail("provider_context_exclusion_unsupported", "This Muse version cannot fully exclude personal context with the existing login. Include is the default; native-only is partial exclusion. No provider request was sent.")
    if _successor is not None:
        from .muse_successor import _check
        _check(store, _successor, config)
        if output != _successor["output"] or bundle is not None:
            _fail("provider_successor_invalid", "Use the exact reserved successor output and original task.")
    run_id = identifier() if _successor is None else _successor["run_id"]
    if output is None:
        parent = store.root / "provider-output"; parent.mkdir(mode=0o700, exist_ok=True); output = str(parent / run_id)
    root = pilot._destination(output)
    if bundle is not None:
        bundle_root, manifest = pilot._bundle(bundle)
        if store.setting("provider-claim:muse:" + manifest["digest"]) or (bundle_root/"provider-submission.json").exists() or (bundle_root/"response-claim.json").exists():
            _fail("provider_already_submitted", "This task already reserved a submission; inspect existing evidence without redispatch.")
    else:
        pilot._request(request); screen_sensitive(request)
        bundle_root = root / "bundle"; manifest, _ = pilot._manifest(request)
        if _successor is None and store.setting("provider-claim:muse:" + manifest["digest"]):
            _fail("provider_already_submitted", "This task already reserved a submission; inspect existing evidence or use an eligible explicit successor.")
    _task_model(config, manifest["request"])
    if _successor is not None and manifest["digest"] != _successor["bundle_digest"]:
        _fail("provider_successor_invalid", "The successor must keep the original task intent unchanged.")
    screen_sensitive(manifest["request"])
    prompt = pilot._prompt(manifest["request"], manifest["digest"])
    capture_budget = _budget(config, prompt)
    if not capture_budget["input_echoes_fit"]:
        _fail("provider_capture_budget_insufficient",
              f"Native input echoes alone require at least {capture_budget['minimum_input_echo_bytes']} bytes; the configured whole-protocol cap is {config['max_output_bytes']}. Reduce the explicit snapshot or configure a supported finite cap. Additional response space is still required. No provider request was sent.")
    root.mkdir(mode=0o700); (root/"workspace").mkdir(mode=0o700); (root/"tmp").mkdir(mode=0o700)
    if request is not None: pilot.prepare(request, output=str(bundle_root))
    pilot._write(root, "prompt.txt", prompt)
    record = {"format":"local-provider-run/1","provider":"muse","experimental":True,"run_id":run_id,"revision":0,
              "configuration_digest":config["digest"],"bundle_digest":manifest["digest"],"bundle":str(bundle_root),"output":str(root),
              "controller_submissions":0,"automatic_retry_allowed":False,"patch_applied":False,"acceptance_allowed":False,"capture_budget":capture_budget,
              "production_dispatch_allowed":False,"remote_usage":"not_sent","native_internal_retries":"unknown","descendant_cessation":"unknown"}
    if _successor is not None:
        record.update(format="local-provider-run/2",manual_successor=_successor)
    record = _event(store, record, root, "preflight")
    claimed = False
    try:
        context = _preflight(config, root)
        if _observe_file(config["binary"]["path"], executable=True) != config["binary"]:
            _fail("provider_executable_changed", "The installed binary changed before submission; configure it again.")
        _, fresh = pilot._bundle(str(bundle_root))
        if fresh["digest"] != manifest["digest"]: _fail("provider_task_changed", "The task changed before submission.")
        if _successor is None:
            _claim(store, bundle_root, manifest, record)
        else:
            from .muse_successor import claim_submission
            claim_submission(store, bundle_root, manifest, record, _successor, config)
        claimed = True
        record = _event(store, record, root, "starting", controller_submissions=1, remote_usage="unknown", context=context)
        session = _uuid7()
        argv = _argv(config, provider="meta", workspace=root/"workspace", prompt=root/"prompt.txt", session=session)
        pilot._write(root, "invocation.json", canonical_bytes({"argv":argv,"session_id":session,"configuration_digest":config["digest"],"bundle_digest":manifest["digest"]}))
        def spawned(receipt):
            nonlocal record
            if _observe_file(config["binary"]["path"], executable=True) != config["binary"]:
                _fail("provider_executable_changed", "The native binary changed before gate release.")
            read_regular(root,"prompt.txt",max_bytes=len(prompt),expected_sha256=hashlib.sha256(prompt).hexdigest(),private=True,expected_mode=0o400)
            if _successor is not None:
                _check(store, _successor, config)
            record = _event(store, record, root, "running", process_receipt=receipt.to_dict())
        env = _environment(config, root)
        result = run_foreground_experiment(argv, mode=FOREGROUND_EXPERIMENT, cwd=root/"workspace", env=env,
            timeout_seconds=config["attempt_seconds"], max_output_bytes=config["max_output_bytes"], signal_grace_seconds=.5,
            on_spawn=spawned, cancel_requested=lambda:(root/"cancel-request.json").exists())
        pilot._write(root,"stdout.bin",redact(result.stdout)); pilot._write(root,"stderr.bin",redact(result.stderr))
        pilot._write(root,"process.json",canonical_bytes(_summary(result)))
        if result.root_exit_code != 0 or result.timed_out or result.cancelled or result.output_limited or _owner_failed(result):
            return _event(store,record,root,"failed",process=_summary(result),error="provider_local_failure",remote_usage="unknown")
        response, native_run = _decode(result.stdout, session, max_proposal_bytes=config.get("max_proposal_bytes", 65536))
        screen_sensitive(response); pilot._proposal(manifest,response)
        _, events, metadata = _journal(config, session)
        observations = {"requested_provider":"meta","requested_model":config["model"],"requested_effort":config["reasoning_effort"],
                        "reported_provider":metadata.get("provider_id"),"reported_model":metadata.get("model_id"),"reported_effort":metadata.get("reasoning_effort"),
                        "configured_model_requests_observed":len(events),"native_run_id":native_run}
        if metadata.get("provider_id") != "meta" or metadata.get("model_id") != config["model"]:
            _fail("provider_response_identity_mismatch", "The native journal reports a different provider or model; inspect the captured output.", outcome="uncertain")
        pilot._write(root,"response.json",canonical_bytes(response))
        proposal = pilot.stage(bundle=str(bundle_root),response=response,output=str(root/"proposal"))
        return _event(store,record,root,"proposal_ready",process=_summary(result),execution=observations,
                      proposal_path=str(root/"proposal/proposed.patch"),review_path=str(root/"proposal/review.json"),proposal_digest=proposal["digest"],remote_usage="unknown")
    except (TaskAlongError, ProcessBoundaryError, OSError) as exc:
        code = exc.code if hasattr(exc,"code") else "provider_local_io"
        record = _event(store,record,root,"blocked" if not claimed else "failed",error=code,remote_usage="unknown" if claimed else "not_sent")
        if isinstance(exc,TaskAlongError):
            raise TaskAlongError(exc.code,exc.message,exit_code=exc.exit_code,effect_outcome="uncertain" if claimed else "not_sent",
                                 recovery=[{"action":"inspect_provider_run","run_id":run_id,"output":str(root)},*exc.recovery]) from None
        _fail(code,"The provider attempt could not complete; preserve captures without redispatch.",outcome="uncertain" if claimed else "not_sent",recovery=[{"action":"inspect_provider_run","run_id":run_id,"output":str(root)}])
    except KeyboardInterrupt:
        _event(store,record,root,"interrupted",remote_usage="unknown" if claimed else "not_sent")
        raise


def inspect(store, run_id):
    if type(run_id) is not str: return None
    record = store.setting("provider-run:" + run_id)
    if record is not None: return record
    from .muse_successor import inspect_reserved
    return inspect_reserved(store, run_id)
