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
from . import muse_response_schema as schema
from .artifact_io import read_regular, _file_state, _parent, _regular, _unchanged_directories
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
_KEYS = {"executable", "account_home", "muse_home", "model", "reasoning_effort", "context", "catalog_digest", "public_context_hashes", "context_hashes", "native_roots", "attempt_seconds", "max_output_bytes", "max_proposal_bytes", "capture_profile", "max_protocol_records", "response_contract"}
_IMPLEMENTATION = (720, 4*1048576, 65536, 8192)
_MEGABYTE = "local-muse-provider/6"
_MEGABYTE_RAW = 64 * 1048576
_MEGABYTE_RECORDS = 131072
_MEGABYTE_FRAME = 16 * 1048576
_NATIVE_STOP_POLICY = "stop-on-first-model-failure-or-second-model-task/1"


def _megabyte(config):
    return config.get("format") in {_MEGABYTE, schema.FORMAT}


def _prompt(config, manifest):
    original = pilot._prompt(manifest["request"], manifest["digest"])
    return schema.prompt(original) if config.get("format") == schema.FORMAT else original


def _native_guard(successor, config, session):
    # Old sealed operations retain their exact execution contract. The explicit
    # interrupted successor adds a local observer, not a hard remote-call cap.
    if config.get("format") == schema.FORMAT:
        return schema.SingleAttemptGuard(session, max_records=_max_records(config), max_frame_bytes=_MEGABYTE_FRAME)
    if successor is None or successor.get("format") not in {"manual-muse-successor/4", "manual-muse-successor/5", "manual-muse-successor/6"}:
        return None
    if successor.get("native_lifecycle_policy") != _NATIVE_STOP_POLICY:
        _fail("provider_successor_invalid", "The interrupted successor requires its bound native stop policy.")
    from .muse_native_lifecycle import NativeModelTaskGuard
    return NativeModelTaskGuard(session, max_records=_max_records(config), max_frame_bytes=_MEGABYTE_FRAME)


def _max_records(config):
    # Never reinterpret an old cohort by adding defaults to its sealed bytes.
    return config["max_protocol_records"] if config["format"] in {"local-muse-provider/5", _MEGABYTE, schema.FORMAT} else 8192 if config["format"] == "local-muse-provider/4" else 2048


class _RecordBudget:
    """Count complete stdout records; never filter or replace their bytes."""
    def __init__(self, maximum=8192):
        self.observed = 0
        self.limited = False
        self.maximum = maximum

    def observe(self, line):
        if line:
            self.observed += 1
            if self.observed > self.maximum:
                self.limited = True
                _fail("provider_protocol_record_limit", "The finite protocol record budget was exceeded.", outcome="uncertain")


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
    profile = value.get("capture_profile")
    if profile is not None and (type(profile) is not str or profile not in {"implementation", "large-task", "megabyte-proposal"}):
        _fail("provider_config_invalid", "Select the supported implementation capture profile or omit it.")
    contract = value.get("response_contract")
    if contract is not None and (contract != schema.CONTRACT or profile != "megabyte-proposal"):
        _fail("provider_config_invalid", "Schema transport requires its explicit version and megabyte-proposal profile.")
    large_task = profile == "large-task"
    megabyte = profile == "megabyte-proposal"
    seconds = value.get("attempt_seconds", 1440 if large_task else 720 if profile else 20)
    maximum = value.get("max_output_bytes", _MEGABYTE_RAW if megabyte else 4*1048576 if profile else 65536)
    proposal_maximum = value.get("max_proposal_bytes", 1048576 if megabyte else 65536)
    records = value.get("max_protocol_records", _MEGABYTE_RECORDS if megabyte else 8192)
    if ("max_protocol_records" in value and not (large_task or megabyte)
            or type(records) is not int or not 2 <= records <= (_MEGABYTE_RECORDS if megabyte else 8192)):
        _fail("provider_config_invalid", "Explicit finite record limits require the large-task profile.")
    catalog_digest = value.get("catalog_digest")
    if (type(model) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", model)
            or type(effort) is not str or effort not in _EFFORTS
            or type(context) is not str or context not in _CONTEXT
            or type(seconds) is not int or not 1 <= seconds <= (1440 if large_task or megabyte else 720)
            or type(maximum) is not int or not 1024 <= maximum <= (_MEGABYTE_RAW if megabyte else 4*1048576 if profile else 1048576)
            or type(proposal_maximum) is not int or not 1024 <= proposal_maximum <= (1048576 if megabyte else 262144)
            or catalog_digest is not None and (type(catalog_digest) is not str or not re.fullmatch(r"[a-f0-9]{64}", catalog_digest))):
        _fail("provider_config_invalid", "Select valid model, effort, context and finite local limits.")
    if profile == "implementation" and (seconds, maximum, proposal_maximum) != _IMPLEMENTATION[:3]:
        _fail("provider_config_invalid", "Implementation capture requires exactly 720 seconds, 4 MiB protocol and 64 KiB proposal.")
    if large_task and proposal_maximum > 65536:
        _fail("provider_config_invalid", "Large-task proposals remain capped at 64 KiB.")
    if megabyte and (maximum, records) != (_MEGABYTE_RAW, _MEGABYTE_RECORDS):
        _fail("provider_config_invalid", "Megabyte proposals require exactly 64 MiB protocol capture and 131072 records.")
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
    config = {"format": schema.FORMAT if contract else _MEGABYTE if megabyte else "local-muse-provider/5" if large_task else "local-muse-provider/4" if profile else "local-muse-provider/3", "provider": "muse", "experimental": True,
              "binary": binary, "account_home": str(home), "muse_home": str(muse_home), "native_roots": native_roots, "model": model,
              "reasoning_effort": effort, "context": context, "catalog_digest": catalog_digest, "public_context_hashes": public_hashes, "context_hashes": context_hashes,
              "attempt_seconds": seconds, "max_output_bytes": maximum, "max_proposal_bytes": proposal_maximum}
    if profile:
        config.update(capture_profile=profile, max_protocol_records=records)
    if contract:
        config["response_contract"] = contract
    config["digest"] = digest(config)
    with store.transaction() as db:
        db.execute("INSERT OR IGNORE INTO settings VALUES (?,?)", ("provider-config:" + config["digest"], canonical_bytes(config).decode()))
        db.execute("INSERT INTO settings VALUES (?,?) ON CONFLICT(name) DO UPDATE SET document=excluded.document", (_CONFIG, canonical_bytes(config).decode()))
    return {"provider": "muse", "configured": True, "experimental": True, "configuration_digest": config["digest"],
            "context": context, "model": model, "reasoning_effort": effort, "activation_required": False,
            "attempt_seconds": seconds, "max_output_bytes": maximum, "max_proposal_bytes": proposal_maximum,
            "max_protocol_records": _max_records(config)}


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
    if type(config) is not dict or config.get("format") not in ("local-muse-provider/1", "local-muse-provider/2", "local-muse-provider/3", "local-muse-provider/4", "local-muse-provider/5", _MEGABYTE, schema.FORMAT) or config.get("digest") != digest(config):
        _fail("provider_configuration_changed", "The local provider configuration is inconsistent; configure it again.")
    large_task = config["format"] == "local-muse-provider/5"
    megabyte = _megabyte(config)
    if (config["format"] == schema.FORMAT and config.get("response_contract") != schema.CONTRACT
            or config["format"] != schema.FORMAT and "response_contract" in config):
        _fail("provider_configuration_changed", "The response contract does not match this sealed configuration version.")
    implementation = config["format"] in {"local-muse-provider/4", "local-muse-provider/5", _MEGABYTE, schema.FORMAT}
    if implementation:
        if (config.get("capture_profile") != ("megabyte-proposal" if megabyte else "large-task" if large_task else "implementation")
                or type(config.get("max_protocol_records")) is not int
                or not (large_task or megabyte) and tuple(config.get(k) for k in ("max_output_bytes", "max_proposal_bytes", "max_protocol_records")) != _IMPLEMENTATION[1:]
                or megabyte and (config.get("max_output_bytes"), config.get("max_protocol_records")) != (_MEGABYTE_RAW, _MEGABYTE_RECORDS)
                or large_task and not 2 <= config["max_protocol_records"] <= 8192
                or not (large_task or megabyte) and config.get("attempt_seconds") != _IMPLEMENTATION[0]):
            _fail("provider_configuration_changed", "The implementation capture profile is inconsistent.")
    elif "capture_profile" in config or "max_protocol_records" in config:
        _fail("provider_configuration_changed", "Legacy capture identities cannot declare implementation bounds.")
    ceiling = 1440 if large_task or megabyte else 720 if config["format"] in {"local-muse-provider/3", "local-muse-provider/4"} else 60
    if type(config.get("attempt_seconds")) is not int or not 1 <= config["attempt_seconds"] <= ceiling:
        _fail("provider_configuration_changed", "The provider deadline is invalid for its configuration format.")
    if type(config.get("max_output_bytes")) is not int or not 1024 <= config["max_output_bytes"] <= (_MEGABYTE_RAW if megabyte else 4*1048576 if implementation else 1048576):
        _fail("provider_configuration_changed", "The whole-protocol capture limit is invalid.")
    if config["format"] != "local-muse-provider/1" and (type(config.get("max_proposal_bytes")) is not int or not 1024 <= config["max_proposal_bytes"] <= (1048576 if megabyte else 65536 if large_task else 262144)):
        _fail("provider_configuration_changed", "This provider configuration requires an explicit finite proposal limit; configure it again.")
    if _observe_file(config["binary"]["path"], executable=True) != config["binary"]:
        _fail("provider_executable_changed", "The configured binary changed; configure the installed provider again.")
    return config


def _argv(config, *, provider, workspace, prompt, session, output_schema=None):
    argv = [config["binary"]["path"], "exec", "--json", "--provider", provider, "--session-id", session,
            "--preset", "empty", "--permission-profile", ":read-only", "--workspace", str(workspace),
            "--prompt-file", str(prompt), "--max-model-steps", "1", "--disable-reminders", "--disable-web-tools",
            "--disable-write", "--disable-shell", "--disable-request-user-input", "--contributor-mode", "off"]
    if config["context"] == "native-only": argv.append("--no-foreign-personal-context")
    if provider == "meta":
        argv += ["--model", config["model"], "--reasoning-effort", config["reasoning_effort"], "--no-parallel-tool-calls"]
    if config.get("format") == schema.FORMAT and provider == "meta":
        if output_schema is None:
            _fail("provider_schema_missing", "Schema transport requires its private bound schema file.")
        argv += ["--output-schema", str(output_schema)]
    elif output_schema is not None:
        _fail("provider_schema_invalid", "Legacy invocations cannot acquire a new response contract.")
    return argv


class _JournalDecimal(str):
    """Keep a decimal wire token distinguishable from an identity string."""


def _native_json(raw, *, max_bytes=None, _journal_numbers=False):
    # Preserve native decimal observations as text, not invented rounded totals.
    # Only the new /6 frame path opts into expanded wire/object bounds. Legacy
    # journal/context readers retain their existing separately bounded dialect.
    if max_bytes is not None:
        if type(max_bytes) is not int or max_bytes != _MEGABYTE_FRAME or type(raw) not in (bytes, str):
            raise ValueError("native frame bound")
        encoded = raw if type(raw) is bytes else raw.encode("utf-8", errors="strict")
        if len(encoded) > max_bytes:
            raise ValueError("native frame bound")
        raw = encoded.decode("utf-8", errors="strict")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError("duplicate native key")
            result[key] = value
        return result
    if type(_journal_numbers) is not bool or _journal_numbers and max_bytes != _MEGABYTE_FRAME:
        raise ValueError("journal numeric mode")
    value = json.loads(raw, object_pairs_hook=pairs, parse_float=_JournalDecimal if _journal_numbers else str,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
    if max_bytes is not None:
        if type(value) is not dict:
            raise ValueError("native frame root")
        stack = [(value, 0)]
        nodes = 0
        while stack:
            item, depth = stack.pop()
            nodes += 1
            if depth > 64 or nodes > 65536:
                raise ValueError("native frame shape")
            if type(item) in (str, _JournalDecimal):
                if len(item.encode("utf-8", errors="strict")) > max_bytes:
                    raise ValueError("native frame string")
            elif type(item) is int:
                if abs(item) > 2**53 - 1:
                    raise ValueError("native frame integer")
            elif item is None or type(item) is bool:
                continue
            elif type(item) in (dict, list):
                if len(item) > 4096:
                    raise ValueError("native frame container")
                if type(item) is dict:
                    stack.extend((key, depth + 1) for key in item)
                    stack.extend((child, depth + 1) for child in item.values())
                else:
                    stack.extend((child, depth + 1) for child in item)
            else:
                raise ValueError("native frame value")
    return value


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


def _journal_identity_path(home, session, days):
    """Select one existing journal through held no-follow directory chains."""
    candidates = []
    for day in days:
        relative = f"sessions/{day:%Y/%m/%d}/{session}/session.jsonl"
        with _parent(home, relative, private=False, missing_ok=True) as (parent, name, links):
            if parent is None:
                continue
            try:
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                _unchanged_directories(links)
                continue
            _regular(info, private=False, max_bytes=_MEGABYTE_RAW)
            _unchanged_directories(links)
            candidates.append((relative, _file_state(info)))
    if len(candidates) != 1:
        _fail("provider_journal_unavailable", "The newly created native session journal is unavailable or ambiguous; preserve captures.", outcome="uncertain")
    return candidates[0]


def _journal_identity(config, session, *, native_run=None, started_unix_ms=None):
    """Observe /6 identity without retaining the journal or configured events.

    The native journal has its own 64 MiB/131072-record/16 MiB-frame bounds.
    Directory and exact file metadata remain fenced while a second streaming
    hash pass verifies the bytes consumed by the first pass. This is an observed
    stability check, not isolation from another process running as the operator.
    Legacy context discovery continues through the separate four-MiB reader.
    """
    try:
        if (not _megabyte(config) or type(session) is not str
                or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", session) is None):
            raise ValueError("journal binding")
        home = pilot._root(config["muse_home"])
        if started_unix_ms is None:
            instant = datetime.datetime.now(datetime.timezone.utc)
        else:
            if type(started_unix_ms) is not int or started_unix_ms <= 0:
                raise ValueError("journal timestamp")
            instant = datetime.datetime.fromtimestamp(started_unix_ms / 1000, datetime.timezone.utc)
        dates = {instant.astimezone().date(), instant.date()}
        days = {day + datetime.timedelta(days=n) for day in dates for n in (-1, 0, 1)}
        relative, selected = _journal_identity_path(home, session, days)
        journal_run = native_run
        def check_run(value):
            nonlocal journal_run
            if type(value) is not str or not 1 <= len(value) <= 128 or not value.isprintable():
                raise ValueError("journal run")
            if journal_run is None:
                journal_run = value
            elif value != journal_run:
                raise ValueError("journal run")
        if native_run is not None:
            check_run(native_run)
        def check_bindings(binding):
            if "session_id" in binding and (type(binding["session_id"]) is not str or binding["session_id"] != session):
                raise ValueError("journal session")
            if "run_id" in binding:
                check_run(binding["run_id"])
            for key, kind in (("run_stream", "run"), ("session_stream", "session")):
                if key in binding:
                    reference = binding[key]
                    if type(reference) is not dict or type(reference.get("kind")) is not str or reference["kind"] != kind:
                        raise ValueError("journal stream binding")
                    if kind == "run":
                        check_run(reference.get("id"))
                    elif type(reference.get("id")) is not str or reference["id"] != session:
                        raise ValueError("journal session")
        with _parent(home, relative, private=False) as (parent, name, links):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=parent)
            try:
                def guard():
                    held = os.fstat(fd)
                    entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    _regular(held, private=False, max_bytes=_MEGABYTE_RAW)
                    _regular(entry, private=False, max_bytes=_MEGABYTE_RAW)
                    if _file_state(held) != selected or _file_state(entry) != selected:
                        raise ValueError("journal changed")
                    _unchanged_directories(links)
                    return held.st_size
                size = guard()
                first_hash = hashlib.sha256()
                records = total = configured = sequence = 0
                metadata = {}
                with os.fdopen(os.dup(fd), "rb", buffering=65536) as stream:
                    while True:
                        line = stream.readline(_MEGABYTE_FRAME + 2)
                        if not line:
                            break
                        records += 1
                        total += len(line)
                        if (records > _MEGABYTE_RECORDS or total > _MEGABYTE_RAW
                                or not line.endswith(b"\n") or not 1 <= len(line) - 1 <= _MEGABYTE_FRAME):
                            raise ValueError("journal framing")
                        first_hash.update(line)
                        row = _native_json(line[:-1], max_bytes=_MEGABYTE_FRAME, _journal_numbers=True)
                        # Older journal rows have no session-stream envelope;
                        # any supplied native binding must still agree exactly.
                        if "stream" in row:
                            reference = row["stream"]
                            if (type(reference) is not dict or reference != {"kind": "session", "id": session}
                                    or type(reference.get("id")) is not str or type(reference.get("kind")) is not str):
                                raise ValueError("journal session")
                        if "sequence" in row:
                            if type(row["sequence"]) is not int or row["sequence"] <= sequence:
                                raise ValueError("journal sequence")
                            sequence = row["sequence"]
                        payload = row.get("payload", {})
                        if (type(payload) is not dict or type(payload.get("event", {})) is not dict
                                or type(payload.get("record", {})) is not dict):
                            raise ValueError("journal payload")
                        record = payload.get("record", {})
                        for binding in (row, payload, record, payload.get("event", {})):
                            check_bindings(binding)
                        if payload.get("event", {}).get("kind") == "model_request_configured":
                            configured += 1
                        if payload.get("kind") == "metadata":
                            if len(json.dumps(record, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")) > 65536:
                                raise ValueError("journal metadata bound")
                            metadata = {}
                            for key in ("provider_id", "model_id", "reasoning_effort"):
                                if key in record:
                                    value = record[key]
                                    if not (key == "reasoning_effort" and value is None) and (type(value) is not str
                                            or not 1 <= len(value.encode("utf-8")) <= 256 or not value.isprintable()):
                                        raise ValueError("journal identity")
                                    metadata[key] = value
                if not records or total != size:
                    raise ValueError("journal length")
                guard()
                os.lseek(fd, 0, os.SEEK_SET)
                final_hash = hashlib.sha256()
                verified = 0
                while verified <= size:
                    chunk = os.read(fd, min(65536, size + 1 - verified))
                    if not chunk:
                        break
                    verified += len(chunk)
                    final_hash.update(chunk)
                if verified != size or first_hash.digest() != final_hash.digest():
                    raise ValueError("journal bytes changed")
                guard()
                if _journal_identity_path(home, session, days) != (relative, selected):
                    raise ValueError("journal selection changed")
                guard()
                return configured, metadata
            finally:
                os.close(fd)
    except (TaskAlongError, OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, OverflowError):
        _fail("provider_journal_invalid", "The new native journal identity observation is unavailable, changed or outside its finite bounds; preserve captures.", outcome="uncertain")


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
    if _megabyte(config) and len(prompt) > 1048576:
        _fail("provider_prompt_too_large", "The prompt exceeds the unchanged one MiB input limit.")
    text = prompt.decode("utf-8")
    minimum = sum(len(json.dumps({"payload_type": kind, "payload": {"prompt": text}},
        ensure_ascii=False, separators=(",", ":")).encode("utf-8")) + 1
        for kind in ("turn.input.user", "run.lifecycle.started"))
    maximum = config["max_output_bytes"]
    value = {"provider": "muse", "model_free": True, "controller_submissions": 0,
            "attempt_seconds": config.get("attempt_seconds"),
            "prompt_bytes": len(prompt), "input_echo_contract": "muse-session-input-echo/1",
            "minimum_input_echo_bytes": minimum, "max_output_bytes": maximum,
            "max_proposal_bytes": config.get("max_proposal_bytes", 65536),
            "input_echoes_fit": minimum < maximum,
            "remaining_after_minimum_echo_bytes": max(0, maximum - minimum),
            "response_fit_guaranteed": False}
    if config.get("format") in {"local-muse-provider/4", "local-muse-provider/5", _MEGABYTE, schema.FORMAT}:
        value.update(capture_profile=config["capture_profile"], max_protocol_records=_max_records(config))
    return value


def budget(store, *, request):
    """Pure local measurement: no native process, claim, output directory or run."""
    config = _configuration(store)
    pilot._request(request); screen_sensitive(request); _task_model(config, request)
    manifest, _ = pilot._manifest(request)
    prompt = _prompt(config, manifest)
    if config["format"] == schema.FORMAT:
        schema.document(request, manifest["digest"], config["max_proposal_bytes"])
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


def _session_records(raw, session, *, max_records=2048):
    try:
        rows = [_native_json(line) for line in raw.splitlines() if line]
        if type(max_records) is not int or max_records not in (2048,8192) or not 1 <= len(rows) <= max_records: raise ValueError()
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


def _decode_megabyte(raw, session, *, max_proposal_bytes, max_records, _terminal_only=False):
    """Iterate bounded wire frames, retaining only one terminal response."""
    from .provider_wire import loads_wire
    try:
        if (type(max_records) is not int or max_records != _MEGABYTE_RECORDS
                or type(max_proposal_bytes) is not int or not 1024 <= max_proposal_bytes <= 1048576):
            raise ValueError()
        if type(raw) is bytes:
            if not raw or len(raw) > _MEGABYTE_RAW or not raw.endswith(b"\n"):
                raise ValueError()
            def byte_records():
                offset = 0
                while offset < len(raw):
                    end = raw.find(b"\n", offset)
                    if end < offset or end - offset > _MEGABYTE_FRAME:
                        raise ValueError()
                    yield raw[offset:end]
                    offset = end + 1
            records = byte_records()
        else:
            # The finalized capture iterator owns framing, held-file identity,
            # full-stream hash verification and bounded pread buffers.
            records = iter(raw)
        run = None
        terminal = None
        sequence = count = total = 0
        for line in records:
            if type(line) is not bytes or len(line) > _MEGABYTE_FRAME or b"\n" in line:
                raise ValueError()
            count += 1
            total += len(line) + 1
            if count > max_records or total > _MEGABYTE_RAW or not line:
                raise ValueError()
            row = _native_json(line, max_bytes=_MEGABYTE_FRAME)
            if (type(row.get("schema_version")) is not int or row["schema_version"] != 1
                    or row.get("stream") != {"kind": "session", "id": session}
                    or type(row.get("sequence")) is not int or row["sequence"] <= sequence
                    or type(row.get("payload_type")) is not str or not row["payload_type"]
                    or type(row.get("payload")) is not dict):
                raise ValueError()
            sequence = row["sequence"]
            payload = row["payload"]
            reference = payload.get("run_stream")
            if reference is not None:
                if (type(reference) is not dict or reference.get("kind") != "run"
                        or type(reference.get("id")) is not str or not reference["id"]
                        or len(reference["id"]) > 128 or not reference["id"].isprintable()):
                    raise ValueError()
                if run is not None and reference["id"] != run:
                    raise ValueError()
                run = reference["id"]
            if row["payload_type"].startswith("run.terminal."):
                if (terminal is not None or row["payload_type"] != "run.terminal.completed" or payload.get("kind") != "run_terminal"
                        or payload.get("terminal") != "completed" or type(payload.get("text")) is not str
                        or reference is None):
                    raise ValueError()
                terminal = payload["text"]
        if run is None or terminal is None:
            raise ValueError()
        if len(terminal.encode("utf-8")) > 4194304:
            raise ValueError()
        if _terminal_only:
            return terminal, run
        text = terminal.strip()
        if text.startswith("```json\n") and text.endswith("\n```"):
            text = text[8:-4].strip()
        response = loads_wire(text, max_bytes=4194304)
        # Measure the complete canonical response before applying the unchanged
        # authority JSON serializer, whose independent ceiling remains one MiB.
        encoded = json.dumps(response, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(encoded) > max_proposal_bytes:
            _fail("provider_proposal_too_large", "The decoded proposal exceeds its separate configured byte limit; preserve captures without redispatch.", outcome="uncertain")
        canonical_bytes(response)
        return response, run
    except (ValueError, TypeError, AttributeError, KeyError, UnicodeError, RecursionError, TaskAlongError) as exc:
        if isinstance(exc, TaskAlongError) and exc.code == "provider_proposal_too_large":
            raise
        _fail("provider_response_unrecognized", "The captured native output has no unambiguous completed response; preserve it without redispatch.", outcome="uncertain")


def _decode(raw, session, *, max_proposal_bytes=65536, max_records=2048, megabyte=False):
    if megabyte:
        return _decode_megabyte(raw, session, max_proposal_bytes=max_proposal_bytes, max_records=max_records)
    try:
        if max_records==8192 and not raw.endswith(b'\n'):raise ValueError()
        rows, run = _session_records(raw, session, max_records=max_records)
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
        # Recheck under the same write lock as claim allocation: an interrupted
        # Max history/anchor may have appeared during model-free preflight.
        from .muse_successor import guard_effort_replay
        guard_effort_replay(store, manifest["request"])
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
        from .muse_successor import _check, configuration_for_successor
        config = configuration_for_successor(store, _successor)
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
    if _successor is None:
        from .muse_successor import guard_effort_replay
        guard_effort_replay(store, manifest["request"])
    _task_model(config, manifest["request"])
    if _successor is not None and manifest["digest"] != _successor["bundle_digest"]:
        _fail("provider_successor_invalid", "The successor must keep the original task intent unchanged.")
    screen_sensitive(manifest["request"])
    prompt = _prompt(config, manifest)
    capture_budget = _budget(config, prompt)
    if not capture_budget["input_echoes_fit"]:
        _fail("provider_capture_budget_insufficient",
              f"Native input echoes alone require at least {capture_budget['minimum_input_echo_bytes']} bytes; the configured whole-protocol cap is {config['max_output_bytes']}. Reduce the explicit snapshot or configure a supported finite cap. Additional response space is still required. No provider request was sent.")
    root.mkdir(mode=0o700); (root/"workspace").mkdir(mode=0o700); (root/"tmp").mkdir(mode=0o700)
    if request is not None: pilot.prepare(request, output=str(bundle_root))
    pilot._write(root, "prompt.txt", prompt)
    transport = None
    if config["format"] == schema.FORMAT:
        schema_bytes = canonical_bytes(schema.document(manifest["request"], manifest["digest"], config["max_proposal_bytes"]))
        pilot._write(root, "output-schema.json", schema_bytes)
        transport = {"contract": schema.CONTRACT, "schema_sha256": hashlib.sha256(schema_bytes).hexdigest(),
                     "schema_bytes": len(schema_bytes), "prompt_sha256": hashlib.sha256(prompt).hexdigest()}
    record = {"format":"local-provider-run/1","provider":"muse","experimental":True,"run_id":run_id,"revision":0,
              "configuration_digest":config["digest"],"bundle_digest":manifest["digest"],"bundle":str(bundle_root),"output":str(root),
              "controller_submissions":0,"automatic_retry_allowed":False,"patch_applied":False,"acceptance_allowed":False,"capture_budget":capture_budget,
              "production_dispatch_allowed":False,"remote_usage":"not_sent","native_internal_retries":"unknown","descendant_cessation":"unknown"}
    if transport is not None:
        record["response_transport"] = transport
    if _successor is not None:
        record.update(format="local-provider-run/2",manual_successor=_successor)
    record = _event(store, record, root, "preflight")
    claimed = False
    from .local_provider_capture import PrivateCapture
    capture_options = {"schema_version": "2.0"} if _megabyte(config) else {}
    capture = PrivateCapture(root/"capture", max_output_bytes=config["max_output_bytes"], max_records=8192, **capture_options)
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
        def check_schema():
            if transport is not None:
                read_regular(root, "output-schema.json", max_bytes=65536, expected_sha256=transport["schema_sha256"],
                             expected_bytes=transport["schema_bytes"], private=True, expected_mode=0o400)
        check_schema()
        schema_options = {"output_schema": root/"output-schema.json"} if transport is not None else {}
        argv = _argv(config, provider="meta", workspace=root/"workspace", prompt=root/"prompt.txt", session=session, **schema_options)
        invocation = {"argv":argv,"session_id":session,"configuration_digest":config["digest"],"bundle_digest":manifest["digest"]}
        if transport is not None: invocation["response_transport"] = transport
        pilot._write(root, "invocation.json", canonical_bytes(invocation))
        def spawned(receipt):
            nonlocal record
            if _observe_file(config["binary"]["path"], executable=True) != config["binary"]:
                _fail("provider_executable_changed", "The native binary changed before gate release.")
            check_schema()
            read_regular(root,"prompt.txt",max_bytes=len(prompt),expected_sha256=hashlib.sha256(prompt).hexdigest(),private=True,expected_mode=0o400)
            if _successor is not None:
                _check(store, _successor, config)
            record = _event(store, record, root, "running", process_receipt=receipt.to_dict())
        env = _environment(config, root)
        record_budget = _RecordBudget(_max_records(config)) if config["format"] in {"local-muse-provider/4", "local-muse-provider/5", _MEGABYTE, schema.FORMAT} else None
        native_guard = _native_guard(_successor, config, session)
        def observe_line(line):
            if record_budget:
                record_budget.observe(line)
            if native_guard:
                native_guard.observe(line)
        capture_options = {"on_stdout_line": observe_line, "max_line_bytes": _MEGABYTE_FRAME if _megabyte(config) else config["max_output_bytes"]} if record_budget else {}
        if _megabyte(config):
            capture_options["_retain_output"] = False
        result = run_foreground_experiment(argv, mode=FOREGROUND_EXPERIMENT, cwd=root/"workspace", env=env,
            timeout_seconds=config["attempt_seconds"], max_output_bytes=config["max_output_bytes"], signal_grace_seconds=.5,
            on_spawn=spawned, cancel_requested=lambda:bool(native_guard and native_guard.stop_requested) or (root/"cancel-request.json").exists(),
            _on_output_chunk=capture.write, **capture_options)
        if native_guard:
            # Keep the actual owner's result independently of capture closure.
            # A later disk/capture failure must not be reported as settlement.
            pilot._write(root, "process-owner.json", canonical_bytes({**_summary(result),
                "native_lifecycle": native_guard.summary(), "capture_finalized": False}))
        closure = capture.finalize()
        check_schema()
        if not _megabyte(config):
            pilot._write(root,"stdout.bin",redact(result.stdout)); pilot._write(root,"stderr.bin",redact(result.stderr))
        process = _summary(result)
        if _megabyte(config):
            process.update(retained_stdout_bytes=closure["streams"]["stdout"]["retained_bytes"],
                           retained_stderr_bytes=closure["streams"]["stderr"]["retained_bytes"],
                           retained_output_bytes=sum(closure["streams"][s]["retained_bytes"] for s in ("stdout", "stderr")))
        process["private_capture"] = closure
        process["process_stream_complete"] = sum(closure["streams"][s]["observed_bytes"] for s in ("stdout", "stderr")) == process["observed_output_bytes"]
        if record_budget:
            process.update(protocol_records_observed=record_budget.observed,
                           protocol_record_limit=record_budget.maximum, protocol_record_limited=record_budget.limited)
        if native_guard:
            process["native_lifecycle"] = native_guard.summary()
        pilot._write(root,"process.json",canonical_bytes(process))
        if result.root_exit_code != 0 or result.timed_out or result.cancelled or result.output_limited or _owner_failed(result) or record_budget and record_budget.limited or native_guard and native_guard.stop_requested or _megabyte(config) and not process["process_stream_complete"]:
            return _event(store,record,root,"failed",process=process,
                          error="provider_protocol_record_limit" if record_budget and record_budget.limited else "provider_native_lifecycle_stop" if native_guard and native_guard.stop_requested else "provider_local_failure",remote_usage="unknown")
        decode_options = {"megabyte": True} if _megabyte(config) else {}
        source = capture.iter_records("stdout", max_record_bytes=_MEGABYTE_FRAME) if _megabyte(config) else result.stdout
        response, native_run = _decode(source, session, max_proposal_bytes=config.get("max_proposal_bytes", 65536), max_records=_max_records(config), **decode_options)
        if transport is not None:
            response = schema.normalize(response, manifest["request"], manifest["digest"], config["max_proposal_bytes"])
        replacement_options = {"replacement_profile": "megabyte-proposal/1"} if _megabyte(config) else {}
        screen_sensitive(response); pilot._proposal(manifest,response, **replacement_options)
        if _megabyte(config):
            configured_count, metadata = _journal_identity(config, session, native_run=native_run,
                started_unix_ms=process.get("receipt", {}).get("started_unix_ms"))
        else:
            _, events, metadata = _journal(config, session)
            configured_count = len(events)
        observations = {"requested_provider":"meta","requested_model":config["model"],"requested_effort":config["reasoning_effort"],
                        "reported_provider":metadata.get("provider_id"),"reported_model":metadata.get("model_id"),"reported_effort":metadata.get("reasoning_effort"),
                        "configured_model_requests_observed":configured_count,"native_run_id":native_run}
        if metadata.get("provider_id") != "meta" or metadata.get("model_id") != config["model"]:
            _fail("provider_response_identity_mismatch", "The native journal reports a different provider or model; inspect the captured output.", outcome="uncertain")
        response_bytes = canonical_bytes(response)
        pilot._write(root,"response.json",response_bytes)
        proposal = pilot.stage(bundle=str(bundle_root),response=response,output=str(root/"proposal"), **replacement_options)
        response_reference = {"response_ref": {"path": "response.json", "sha256": hashlib.sha256(response_bytes).hexdigest(), "bytes": len(response_bytes)}} if _megabyte(config) else {}
        return _event(store,record,root,"proposal_ready",process=process,execution=observations,
                      proposal_path=str(root/"proposal/proposed.patch"),review_path=str(root/"proposal/review.json"),proposal_digest=proposal["digest"],remote_usage="unknown", **response_reference)
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
    finally:
        capture.close()


def inspect(store, run_id):
    if type(run_id) is not str: return None
    record = store.setting("provider-run:" + run_id)
    if record is not None: return record
    from .muse_successor import inspect_reserved
    return inspect_reserved(store, run_id)
