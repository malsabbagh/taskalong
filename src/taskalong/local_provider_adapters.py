"""Closed passive projections for configured local providers.

No function launches, discovers credentials, reads runtime files, or grants
admission. Codex projections are consumed only by the versioned CodexCLI.run
branch; the shared owner fingerprints the complete declared runtime closure,
controls the environment and lifetime, and validates proposals independently.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import PurePosixPath

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from referencing.exceptions import Unresolvable

from .errors import TaskAlongError
from .local_provider_contract import ProviderLimits, ProviderObservation
from .validation import canonical_bytes, loads
from .executors.antigravity_native import NativeAntigravityConfig, plan_native_turn
from .executors.antigravity_native_protocol import NativeAntigravityDecoder, checked_native_schema
from .executors.claude_local import create_adapter
from .executors.claude_local_config import absolute_path, executable, model_name
from .executors.claude_local_protocol import response_schema
from .executors.codex_protocol import CodexEventDecoder

FORMAT = "configured-provider-profile/1"
FORMAT_V2 = "configured-provider-profile/2"
FORMAT_V3 = "configured-provider-profile/3"
_ATTEMPT_CEILINGS = {FORMAT: 720, FORMAT_V2: 1440, FORMAT_V3: 1440}
PROVIDERS = frozenset({"codex", "antigravity", "claude-code"})
MAX_OUTPUT_BYTES = 4 * 1024 * 1024


def _fail(code="local_provider_configuration_invalid", *, uncertain=False):
    raise TaskAlongError(code, "The configured provider request is outside its closed passive contract.",
                         exit_code=3, effect_outcome="uncertain" if uncertain else "not_sent")


def _object(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        _fail()


def _limits(value):
    result = value if type(value) is ProviderLimits else ProviderLimits.from_dict(value)
    if result.max_output_bytes > MAX_OUTPUT_BYTES:
        _fail("local_provider_limits_unsupported")
    return result


def _closure(raw, provider, cfg):
    if type(raw) is not dict:
        _fail()
    kind = raw.get("kind")
    if kind == "native":
        _object(raw, {"kind"})
        if provider == "claude-code" and cfg["backend"] == "ollama":
            _fail("local_provider_runtime_closure_required")
        return {"kind": kind}
    if kind == "node" and provider == "codex":
        _object(raw, {"kind", "node", "entrypoint", "native_binary"})
        node, entry = executable(raw["node"]), executable(raw["entrypoint"])
        native = executable(raw["native_binary"])
        if entry != cfg["executable"] or len({node["path"], entry["path"], native["path"]}) != 3:
            _fail("local_provider_runtime_closure_invalid")
        return {"kind": kind, "node": node, "entrypoint": entry, "native_binary": native}
    if kind == "ollama-launch" and provider == "claude-code" and cfg["backend"] == "ollama":
        _object(raw, {"kind", "claude_on_path", "path", "settings_file", "model_pointer"})
        actual = executable(raw["claude_on_path"])
        settings = executable(raw["settings_file"])
        if (any(actual[key] != cfg["executable"][key] for key in ("sha256", "version"))
                or absolute_path(raw["path"]) != str(PurePosixPath(actual["path"]).parent)
                or PurePosixPath(actual["path"]).name != "claude"):
            _fail("local_provider_runtime_closure_invalid")
        if (PurePosixPath(settings["path"]).parts[-2:] != (".ollama", "config.json")
                or type(raw["model_pointer"]) is not list
                or raw["model_pointer"] != ["integrations", "claude", "models", 0]
                or type(raw["model_pointer"][-1]) is not int):
            _fail("local_provider_runtime_closure_invalid")
        return {"kind": kind, "claude_on_path": actual, "path": raw["path"],
                "settings_file": settings, "model_pointer": ["integrations", "claude", "models", 0]}
    _fail("local_provider_runtime_closure_invalid")


def normalize_configuration(provider, raw):
    """Validate and copy a complete versioned configured-provider profile.

    Version 1 retains its 720-second ceiling; versions 2 and 3 permit an explicit
    finite limit through 1440 seconds. Version 3 requires Codex native_roots.
    All preserve the shared default of 720 and the supplied format, with
    unchanged output and submission bounds.

    Claude uses its existing claude-local/1 mapping plus runtime_closure. Codex
    and Antigravity use format/executable/model/effort/context/runtime_closure;
    Antigravity additionally requires print_timeout_seconds. Descriptors are
    exactly {path,version,sha256}; they are declarations pending owner checks.
    """
    if type(provider) is not str or provider not in PROVIDERS:
        _fail("local_provider_unsupported")
    fields = {"format", "provider", "adapter_configuration", "limits"}
    if type(raw) is dict and raw.get("format") == FORMAT_V3:
        fields.add("native_roots")
    _object(raw, fields)
    if (type(raw["format"]) is not str or raw["format"] not in _ATTEMPT_CEILINGS
            or raw["provider"] != provider):
        _fail()
    limits = _limits(raw["limits"])
    if limits.attempt_seconds > _ATTEMPT_CEILINGS[raw["format"]]:
        _fail("local_provider_limits_unsupported")
    roots = None
    if raw["format"] == FORMAT_V3:
        roots = raw["native_roots"]
        if provider != "codex" or type(roots) is not dict or set(roots) - {"CODEX_HOME"}:
            _fail("local_provider_native_roots_invalid")
        try:
            roots = {key: absolute_path(value) for key, value in roots.items()}
        except TaskAlongError:
            _fail("local_provider_native_roots_invalid")
    inner = raw["adapter_configuration"]
    if type(inner) is not dict or "runtime_closure" not in inner:
        _fail("local_provider_runtime_closure_required")
    cfg = {k: v for k, v in inner.items() if k != "runtime_closure"}
    if provider == "claude-code":
        cfg.setdefault("max_turns", 1)
        cfg = create_adapter().validate_config(cfg)
        if cfg["backend"] == "anthropic" and cfg["backend_config"]["auth_mode"] != "existing-account":
            # The owner intentionally strips ambient API keys. Until an
            # explicit selected-source mechanism exists, never accept a key
            # route that could silently fall back to HOME-held account auth.
            _fail("local_provider_auth_source_unsupported")
    else:
        fields = {"format", "executable", "model", "effort", "context"}
        if provider == "antigravity":
            fields.add("print_timeout_seconds")
        _object(cfg, fields)
        if cfg["format"] != ("codex-local/1" if provider == "codex" else "antigravity-native/1"):
            _fail()
        cfg = dict(cfg, executable=executable(cfg["executable"]), model=model_name(cfg["model"]))
        allowed_efforts = {"low", "medium", "high", "xhigh"} if provider == "codex" else {"low", "medium", "high", "xhigh", "max"}
        if type(cfg["effort"]) is not str or cfg["effort"] not in allowed_efforts:
            _fail("local_provider_effort_unsupported")
        contexts = {"include", "native-only"} if provider == "codex" else {"include"}
        if type(cfg["context"]) is not str or cfg["context"] not in contexts:
            _fail("local_provider_context_unsupported")
        if provider == "antigravity":
            NativeAntigravityConfig(cfg["executable"]["path"], cfg["executable"]["sha256"],
                cfg["model"], cfg["effort"], cfg["print_timeout_seconds"])
    cfg["runtime_closure"] = _closure(inner["runtime_closure"], provider, cfg)
    result = {"format": raw["format"], "provider": provider, "adapter_configuration": cfg, "limits": limits.to_dict()}
    if roots is not None:
        result["native_roots"] = roots
    return loads(canonical_bytes(result))


def _configuration(config):
    if type(config) is not dict or "provider" not in config:
        _fail()
    return normalize_configuration(config["provider"], config)


def executable_descriptors(config):
    """Every declared executable/entrypoint to fingerprint before the claim."""
    config = _configuration(config)
    cfg, result = config["adapter_configuration"], []
    values = [cfg["executable"]]
    closure = cfg["runtime_closure"]
    if closure["kind"] == "node":
        values += [closure["node"], closure["entrypoint"], closure["native_binary"]]
    if closure["kind"] == "ollama-launch":
        values += [cfg["backend_config"]["launcher"], closure["claude_on_path"]]
    for item in values:
        if item not in result:
            result.append(copy.deepcopy(item))
    return result


def validate_saved_model(config, raw):
    """Validate owner-read nonsecret settings bytes, performing no file I/O.

    Ollama v0.40.13 cmd/config/config.go selects integrations.claude.models[0]
    from $HOME/.ollama/config.json. The owner must bind that effective HOME,
    reject legacy-file migration, and recheck immediately before claim/release.
    This verifies selection only, never a mutation-free or single-call runtime.
    """
    config = _configuration(config)
    cfg = config["adapter_configuration"]
    closure = cfg["runtime_closure"]
    if closure["kind"] != "ollama-launch" or type(raw) is not bytes or not 1 <= len(raw) <= 65536:
        _fail("local_provider_saved_model_invalid")
    if hashlib.sha256(raw).hexdigest() != closure["settings_file"]["sha256"]:
        _fail("local_provider_saved_model_changed")
    try:
        value = loads(raw, max_bytes=65536)
        for key in closure["model_pointer"]:
            if type(key) is int and type(value) is not list or type(key) is str and type(value) is not dict:
                raise ValueError
            value = value[key]
        if type(value) is not str or value != cfg["backend_config"]["saved_model"] or value != cfg["model"]:
            raise ValueError
    except (TaskAlongError, ValueError, KeyError, IndexError, TypeError):
        _fail("local_provider_saved_model_mismatch")
    return {"settings_sha256": closure["settings_file"]["sha256"], "selected_model": value}


def capabilities(config):
    config = _configuration(config)
    return {"provider": config["provider"], "configured_experimental": True,
            "production_dispatch": "unsupported", "context_exclude": "unsupported",
            "context_isolation": "unqualified", "tool_containment": "unqualified",
            "effective_effort": "unknown", "remote_cancellation": "unknown",
            "hard_cost_cap": "unsupported", "hard_token_cap": "unsupported",
            "native_resume": "unsupported", "native_retry_count": "unknown"}


def _binding(config, raw):
    if type(raw) is not dict:
        _fail("local_provider_binding_invalid")
    cfg, provider = config["adapter_configuration"], config["provider"]
    if (raw.get("provider") != provider or raw.get("backend") != cfg.get("backend")
            or raw.get("requested_model") != cfg["model"] or raw.get("requested_effort") != cfg["effort"]
            or raw.get("context_policy") != cfg["context"]):
        _fail("local_provider_binding_mismatch")
    if raw.get("required_guarantees", []) != []:
        _fail("local_provider_guarantee_unsupported")
    outputs = raw.get("writable_outputs")
    if type(outputs) is dict:
        outputs = sorted(outputs)
    common = {"provider_id": "claude-code", "backend": cfg.get("backend", "anthropic"),
        "run_id": raw.get("run_id"), "attempt_id": raw.get("attempt_id"),
        "bundle_digest": raw.get("bundle_digest", raw.get("request_digest")),
        "requested_model": cfg["model"], "expected_reported_model": cfg.get("expected_reported_model", cfg["model"]),
        "requested_effort": cfg["effort"], "context": cfg["context"], "writable_outputs": outputs}
    default_schema = response_schema(common)
    artifact_format = raw.get("artifact_format", "file-replacements/1")
    if type(artifact_format) is not str or artifact_format not in {"file-replacements/1", "unified-diff/1"}:
        _fail("local_provider_artifact_format_unsupported")
    if artifact_format == "unified-diff/1":
        if provider == "claude-code":
            _fail("local_provider_artifact_format_unsupported")
        default_schema = {"type": "object", "additionalProperties": False,
            "required": ["bundle_digest", "patch"], "properties": {
                "bundle_digest": {"type": "string", "const": common["bundle_digest"]},
                "patch": {"type": "string"}}}
    schema = checked_native_schema(raw.get("result_schema", default_schema))
    if provider == "claude-code" and canonical_bytes(schema) != canonical_bytes(default_schema):
        _fail("local_provider_artifact_format_unsupported")
    return common, schema


def proposal_schema(config, binding):
    """Schema bytes must be materialized by the owner before a Codex claim."""
    config = _configuration(config)
    return _binding(config, binding)[1]


def adapter_invocation(config, prepared, prompt):
    """Return only {argv,stdin,env_overrides}; no process or file effects.

    prepared carries the common task binding plus absolute workspace/control_root/
    prompt_file/result_file, remaining_budget, and optional schema_file (default
    control_root/proposal-schema.json). The owner materializes the schema file.
    """
    config = _configuration(config)
    binding, schema = _binding(config, prepared)
    required = {"remaining_budget", "workspace", "control_root", "prompt_file", "result_file"}
    if not required <= set(prepared):
        _fail("local_provider_binding_invalid")
    if type(prompt) is not bytes or not prompt or len(prompt) > MAX_OUTPUT_BYTES:
        _fail("local_provider_input_invalid")
    try:
        text = prompt.decode("utf-8")
    except UnicodeError:
        _fail("local_provider_input_invalid")
    budget = _limits(prepared["remaining_budget"])
    if any(value > config["limits"][key] for key, value in budget.to_dict().items()):
        _fail("local_provider_limits_expanded")
    cfg, provider = config["adapter_configuration"], config["provider"]
    workspace = absolute_path(prepared["workspace"])
    control = absolute_path(prepared["control_root"])
    if workspace == control or workspace.startswith(control + "/") or control.startswith(workspace + "/"):
        _fail("local_provider_binding_invalid")
    overrides = {}
    if provider == "claude-code":
        inner = {k: v for k, v in cfg.items() if k != "runtime_closure"}
        plan = create_adapter().build_invocation(inner, binding, prepared)
        argv, stdin, overrides = plan["argv"], prompt, plan["environment_overrides"]
        if cfg["runtime_closure"]["kind"] == "ollama-launch":
            overrides["PATH"] = cfg["runtime_closure"]["path"]
    elif provider == "antigravity":
        native = NativeAntigravityConfig(cfg["executable"]["path"], cfg["executable"]["sha256"],
            cfg["model"], cfg["effort"], cfg["print_timeout_seconds"])
        plan = plan_native_turn(native, prompt=text, result_schema=schema, remaining_seconds=budget.attempt_seconds)
        argv, stdin = list(plan.argv), plan.stdin
    else:
        overrides.update(config.get("native_roots", {}))
        schema_file = absolute_path(prepared.get("schema_file", control + "/proposal-schema.json"))
        result_file = absolute_path(prepared["result_file"])
        if any(not p.startswith(control + "/") for p in (schema_file, result_file)) or schema_file == result_file:
            _fail("local_provider_binding_invalid")
        closure = cfg["runtime_closure"]
        prefix = ([closure["node"]["path"], closure["entrypoint"]["path"]]
                  if closure["kind"] == "node" else [cfg["executable"]["path"]])
        argv = prefix + ["--no-daemon", "exec", "--json", "--color", "never", "--sandbox", "read-only",
            "-c", 'approval_policy="never"', "-c", "model_reasoning_effort=" + json.dumps(cfg["effort"]),
            "-m", cfg["model"], "-C", workspace, "--output-schema", schema_file,
            "--output-last-message", result_file, "-"]
        if cfg["context"] == "native-only":
            argv[argv.index("exec") + 1:argv.index("exec") + 1] = ["--ignore-user-config", "--strict-config"]
        stdin = prompt
    return {"argv": argv, "stdin": stdin, "env_overrides": overrides}


class _Decoder:
    """Bounded normalized facade; failures retain any already observed identity."""
    def __init__(self, config, binding, limits):
        self.config = _configuration(config)
        self.binding, self.schema = _binding(self.config, binding)
        self.limits = _limits(limits)
        if any(v > self.config["limits"][k] for k, v in self.limits.to_dict().items()):
            _fail("local_provider_limits_expanded")
        self.provider = self.config["provider"]
        self._error = self._finished = self._exit = None
        self._total = 0
        self._pending, self._result, self._stderr = bytearray(), bytearray(), bytearray()
        self._initialized_session = None
        if self.provider == "claude-code":
            self.native = create_adapter().new_decoder(self.binding, self.limits.to_dict())
        elif self.provider == "antigravity":
            if "workspace" not in binding:
                _fail("local_provider_binding_invalid")
            self.native = NativeAntigravityDecoder(expected_model=self.binding["requested_model"],
                expected_cwd=absolute_path(binding["workspace"]), result_schema=self.schema,
                max_output_bytes=self.limits.max_output_bytes, max_line_bytes=self.limits.max_record_bytes,
                max_frames=self.limits.max_protocol_records)
        else:
            self.native = CodexEventDecoder(max_records=self.limits.max_protocol_records,
                                           max_line_bytes=self.limits.max_record_bytes)

    @property
    def session_id(self):
        if self.provider == "codex":
            return self.native.thread_id
        if self.provider == "antigravity":
            return self.native.conversation_id
        return self._initialized_session

    @property
    def error_code(self):
        return self._error

    def feed(self, stream, chunk):
        if self._error:
            _fail(self._error, uncertain=True)
        try:
            if self._finished is not None or type(stream) is not str or stream not in {"stdout", "stderr", "result"} or type(chunk) is not bytes:
                _fail("local_provider_stream_invalid", uncertain=True)
            self._total += len(chunk)
            if self._total > self.limits.max_output_bytes:
                _fail("local_provider_output_limit", uncertain=True)
            if stream == "result":
                if self.provider != "codex" or len(self._result) + len(chunk) > self.limits.max_record_bytes:
                    _fail("local_provider_result_limit", uncertain=True)
                self._result.extend(chunk)
            elif self.provider == "claude-code":
                try:
                    self.native.feed(stream, chunk)
                finally:
                    # A later malformed record in the same pipe read cannot
                    # erase an init already observed by the native decoder.
                    if getattr(self.native, "_initialized", False):
                        self._initialized_session = self.binding["attempt_id"]
            elif stream == "stderr":
                self._stderr.extend(chunk)
            elif self.provider == "antigravity":
                self.native.feed(chunk)
            else:
                self._pending.extend(chunk)
                while b"\n" in self._pending:
                    line, _, rest = self._pending.partition(b"\n")
                    self._pending = bytearray(rest)
                    self.native.consume(bytes(line))
                    if self.native.error_code:
                        _fail(self.native.error_code, uncertain=True)
                if len(self._pending) > self.limits.max_record_bytes:
                    _fail("local_provider_record_limit", uncertain=True)
        except TaskAlongError as exc:
            self._error = exc.code
            raise

    def finish(self, exit_code):
        if self._finished is not None:
            if type(exit_code) is not int or exit_code != self._exit:
                _fail("local_provider_finish_conflict", uncertain=True)
            return copy.deepcopy(self._finished)
        value: ProviderObservation = {"provider": self.provider, "backend": self.config["adapter_configuration"].get("backend"),
            "session_id": self.session_id, "turn_id": None, "requested_model": self.binding["requested_model"],
            "reported_model": None, "requested_effort": self.binding["requested_effort"], "effective_effort": None,
            "terminal_status": "failed", "structured_result": None, "reported_usage": {}, "tool_denials": [],
            "protocol_errors": [], "diagnostics": {"qualification": "native_unqualified"}}
        try:
            if self._error:
                _fail(self._error, uncertain=True)
            if type(exit_code) is not int:
                _fail("local_provider_exit_invalid", uncertain=True)
            if self.provider == "claude-code":
                native = self.native.finish(exit_code=exit_code)
                value.update(session_id=native["native_session_id"], reported_model=native["reported_model"],
                    structured_result=native["structured_response"], reported_usage=native["reported_usage"], terminal_status="completed")
            elif self.provider == "antigravity":
                native = self.native.finish(exit_code=exit_code, stderr=bytes(self._stderr))
                value.update(session_id=native.conversation_id, reported_model=native.reported_model,
                             reported_usage=loads(native.reported_usage_json))
                if not native.successful:
                    if native.provider_status == "CANCELED":
                        value["terminal_status"] = "cancelled"
                    elif native.provider_status in {"WAITING", "RUNNING"}:
                        value["terminal_status"] = "incomplete"
                    _fail(native.error_code, uncertain=True)
                proposal = loads(native.structured_output_json, max_bytes=self.limits.max_proposal_bytes)
                value.update(structured_result=proposal, terminal_status="completed")
            else:
                value.update(session_id=self.native.thread_id, reported_usage=self.native.usage)
                value["diagnostics"].update(self.native.diagnostics)
                if self._pending or self.native.error_code or self.native.terminal != "turn.completed" or self.native.thread_id is None:
                    _fail(self.native.error_code or "local_provider_stream_incomplete", uncertain=True)
                if exit_code != 0:
                    _fail("local_provider_exit_failed", uncertain=True)
                value["diagnostics"].update(stderr_bytes=len(self._stderr),
                    stderr_sha256=hashlib.sha256(self._stderr).hexdigest(),
                    stderr_classification="unclassified" if self._stderr else "absent")
                proposal = loads(bytes(self._result), max_bytes=self.limits.max_record_bytes)
                if len(canonical_bytes(proposal)) > self.limits.max_proposal_bytes:
                    _fail("local_provider_result_limit", uncertain=True)
                Draft202012Validator(self.schema).validate(proposal)
                if type(proposal) is not dict:
                    _fail("local_provider_result_invalid", uncertain=True)
                value.update(structured_result=proposal, terminal_status="completed")
        except (TaskAlongError, ValidationError, Unresolvable, ValueError, RecursionError) as exc:
            self._error = exc.code if isinstance(exc, TaskAlongError) else "local_provider_result_invalid"
            value["protocol_errors"] = [self._error]
            if self._error == "claude_local_permission_denied":
                value["tool_denials"] = [{"code": "reported_permission_denial"}]
        self._exit, self._finished = exit_code, copy.deepcopy(value)
        return value


def decoder(config, binding, limits):
    """feed(stream,bytes); finish(exit_code) -> ProviderObservation.

    Malformed feed raises a safe sticky error so the owner can stop promptly;
    finish still returns a failed observation. Codex's separate result stream
    carries output-last-message bytes. No result establishes acceptance.
    """
    return _Decoder(config, binding, limits)
