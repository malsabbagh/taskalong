"""Pure configuration for the configured Claude CLI, separate from old fixtures.

Configuration is operator input. This module never discovers auth, opens a file,
probes a server, installs a client, or grants dispatch/production authority.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from ..errors import TaskAlongError

FORMAT = "claude-local/1"
PROVIDER_ID = "claude-code"
EFFORTS = frozenset({"low", "medium", "high", "xhigh", "max"})
CONTEXTS = frozenset({"include", "native-only"})


def refuse(code):
    raise TaskAlongError(code, "The configured Claude request is outside its supported adapter contract.")


def text(value, *, maximum=256):
    if (type(value) is not str or not value or len(value) > maximum
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        refuse("claude_local_config_invalid")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError:
        refuse("claude_local_config_invalid")
    return value


def absolute_path(value):
    text(value, maximum=4096)
    path = PurePosixPath(value)
    if (not path.is_absolute() or str(path) != value or ".." in path.parts
            or value == "/" or value.startswith("//")):
        refuse("claude_local_path_invalid")
    return value


def model_name(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}", value):
        refuse("claude_local_model_invalid")
    return value


def _object(value, required, optional=()):
    if type(value) is not dict or not set(required) <= set(value) <= set(required) | set(optional):
        refuse("claude_local_config_invalid")


def executable(value):
    _object(value, {"path", "version", "sha256"})
    if type(value["sha256"]) is not str or not re.fullmatch(r"[a-f0-9]{64}", value["sha256"]):
        refuse("claude_local_config_invalid")
    return {"path": absolute_path(value["path"]), "version": text(value["version"]),
            "sha256": value["sha256"]}


def _ollama_endpoint(value):
    # The launch transport targets an existing loopback daemon, which may itself
    # use cloud inference. No direct-cloud credential or arbitrary proxy input.
    if type(value) is not str:
        refuse("claude_local_endpoint_invalid")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        refuse("claude_local_endpoint_invalid")
    if (parts.scheme != "http" or parts.hostname not in {"localhost", "127.0.0.1", "::1"}
            or port is None or not 1 <= port <= 65535 or parts.path or parts.query or parts.fragment
            or parts.username is not None or parts.password is not None
            or value != f"http://{'[::1]' if parts.hostname == '::1' else parts.hostname}:{port}"):
        refuse("claude_local_endpoint_invalid")
    return value


def validate_config(raw):
    """Return a fresh strict JSON-compatible mapping; no I/O or secret values."""
    _object(raw, {"format", "provider_id", "backend", "executable", "model",
                  "expected_reported_model", "backend_config"}, {"effort", "context", "max_turns"})
    if raw["format"] != FORMAT or raw["provider_id"] != PROVIDER_ID:
        refuse("claude_local_config_invalid")
    backend = raw["backend"]
    if type(backend) is not str or backend not in {"anthropic", "ollama"}:
        refuse("claude_local_backend_unsupported")
    context = raw.get("context", "include")
    if context == "exclude":
        refuse("claude_local_context_exclusion_unsupported")
    if type(context) is not str or context not in CONTEXTS:
        refuse("claude_local_config_invalid")
    effort = raw.get("effort")
    if effort is not None and (type(effort) is not str or effort not in EFFORTS):
        refuse("claude_local_effort_unsupported")
    turns = raw.get("max_turns", 8)
    if type(turns) is not int or not 1 <= turns <= 64:
        refuse("claude_local_config_invalid")
    selected = model_name(raw["model"])
    cfg = raw["backend_config"]
    if backend == "anthropic":
        _object(cfg, {"transport", "endpoint", "auth_mode"})
        if (cfg["transport"] != "native" or cfg["endpoint"] != "https://api.anthropic.com"
                or type(cfg["auth_mode"]) is not str or cfg["auth_mode"] not in {"existing-account", "api-key"}):
            refuse("claude_local_backend_unsupported")
        route = dict(cfg)
    else:
        _object(cfg, {"transport", "endpoint", "inference", "launcher", "saved_model"})
        if (cfg["transport"] != "ollama-launch" or type(cfg["inference"]) is not str
                or cfg["inference"] not in {"local", "cloud"}):
            refuse("claude_local_backend_unsupported")
        if model_name(cfg["saved_model"]) != selected:
            # Refuse known configuration changes instead of calling the launcher
            # with a new model and changing persistent operator preferences.
            refuse("claude_local_launcher_model_change")
        if cfg["inference"] == "local" and selected.endswith((":cloud", "-cloud")):
            # Naming cannot authenticate actual origin, but an explicit cloud
            # name must never be presented as a known local-only configuration.
            refuse("claude_local_route_conflict")
        route = {"transport": "ollama-launch", "endpoint": _ollama_endpoint(cfg["endpoint"]),
                 "inference": cfg["inference"], "launcher": executable(cfg["launcher"]),
                 "saved_model": selected}
    return {"format": FORMAT, "provider_id": PROVIDER_ID, "backend": backend,
            "executable": executable(raw["executable"]), "model": selected,
            "expected_reported_model": model_name(raw["expected_reported_model"]),
            "effort": effort, "context": context, "max_turns": turns, "backend_config": route}


def capabilities(raw):
    """Document interfaces separately from effective backend guarantees."""
    config = validate_config(raw)

    def cap(status, scope, evidence="documented native interface"):
        return {"status": status, "evidence": evidence, "scope": scope}

    return {
        "headless": cap("supported", "Claude print mode; installed-version live behavior unqualified"),
        "platform": cap("unqualified", "POSIX absolute paths; no Windows launcher support in this adapter"),
        "context_include": cap("supported", "Default native account and preconfigured context discovery"),
        "context_exclude": cap("unsupported", "Managed/native instructions cannot all be excluded"),
        "context_native_only": cap("unqualified", "Partial: safe mode plus empty setting sources/MCP; managed policy remains"),
        "tool_policy": cap("unqualified", "--tools empty and dontAsk; flags and reported inventory are not OS containment"),
        "structured_output": cap("unqualified", "CLI --json-schema; backend/model compatibility requires native observation"),
        "model_observation": cap("unqualified", "Exact init/assistant/modelUsage string checks are wire claims, not route authentication"),
        "effort_observation": cap("unknown", "CLI argument preserved exactly; effective effort not proven by this protocol"),
        "backend_route": cap("unqualified", f"Explicit {config['backend']} selection; endpoint and inference origin are configured intent"),
        "local_cancel": cap("unqualified", "Owner signals and observes launcher/client/group/descendants separately"),
        "remote_cancel": cap("unknown", "No authenticated remote-cancellation contract established"),
        "cost_cap": cap("unsupported", "CLI client estimates can overshoot; no billing cap guaranteed"),
        "token_cap": cap("unsupported", "No whole-task hard token cap established"),
        "native_resume": cap("unsupported", "Fresh attempt/session only; no session persistence or replay"),
        "native_retries": cap("unknown", "One owned invocation does not imply one backend model request"),
        "production_dispatch": cap("unsupported", "Separate production qualification stays closed; configured owner route is separate"),
    }
