"""Passive configured Claude adapter; the shared owner alone may dispatch it.

Native Anthropic and Ollama are explicit backends of one CLI protocol. Existing
claude_code/claude_protocol fixture contracts are unchanged. No run(), auth
discovery, setup, model download, retry, acceptance or publication lives here.
"""
from __future__ import annotations

import json

from .claude_local_config import PROVIDER_ID, absolute_path, capabilities, refuse, validate_config
from .claude_local_protocol import ClaudeLocalDecoder, validate_binding, response_schema


def build_invocation(raw, task_binding, locations):
    config = validate_config(raw)
    binding = validate_binding(task_binding)
    if (binding["backend"] != config["backend"] or binding["requested_model"] != config["model"]
            or binding["expected_reported_model"] != config["expected_reported_model"]
            or binding["requested_effort"] != config["effort"] or binding["context"] != config["context"]):
        refuse("claude_local_configuration_mismatch")
    requirements = task_binding.get("required_guarantees", [])
    if type(requirements) is not list or requirements:
        # No implied satisfaction of a new hard guarantee by an unqualified flag.
        refuse("claude_local_guarantee_unsupported")
    if type(locations) is not dict or not {"workspace", "prompt_file", "control_root"} <= set(locations):
        refuse("claude_local_path_invalid")
    workspace = absolute_path(locations["workspace"])
    prompt_file = absolute_path(locations["prompt_file"])
    control_root = absolute_path(locations["control_root"])
    if (workspace == control_root or not prompt_file.startswith(control_root + "/")
            or workspace.startswith(control_root + "/") or control_root.startswith(workspace + "/")):
        refuse("claude_local_path_invalid")
    args = ["--print", "--input-format", "text", "--output-format", "stream-json", "--verbose",
            "--json-schema", json.dumps(response_schema(binding), sort_keys=True, separators=(",", ":")),
            "--session-id", binding["attempt_id"], "--no-session-persistence",
            "--permission-mode", "dontAsk", "--tools", "", "--max-turns", str(config["max_turns"]),
            "--no-chrome", "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}']
    if config["effort"] is not None:
        args += ["--effort", config["effort"]]
    if config["context"] == "native-only":
        args += ["--safe-mode", "--setting-sources=", "--disable-slash-commands"]
    route = config["backend_config"]
    overrides = {"ANTHROPIC_BASE_URL": route["endpoint"]}
    if config["backend"] == "ollama":
        # No --yes: it auto-approves pulls/setup. No selection change is admitted
        # above. The owner must recheck the existing saved model at release.
        argv = [route["launcher"]["path"], "launch", "claude", "--model", config["model"], "--", *args]
        overrides["OLLAMA_HOST"] = route["endpoint"]
        owner_requirements = ["recheck_saved_ollama_model", "pin_launcher_resolved_claude_on_path",
                              "observe_launcher_and_client_lifetime", "preserve_existing_ollama_account"]
    else:
        argv = [config["executable"]["path"], "--model", config["model"], *args]
        owner_requirements = ["supply_only_selected_anthropic_auth_source"]
    return {"provider_id": PROVIDER_ID, "backend": config["backend"], "argv": argv, "shell": False,
            "cwd": workspace, "environment_overrides": overrides,
            "expected_reported_model": config["expected_reported_model"], "requested_effort": config["effort"],
            "native_effort_argument": config["effort"], "result_transport": "stdout-jsonl", "result_path": None,
            "stdin_path": prompt_file, "executable_bindings": [config["executable"]] + (
                [route["launcher"]] if config["backend"] == "ollama" else []),
            "configured_inference": route.get("inference"), "auth_mode": route.get("auth_mode"),
            "owner_requirements": owner_requirements + ["controlled_backend_environment",
                "enforce_deadline_and_combined_capture_limits", "preserve_capture_on_failure",
                "terminal_is_not_cessation_or_acceptance"],
            "limitations": ["native_backend_live_unqualified", "native_retries_unknown",
                "effective_effort_unknown", "route_provenance_unobserved", "remote_cessation_unknown",
                "context_native_only_is_partial" if config["context"] == "native-only" else "native_customizations_included"]}


def new_decoder(task_binding, limits):
    return ClaudeLocalDecoder(task_binding, limits)


class ClaudeLocalAdapter:
    provider_id = PROVIDER_ID
    validate_config = staticmethod(validate_config)
    capabilities = staticmethod(capabilities)
    build_invocation = staticmethod(build_invocation)
    new_decoder = staticmethod(new_decoder)


def create_adapter():
    return ClaudeLocalAdapter()
