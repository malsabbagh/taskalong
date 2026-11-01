"""Passive provider registry with original synthetic events; no model calls."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong.local_provider_contract import ProviderLimits
from taskalong.local_provider_adapters import (
    adapter_invocation, capabilities, decoder, executable_descriptors,
    normalize_configuration, proposal_schema,
    validate_saved_model,
)


def descriptor(path, sha="a"):
    return {"path": path, "version": "synthetic-1", "sha256": sha * 64}


def configuration(provider="codex", *, backend="anthropic", closure=None):
    if provider == "claude-code":
        route = {"transport": "native", "endpoint": "https://api.anthropic.com", "auth_mode": "existing-account"}
        if backend == "ollama":
            route = {"transport": "ollama-launch", "endpoint": "http://127.0.0.1:11434", "inference": "local",
                     "launcher": descriptor("/synthetic/ollama", "b"), "saved_model": "synthetic-model"}
        inner = {"format": "claude-local/1", "provider_id": provider, "backend": backend,
            "executable": descriptor("/synthetic/claude"), "model": "synthetic-model",
            "expected_reported_model": "synthetic-model", "effort": "high", "context": "include", "backend_config": route}
    else:
        inner = {"format": "codex-local/1" if provider == "codex" else "antigravity-native/1",
            "executable": descriptor("/synthetic/" + provider), "model": "synthetic-model", "effort": "high", "context": "include"}
        if provider == "antigravity":
            inner["print_timeout_seconds"] = 720
    inner["runtime_closure"] = closure or {"kind": "native"}
    return {"format": "configured-provider-profile/1", "provider": provider,
            "adapter_configuration": inner, "limits": ProviderLimits().to_dict()}


def binding(provider="codex", backend=None):
    return {"provider": provider, "backend": backend, "run_id": "11111111-1111-4111-8111-111111111111",
        "attempt_id": "22222222-2222-4222-8222-222222222222", "bundle_digest": "c" * 64,
        "requested_model": "synthetic-model", "requested_effort": "high", "context_policy": "include",
        "writable_outputs": {"new.txt": None}, "workspace": "/synthetic/task/work",
        "control_root": "/synthetic/task/control", "prompt_file": "/synthetic/task/control/prompt.txt",
        "result_file": "/synthetic/task/control/result.json", "remaining_budget": ProviderLimits().to_dict()}


def wire(*events):
    return b"".join((json.dumps(e) + "\n").encode() for e in events)


PROPOSAL = {"bundle_digest": "c" * 64, "changes": {"new.txt": "hello\n"}}


class LocalProviderAdapterTests(unittest.TestCase):
    def test_registry_is_closed_copies_config_and_does_no_io(self):
        with patch("builtins.open", side_effect=AssertionError("file I/O")), \
                patch("subprocess.Popen", side_effect=AssertionError("process")), \
                patch("socket.create_connection", side_effect=AssertionError("network")):
            for provider in ("codex", "antigravity", "claude-code"):
                raw = configuration(provider)
                config = normalize_configuration(provider, raw)
                self.assertEqual(normalize_configuration(provider, config), config)
                bound = binding(provider, "anthropic" if provider == "claude-code" else None)
                plan = adapter_invocation(config, bound, b"A scoped task\n")
                self.assertEqual(set(plan), {"argv", "stdin", "env_overrides"})
                self.assertTrue(all(type(x) is str for x in plan["argv"]))
                raw["adapter_configuration"]["executable"]["path"] = "/changed"
                self.assertNotEqual(config["adapter_configuration"]["executable"]["path"], "/changed")
                self.assertEqual(capabilities(config)["production_dispatch"], "unsupported")
        for provider in ("arbitrary", [], None):
            with self.assertRaises(TaskAlongError):
                normalize_configuration(provider, configuration())

    def test_unknown_credentials_flags_context_and_expanded_limits_are_refused(self):
        for provider in ("codex", "antigravity", "claude-code"):
            raw = configuration(provider)
            for change in ({"token": "private-canary"}, {"args": ["--continue"]}, {"context": "exclude"}, {"runtime_closure": {}}):
                with self.subTest(provider=provider, change=change), self.assertRaises(TaskAlongError):
                    normalize_configuration(provider, raw | {"adapter_configuration": raw["adapter_configuration"] | change})
            with self.assertRaises(TaskAlongError):
                normalize_configuration(provider, raw | {"limits": raw["limits"] | {"max_output_bytes": 4 * 1024 * 1024 + 1}})
        raw = configuration()
        raw["adapter_configuration"]["executable"]["version"] = ""
        with self.assertRaises(TaskAlongError):
            normalize_configuration("codex", raw)
        raw = configuration("claude-code")
        raw["adapter_configuration"]["backend_config"]["auth_mode"] = "api-key"
        with self.assertRaises(TaskAlongError) as error:
            normalize_configuration("claude-code", raw)
        self.assertEqual(error.exception.code, "local_provider_auth_source_unsupported")

    def test_node_entrypoint_and_ollama_actual_claude_are_bound(self):
        raw = configuration()
        raw["adapter_configuration"]["runtime_closure"] = {
            "kind": "node", "node": descriptor("/synthetic/node", "d"),
            "native_binary": descriptor("/synthetic/codex-native", "e"),
            "entrypoint": raw["adapter_configuration"]["executable"]}
        plan = adapter_invocation(raw, binding(), b"Task")
        self.assertEqual(plan["argv"][:2], ["/synthetic/node", "/synthetic/codex"])
        self.assertEqual(len(executable_descriptors(raw)), 3)
        raw["adapter_configuration"]["runtime_closure"]["entrypoint"] = descriptor("/other")
        with self.assertRaises(TaskAlongError):
            normalize_configuration("codex", raw)
        raw = configuration("claude-code", backend="ollama")
        with self.assertRaises(TaskAlongError):
            normalize_configuration("claude-code", raw)
        raw["adapter_configuration"]["runtime_closure"] = {"kind": "ollama-launch",
            "claude_on_path": descriptor("/synthetic/claude"), "path": "/synthetic",
            "settings_file": descriptor("/synthetic/home/.ollama/config.json", "f"),
            "model_pointer": ["integrations", "claude", "models", 0]}
        plan = adapter_invocation(raw, binding("claude-code", "ollama"), b"Task")
        self.assertEqual(plan["argv"][:3], ["/synthetic/ollama", "launch", "claude"])
        self.assertEqual(plan["env_overrides"]["PATH"], "/synthetic")
        self.assertEqual(len(executable_descriptors(raw)), 2)
        self.assertNotIn("--yes", plan["argv"])

    def test_saved_ollama_selection_requires_hash_and_exact_documented_pointer(self):
        settings = b'{"integrations":{"claude":{"models":["synthetic-model"]}}}'
        raw = configuration("claude-code", backend="ollama", closure={"kind": "ollama-launch",
            "claude_on_path": descriptor("/synthetic/claude"), "path": "/synthetic",
            "settings_file": {"path": "/synthetic/home/.ollama/config.json", "version": "synthetic-1",
                              "sha256": hashlib.sha256(settings).hexdigest()},
            "model_pointer": ["integrations", "claude", "models", 0]})
        with patch("builtins.open", side_effect=AssertionError("file I/O")):
            self.assertEqual(validate_saved_model(raw, settings)["selected_model"], "synthetic-model")
        with self.assertRaises(TaskAlongError) as failure:
            validate_saved_model(raw, settings + b" ")
        self.assertEqual(failure.exception.code, "local_provider_saved_model_changed")
        changed = b'{"integrations":{"claude":{"models":["other"]}}}'
        raw["adapter_configuration"]["runtime_closure"]["settings_file"]["sha256"] = hashlib.sha256(changed).hexdigest()
        with self.assertRaises(TaskAlongError) as failure:
            validate_saved_model(raw, changed)
        self.assertEqual(failure.exception.code, "local_provider_saved_model_mismatch")
        raw["adapter_configuration"]["runtime_closure"]["model_pointer"][-1] = False
        with self.assertRaises(TaskAlongError):
            normalize_configuration("claude-code", raw)

    def test_native_argv_remains_fresh_and_remaining_budget_is_conserved(self):
        for provider in ("codex", "antigravity", "claude-code"):
            raw = configuration(provider)
            b = binding(provider, "anthropic" if provider == "claude-code" else None)
            b["remaining_budget"]["attempt_seconds"] = 13
            plan = adapter_invocation(raw, b, b"Task")
            for flag in ("--continue", "--resume", "--dangerously-skip-permissions", "--fallback-model"):
                self.assertNotIn(flag, plan["argv"])
            if provider == "antigravity":
                self.assertEqual(plan["argv"][plan["argv"].index("--print-timeout") + 1], "13s")
                self.assertEqual(json.loads(plan["stdin"])["event"], "user")
            if provider == "claude-code":
                self.assertEqual(plan["argv"][plan["argv"].index("--max-turns") + 1], "1")
            b["required_guarantees"] = ["hard_cost_cap"]
            with self.assertRaises(TaskAlongError):
                adapter_invocation(raw, b, b"Task")

    def test_artifact_format_is_explicit_and_claude_diff_refuses_before_dispatch(self):
        for provider in ("codex", "antigravity"):
            b = binding(provider) | {"artifact_format": "unified-diff/1"}
            schema = proposal_schema(configuration(provider), b)
            self.assertEqual(schema["required"], ["bundle_digest", "patch"])
        with self.assertRaises(TaskAlongError) as failure:
            adapter_invocation(configuration("claude-code"), binding("claude-code", "anthropic") |
                               {"artifact_format": "unified-diff/1"}, b"Task")
        self.assertEqual(failure.exception.code, "local_provider_artifact_format_unsupported")

    def test_codex_fragmented_stdout_and_separate_result_preserve_unknowns(self):
        d = decoder(configuration(), binding(), ProviderLimits())
        raw = wire({"type": "thread.started", "thread_id": "synthetic-session"},
                   {"type": "turn.completed", "usage": {"input_tokens": 9, "output_tokens": 2}})
        for offset in range(0, len(raw), 7):
            d.feed("stdout", raw[offset:offset + 7])
        self.assertEqual(d.session_id, "synthetic-session")
        d.feed("result", json.dumps(PROPOSAL).encode())
        result = d.finish(0)
        self.assertEqual(result["terminal_status"], "completed")
        self.assertEqual(result["structured_result"], PROPOSAL)
        self.assertIsNone(result["reported_model"])
        self.assertIsNone(result["effective_effort"])
        result["structured_result"]["changes"].clear()
        self.assertEqual(d.finish(0)["structured_result"], PROPOSAL)
        with self.assertRaises(TaskAlongError):
            d.finish(1)

    def test_antigravity_nested_decimals_and_cumulative_usage(self):
        cfg, b = configuration("antigravity"), binding("antigravity")
        schema = proposal_schema(cfg, b)
        d = decoder(cfg, b, ProviderLimits())
        d.feed("stdout", wire({"event": "init", "conversation_id": "synthetic-session", "init": {
            "cwd": b["workspace"], "model": "synthetic-model", "tools": [], "permission_mode": "request-review", "json_schema": schema}},
            {"event": "step_update", "step_update": {"conversation_id": "synthetic-session", "step_index": 3,
                "step_type": "checkpoint", "state": "DONE", "duration_seconds": 0.5, "usage": {"input_tokens": 999}}},
            {"event": "result", "result": {"conversation_id": "synthetic-session", "status": "SUCCESS", "response": "private",
                "num_turns": 1, "duration_seconds": 1.25, "structured_output": PROPOSAL, "usage": {"input_tokens": 10}}}))
        result = d.finish(0)
        self.assertEqual(result["terminal_status"], "completed")
        self.assertEqual(result["reported_usage"]["input_tokens"], 10)
        self.assertIsNone(result["reported_usage"]["output_tokens"])
        self.assertNotIn("private", json.dumps(result))

    def test_claude_existing_adapter_normalizes_without_runtime_claims(self):
        cfg, b = configuration("claude-code"), binding("claude-code", "anthropic")
        d = decoder(cfg, b, ProviderLimits())
        common = {"session_id": b["attempt_id"], "parent_tool_use_id": None}
        d.feed("stdout", wire(common | {"type": "system", "subtype": "init", "model": "synthetic-model", "tools": []}))
        self.assertEqual(d.session_id, b["attempt_id"])
        d.feed("stdout", wire(common | {"type": "result", "subtype": "success", "is_error": False,
            "permission_denials": [], "structured_output": PROPOSAL}))
        result = d.finish(0)
        self.assertEqual(result["structured_result"], PROPOSAL)
        self.assertEqual(result["backend"], "anthropic")
        self.assertEqual(result["diagnostics"]["qualification"], "native_unqualified")

    def test_sticky_errors_preserve_observed_session_and_do_not_expose_prose(self):
        d = decoder(configuration(), binding(), ProviderLimits())
        d.feed("stdout", wire({"type": "thread.started", "thread_id": "synthetic-session"}))
        with self.assertRaises(TaskAlongError):
            d.feed("stdout", b'{"private-canary":true}\n')
        with self.assertRaises(TaskAlongError):
            d.feed("stdout", wire({"type": "turn.completed"}))
        result = d.finish(0)
        self.assertEqual(result["session_id"], "synthetic-session")
        self.assertEqual(result["terminal_status"], "failed")
        self.assertNotIn("private-canary", json.dumps(result))

    def test_claude_identity_survives_later_error_for_every_pipe_split(self):
        cfg, b = configuration("claude-code"), binding("claude-code", "anthropic")
        common = {"session_id": b["attempt_id"], "parent_tool_use_id": None}
        raw = wire(common | {"type": "system", "subtype": "init", "model": "synthetic-model", "tools": []},
            common | {"type": "result", "subtype": "success", "is_error": False, "permission_denials": [],
                "structured_output": PROPOSAL | {"bundle_digest": "d" * 64}})
        for split in range(len(raw) + 1):
            d = decoder(cfg, b, ProviderLimits())
            try:
                d.feed("stdout", raw[:split])
                d.feed("stdout", raw[split:])
            except TaskAlongError:
                pass
            result = d.finish(0)
            self.assertEqual(result["terminal_status"], "failed")
            self.assertEqual(result["session_id"], b["attempt_id"])

    def test_bounds_truncation_nonzero_and_unbound_results_fail(self):
        for options in ({"max_output_bytes": 32, "max_record_bytes": 32},):
            limits = ProviderLimits.from_dict(ProviderLimits().to_dict() | options)
            d = decoder(configuration(), binding(), limits)
            with self.assertRaises(TaskAlongError):
                d.feed("result", b"x" * 33)
            self.assertEqual(d.finish(0)["terminal_status"], "failed")
        for tail, exit_code, proposal in ((b"x", 0, PROPOSAL), (b"", 1, PROPOSAL),
                (b"", 0, PROPOSAL | {"bundle_digest": "d" * 64})):
            d = decoder(configuration(), binding(), ProviderLimits())
            d.feed("stdout", wire({"type": "thread.started", "thread_id": "s"}, {"type": "turn.completed"}) + tail)
            d.feed("result", json.dumps(proposal).encode())
            self.assertEqual(d.finish(exit_code)["terminal_status"], "failed")

    def test_result_wire_bound_and_canonical_proposal_bound_are_independent(self):
        limits = ProviderLimits.from_dict(ProviderLimits().to_dict() | {"max_proposal_bytes": len(json.dumps(PROPOSAL,separators=(",", ":")).encode())})
        raw = b" " * 70000 + json.dumps(PROPOSAL,indent=8).encode()
        self.assertGreater(len(raw),limits.max_proposal_bytes)
        d = decoder(configuration(),binding(),limits)
        d.feed("stdout",wire({"type":"thread.started","thread_id":"s"},{"type":"turn.completed"}))
        d.feed("result",raw)
        self.assertEqual(d.finish(0)["terminal_status"],"completed")
        limits = ProviderLimits.from_dict(limits.to_dict() | {"max_proposal_bytes": 10})
        d = decoder(configuration(),binding(),limits)
        d.feed("stdout",wire({"type":"thread.started","thread_id":"s"},{"type":"turn.completed"}))
        d.feed("result",raw)
        self.assertEqual(d.finish(0)["terminal_status"],"failed")
        self.assertIn("local_provider_result_limit",d.finish(0)["protocol_errors"])
        d = decoder(configuration(),binding(),ProviderLimits())
        with self.assertRaises(TaskAlongError):
            d.feed("result",b" " * (1048576+1))


if __name__ == "__main__":
    unittest.main()
