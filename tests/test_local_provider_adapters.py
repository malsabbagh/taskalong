"""Passive provider registry with original synthetic events; no model calls."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong.local_provider_contract import ProviderLimits
from taskalong.validation import canonical_bytes, loads
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
    def extended(self, provider="codex", **limits):
        cfg = configuration(provider) | {"format": "configured-provider-profile/4", "native_roots": {}}
        cfg["limits"].update({"max_proposal_bytes": 1048576, "max_record_bytes": 4194304} | limits)
        b = binding(provider, "anthropic" if provider == "claude-code" else None)
        b["remaining_budget"] = cfg["limits"].copy()
        return cfg, b

    def proposal_stream(self, cfg, b, proposal):
        provider = cfg["provider"]
        if provider == "codex":
            return [("stdout", wire({"type": "thread.started", "thread_id": "synthetic-session"},
                                     {"type": "turn.completed"})),
                    ("result", json.dumps(proposal).encode())]
        if provider == "antigravity":
            return [("stdout", wire({"event": "init", "conversation_id": "synthetic-session", "init": {
                "cwd": b["workspace"], "model": "synthetic-model", "tools": [],
                "permission_mode": "request-review", "json_schema": proposal_schema(cfg, b)}},
                {"event": "result", "result": {"conversation_id": "synthetic-session", "status": "SUCCESS",
                    "num_turns": 1, "response": "", "duration_seconds": 1.25, "structured_output": proposal}}))]
        common = {"session_id": b["attempt_id"], "parent_tool_use_id": None}
        return [("stdout", wire(common | {"type": "system", "subtype": "init", "model": "synthetic-model", "tools": []},
            common | {"type": "result", "subtype": "success", "is_error": False,
                "permission_denials": [], "total_cost_usd": 0.25, "structured_output": proposal}))]

    def test_profile_four_preserves_defaults_and_requires_explicit_roots_for_all_providers(self):
        for provider in ("codex", "antigravity", "claude-code"):
            cfg, b = self.extended(provider)
            default = cfg | {"limits": ProviderLimits().to_dict()}
            self.assertEqual(normalize_configuration(provider, default)["limits"], default["limits"])
            normalized = normalize_configuration(provider, cfg)
            self.assertEqual(normalized["limits"], cfg["limits"])
            self.assertEqual(normalize_configuration(provider, normalized), normalized)
            self.assertEqual(decoder(cfg, b, cfg["limits"]).limits.max_proposal_bytes, 1048576)
            with self.assertRaises(TaskAlongError):
                normalize_configuration(provider, {k: v for k, v in cfg.items() if k != "native_roots"})
            if provider != "codex":
                with self.assertRaises(TaskAlongError):
                    normalize_configuration(provider, cfg | {"native_roots": {"CODEX_HOME": "/synthetic/root"}})
            maximum = cfg | {"limits": cfg["limits"] | {"max_record_bytes": 16777216,
                "max_output_bytes": 67108864, "max_protocol_records": 131072}}
            self.assertEqual(normalize_configuration(provider, maximum)["limits"], maximum["limits"])
            for field, value in (("max_proposal_bytes", 1048577), ("max_record_bytes", 16777217),
                                 ("max_output_bytes", 67108865), ("max_protocol_records", 131073)):
                with self.subTest(provider=provider, field=field), self.assertRaises(TaskAlongError):
                    normalize_configuration(provider, cfg | {"limits": cfg["limits"] | {field: value}})
        for version in (1, 2, 3):
            cfg = configuration() | {"format": f"configured-provider-profile/{version}"}
            if version == 3:
                cfg["native_roots"] = {}
            for field, value in (("max_proposal_bytes", 65537), ("max_record_bytes", 1048577),
                                 ("max_protocol_records", 8193), ("max_output_bytes", 4194305)):
                with self.subTest(version=version, field=field), self.assertRaises(TaskAlongError):
                    normalize_configuration("codex", cfg | {"limits": cfg["limits"] | {field: value}})

    def test_profile_four_accepts_exact_megabyte_proposals_inside_larger_native_frames(self):
        overhead = len(canonical_bytes(PROPOSAL | {"changes": {"new.txt": "\n"}}))
        count, extra = divmod(1048576 - overhead, 2)
        proposal = PROPOSAL | {"changes": {"new.txt": "é" * count + "x" * extra + "\n"}}
        self.assertEqual(len(canonical_bytes(proposal)), 1048576)
        expected = hashlib.sha256(canonical_bytes(proposal)).hexdigest()
        for provider in ("codex", "antigravity", "claude-code"):
            cfg, b = self.extended(provider)
            d = decoder(cfg, b, cfg["limits"])
            stream = self.proposal_stream(cfg, b, proposal)
            self.assertGreater(max(len(raw) for _, raw in stream), 1048576)
            self.assertLess(sum(len(raw) for _, raw in stream), 4194304)
            for name, raw in stream:
                for offset in range(0, len(raw), 65521):
                    d.feed(name, raw[offset:offset + 65521])
            result = d.finish(0)
            self.assertEqual(result["terminal_status"], "completed", result["protocol_errors"])
            self.assertEqual(hashlib.sha256(canonical_bytes(result["structured_result"])).hexdigest(), expected)
            self.assertIsNone(result["effective_effort"])
            with self.assertRaises(TaskAlongError):
                loads(json.dumps(proposal).encode())  # Authority JSON stays one MiB.

    def test_profile_four_rejects_canonical_overflow_and_raw_flood_without_retry(self):
        proposal = PROPOSAL | {"changes": {"new.txt": "x" * 1048576 + "\n"}}
        for provider in ("codex", "antigravity", "claude-code"):
            cfg, b = self.extended(provider)
            d = decoder(cfg, b, cfg["limits"])
            try:
                for name, raw in self.proposal_stream(cfg, b, proposal):
                    d.feed(name, raw)
            except TaskAlongError:
                pass
            result = d.finish(0)
            self.assertEqual(result["terminal_status"], "failed")
            self.assertIsNone(result["structured_result"])
            d = decoder(cfg, b, cfg["limits"])
            with self.assertRaises(TaskAlongError):
                d.feed("stdout", b"x" * 4194305)
            self.assertEqual(d.finish(0)["terminal_status"], "failed")

    def test_profile_four_codex_large_result_rejects_malformed_json_atomically(self):
        cfg, b = self.extended()
        nesting = b'{"a":' * 40 + b'0' + b'}' * 40
        for raw in (b'{"changes":{},"changes":{}}', b'{"x":NaN}', b'{"x":1.5}',
                    b'{"x":"\\ud800"}', b'\xff', nesting, b'{"x":' + b'[' * 1500 + b'0' + b']' * 1500 + b'}'):
            d = decoder(cfg, b, cfg["limits"])
            d.feed("stdout", wire({"type": "thread.started", "thread_id": "synthetic-session"}, {"type": "turn.completed"}))
            d.feed("result", raw)
            result = d.finish(0)
            self.assertEqual(result["terminal_status"], "failed")
            self.assertIsNone(result["structured_result"])

    def test_profile_four_record_flood_remains_bounded_for_all_providers(self):
        for provider in ("codex", "antigravity", "claude-code"):
            cfg, b = self.extended(provider, max_protocol_records=2)
            stream = self.proposal_stream(cfg, b, PROPOSAL)
            frames = [json.loads(line) for line in stream[0][1].splitlines()]
            if provider == "codex":
                middle = {"type": "future.event"}
            elif provider == "antigravity":
                middle = {"event": "step_update", "step_update": {"conversation_id": "synthetic-session",
                    "step_index": 1, "step_type": "checkpoint", "state": "DONE"}}
            else:
                middle = {"type": "system", "subtype": "status", "session_id": b["attempt_id"]}
            d = decoder(cfg, b, cfg["limits"])
            with self.assertRaises(TaskAlongError):
                d.feed("stdout", wire(frames[0], middle, frames[1]))
            result = d.finish(0)
            self.assertEqual(result["terminal_status"], "failed")
            self.assertIsNone(result["structured_result"])
            self.assertIsNotNone(result["session_id"])

    def test_profile_four_streams_32768_deltas_and_one_megabyte_final_proposal(self):
        overhead = len(canonical_bytes(PROPOSAL | {"changes": {"new.txt": "\n"}}))
        proposal = PROPOSAL | {"changes": {"new.txt": "x" * (1048576 - overhead) + "\n"}}
        self.assertEqual(len(canonical_bytes(proposal)), 1048576)
        for provider in ("codex", "antigravity", "claude-code"):
            cfg, b = self.extended(provider, max_output_bytes=67108864,
                max_record_bytes=16777216, max_protocol_records=131072)
            stream = self.proposal_stream(cfg, b, proposal)
            frames = stream[0][1].splitlines(keepends=True)
            if provider == "codex":
                delta = {"type": "item.updated", "item": {"text": "x" * 512}}
            elif provider == "antigravity":
                delta = {"event": "step_update", "step_update": {"conversation_id": "synthetic-session",
                    "step_index": 1, "step_type": "agent_response", "state": "ACTIVE", "text_delta": "x" * 512}}
            else:
                delta = {"type": "stream_event", "session_id": b["attempt_id"], "event": {
                    "type": "content_block_delta", "delta": {"type": "text_delta", "text": "x" * 512}}}
            batch = wire(delta) * 128
            d = decoder(cfg, b, cfg["limits"])
            d.feed("stdout", frames[0])
            for _ in range(256):
                d.feed("stdout", batch)
            if provider == "antigravity":
                done = copy.deepcopy(delta)
                done["step_update"]["state"] = "DONE"
                d.feed("stdout", wire(done))
            d.feed("stdout", frames[1])
            for stream_name, raw in stream[1:]:
                d.feed(stream_name, raw)
            self.assertGreater(d._total, 17 * 1048576)
            self.assertLess(d._total, 67108864)
            result = d.finish(0)
            self.assertEqual(result["terminal_status"], "completed", result["protocol_errors"])
            self.assertEqual(len(canonical_bytes(result["structured_result"])), 1048576)
            self.assertEqual(d._pending, b"")

    def test_profile_four_codex_response_wire_remains_four_megabytes(self):
        cfg, b = self.extended(max_output_bytes=67108864, max_record_bytes=16777216,
                               max_protocol_records=131072)
        d = decoder(cfg, b, cfg["limits"])
        with self.assertRaises(TaskAlongError) as caught:
            d.feed("result", b" " * 4194305)
        self.assertEqual(caught.exception.code, "local_provider_result_limit")
        d = decoder(cfg, b, cfg["limits"])
        d.feed("stdout", wire({"type": "thread.started", "thread_id": "synthetic-session"}, {"type": "turn.completed"}))
        raw = json.dumps(PROPOSAL).encode()
        d.feed("result", raw + b" " * (4194304 - len(raw)))
        self.assertEqual(d.finish(0)["terminal_status"], "completed")

    def test_profile_four_accepts_large_outer_frames_but_refuses_frame_overflow(self):
        payload = "x" * (9 * 1048576)
        overflow = b"x" * 16777217
        for provider in ("codex", "antigravity", "claude-code"):
            cfg, b = self.extended(provider, max_output_bytes=67108864,
                max_record_bytes=16777216, max_protocol_records=131072)
            stream = self.proposal_stream(cfg, b, PROPOSAL)
            frames = stream[0][1].splitlines(keepends=True)
            if provider == "codex":
                event = {"type": "item.updated", "item": {"text": payload}}
            elif provider == "antigravity":
                event = {"event": "step_update", "step_update": {"conversation_id": "synthetic-session",
                    "step_index": 1, "step_type": "agent_response", "state": "DONE", "text_delta": payload}}
            else:
                event = {"type": "stream_event", "session_id": b["attempt_id"], "event": {
                    "type": "content_block_delta", "delta": {"type": "text_delta", "text": payload}}}
            d = decoder(cfg, b, cfg["limits"])
            d.feed("stdout", frames[0])
            d.feed("stdout", wire(event))
            d.feed("stdout", frames[1])
            for stream_name, raw in stream[1:]:
                d.feed(stream_name, raw)
            self.assertEqual(d.finish(0)["terminal_status"], "completed")
            d = decoder(cfg, b, cfg["limits"])
            with self.assertRaises(TaskAlongError):
                d.feed("stdout", overflow)
            self.assertEqual(d.finish(0)["terminal_status"], "failed")

    def test_profile_four_stderr_is_incremental_metadata_without_private_byte_retention(self):
        raw = b"private synthetic diagnostic\n" * 4096
        for provider in ("codex", "antigravity"):
            cfg, b = self.extended(provider, max_output_bytes=67108864,
                max_record_bytes=16777216, max_protocol_records=131072)
            d = decoder(cfg, b, cfg["limits"])
            for offset in range(0, len(raw), 19):
                d.feed("stderr", raw[offset:offset + 19])
            for stream_name, chunk in self.proposal_stream(cfg, b, PROPOSAL):
                d.feed(stream_name, chunk)
            self.assertEqual(d._stderr, b"")
            result = d.finish(0)
            self.assertEqual(result["diagnostics"]["stderr_bytes"], len(raw))
            self.assertEqual(result["diagnostics"]["stderr_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertNotIn("private synthetic", json.dumps(result))
            self.assertEqual(result["terminal_status"], "completed" if provider == "codex" else "failed")
            if provider == "antigravity":
                self.assertIn("agy_native_diagnostics_unqualified", result["protocol_errors"])
            legacy = decoder(configuration(provider), binding(provider), ProviderLimits())
            legacy.feed("stderr", raw)
            self.assertEqual(bytes(legacy._stderr), raw)

    def test_profile_three_codex_roots_are_explicit_passive_and_copied(self):
        raw = configuration() | {"format": "configured-provider-profile/3", "native_roots": {"CODEX_HOME": "/synthetic/native-root"}}
        original = copy.deepcopy(raw)
        with patch("builtins.open", side_effect=AssertionError("file I/O")):
            normalized = normalize_configuration("codex", raw)
            plan = adapter_invocation(normalized, binding(), b"Task")
        self.assertEqual(normalized, original)
        self.assertEqual(plan["env_overrides"], {"CODEX_HOME": "/synthetic/native-root"})
        raw["native_roots"]["CODEX_HOME"] = "/changed"
        self.assertEqual(normalized, original)
        self.assertEqual(adapter_invocation(original | {"native_roots": {}}, binding(), b"Task")["env_overrides"], {})

    def test_profile_three_rejects_unknown_roots_invalid_paths_and_other_providers(self):
        raw = configuration() | {"format": "configured-provider-profile/3", "native_roots": {}}
        invalid = [None, [], {"HOME": "/synthetic"}, {"API_KEY": "canary"}]
        invalid += [{"CODEX_HOME": value} for value in (None, True, "", "relative", "/", "/a/../b", "/a//b", "/bad\nroot", "/" + "a" * 4096)]
        for roots in invalid:
            with self.subTest(roots=roots), self.assertRaises(TaskAlongError):
                normalize_configuration("codex", raw | {"native_roots": roots})
        with self.assertRaises(TaskAlongError):
            normalize_configuration("codex", {k: v for k, v in raw.items() if k != "native_roots"})
        for provider in ("antigravity", "claude-code"):
            with self.assertRaises(TaskAlongError):
                normalize_configuration(provider, configuration(provider) | {"format": raw["format"], "native_roots": {}})
        for version in (1, 2):
            with self.assertRaises(TaskAlongError):
                normalize_configuration("codex", raw | {"format": f"configured-provider-profile/{version}"})

    def test_profile_three_keeps_default_and_all_other_budget_bounds(self):
        raw = configuration() | {"format": "configured-provider-profile/3", "native_roots": {}}
        self.assertEqual(normalize_configuration("codex", raw)["limits"], ProviderLimits().to_dict())
        for seconds in (13, 720, 1440):
            limits = raw["limits"] | {"attempt_seconds": seconds}
            self.assertEqual(normalize_configuration("codex", raw | {"limits": limits})["limits"], limits)
        for field, value in (("attempt_seconds", 1441), ("max_output_bytes", 4194305),
                ("max_protocol_records", 8193), ("max_record_bytes", 1048577),
                ("max_proposal_bytes", 65537), ("max_controller_submissions", 2)):
            with self.subTest(field=field), self.assertRaises(TaskAlongError):
                normalize_configuration("codex", raw | {"limits": raw["limits"] | {field: value}})

    def test_profile_versions_preserve_defaults_shorter_limits_and_identity(self):
        self.assertEqual(ProviderLimits().attempt_seconds, 720)
        for provider in ("codex", "antigravity", "claude-code"):
            for version in (1, 2):
                for seconds in (13, 720):
                    raw = configuration(provider)
                    raw["format"] = f"configured-provider-profile/{version}"
                    raw["limits"]["attempt_seconds"] = seconds
                    normalized = normalize_configuration(provider, raw)
                    self.assertEqual(normalized["format"], raw["format"])
                    self.assertEqual(normalized["limits"], raw["limits"])
                    self.assertEqual(normalize_configuration(provider, normalized), normalized)
                    self.assertEqual(executable_descriptors(normalized), executable_descriptors(configuration(provider)))

    def test_profile_one_retains_720_ceiling_and_two_permits_explicit_1440(self):
        for provider in ("codex", "antigravity", "claude-code"):
            for seconds in (721, 1440):
                raw = configuration(provider)
                raw["limits"]["attempt_seconds"] = seconds
                with self.assertRaises(TaskAlongError):
                    normalize_configuration(provider, raw)
                raw["format"] = "configured-provider-profile/2"
                self.assertEqual(normalize_configuration(provider, raw)["limits"]["attempt_seconds"], seconds)
            for seconds in (1441, True, 1440.0):
                raw = configuration(provider)
                raw["format"] = "configured-provider-profile/2"
                raw["limits"]["attempt_seconds"] = seconds
                with self.subTest(provider=provider, seconds=seconds), self.assertRaises(TaskAlongError):
                    normalize_configuration(provider, raw)

    def test_profile_two_preserves_other_bounds_for_every_provider(self):
        for provider in ("codex", "antigravity", "claude-code"):
            raw = configuration(provider)
            raw["format"] = "configured-provider-profile/2"
            raw["limits"]["attempt_seconds"] = 1440
            for field, value in (("max_output_bytes", 4 * 1024 * 1024 + 1),
                    ("max_protocol_records", 8193), ("max_record_bytes", 1024 * 1024 + 1),
                    ("max_proposal_bytes", 65537), ("max_controller_submissions", 2)):
                with self.subTest(provider=provider, field=field), self.assertRaises(TaskAlongError):
                    normalize_configuration(provider, raw | {"limits": raw["limits"] | {field: value}})

    def test_all_providers_consume_explicit_1440_without_effort_translation(self):
        for provider in ("codex", "antigravity", "claude-code"):
            raw = configuration(provider)
            raw["format"] = "configured-provider-profile/2"
            raw["limits"]["attempt_seconds"] = 1440
            if provider == "antigravity":
                raw["adapter_configuration"]["print_timeout_seconds"] = 1440
            b = binding(provider, "anthropic" if provider == "claude-code" else None)
            b["remaining_budget"]["attempt_seconds"] = 1440
            plan = adapter_invocation(raw, b, b"A scoped task\n")
            d = decoder(raw, b, raw["limits"])
            self.assertEqual(d.limits.attempt_seconds, 1440)
            self.assertEqual(d.binding["requested_effort"], "high")
            if provider == "codex":
                self.assertIn('model_reasoning_effort="high"', plan["argv"])
            else:
                self.assertEqual(plan["argv"][plan["argv"].index("--effort") + 1], "high")
            if provider == "antigravity":
                position = plan["argv"].index("--print-timeout") + 1
                self.assertEqual(plan["argv"][position], "1440s")
                raw["adapter_configuration"]["print_timeout_seconds"] = 17
                self.assertEqual(adapter_invocation(raw, b, b"Task")["argv"][position], "17s")
            b["remaining_budget"]["attempt_seconds"] = 1441
            with self.assertRaises(TaskAlongError):
                adapter_invocation(raw, b, b"Task")

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
