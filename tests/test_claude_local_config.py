"""Original offline config/invocation tests; no installed CLI is executed."""
import json
import unittest
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong.executors.claude_local import create_adapter
from taskalong.executors.claude_local_config import validate_config


def config(backend="anthropic", **changes):
    selected = "synthetic-model" if backend == "anthropic" else "synthetic-model:cloud"
    route = ({"transport": "native", "endpoint": "https://api.anthropic.com", "auth_mode": "existing-account"}
             if backend == "anthropic" else {"transport": "ollama-launch", "endpoint": "http://127.0.0.1:11434",
                 "inference": "cloud", "saved_model": selected,
                 "launcher": {"path": "/opt/ollama", "version": "0.40.13", "sha256": "b" * 64}})
    return {"format": "claude-local/1", "provider_id": "claude-code", "backend": backend,
            "executable": {"path": "/opt/claude", "version": "2.1.220", "sha256": "a" * 64},
            "model": selected, "expected_reported_model": "synthetic-model", "backend_config": route, **changes}


def binding(cfg=None, **changes):
    cfg = validate_config(cfg or config())
    return {"provider_id": "claude-code", "backend": cfg["backend"],
            "run_id": "11111111-1111-4111-8111-111111111111",
            "attempt_id": "22222222-2222-4222-8222-222222222222", "bundle_digest": "c" * 64,
            "requested_model": cfg["model"], "expected_reported_model": cfg["expected_reported_model"],
            "requested_effort": cfg["effort"], "context": cfg["context"],
            "writable_outputs": ["src/app.py", "new.txt"], **changes}


LOCATIONS = {"workspace": "/private/task/work", "control_root": "/private/task/control",
             "prompt_file": "/private/task/control/prompt.txt"}


class ClaudeLocalConfigTests(unittest.TestCase):
    def setUp(self):
        self.adapter = create_adapter()

    def assert_refused(self, value, code=None):
        with self.assertRaises(TaskAlongError) as error:
            validate_config(value)
        if code:
            self.assertEqual(error.exception.code, code)
        self.assertEqual(error.exception.effect_outcome, "not_sent")

    def test_defaults_are_explicit_and_input_is_not_retained(self):
        raw = config("ollama")
        normalized = validate_config(raw)
        self.assertEqual((normalized["context"], normalized["effort"], normalized["max_turns"]), ("include", None, 8))
        raw["backend_config"]["launcher"]["path"] = "/changed"
        self.assertEqual(normalized["backend_config"]["launcher"]["path"], "/opt/ollama")
        self.assertEqual(validate_config(normalized), normalized)

    def test_closed_configuration_never_accepts_credentials_or_task_flags(self):
        for extra in ({"token": "CANARY"}, {"args": ["--dangerously-skip-permissions"]},
                      {"module": "arbitrary"}, {"fallback_model": "other"}):
            with self.subTest(extra=extra):
                self.assert_refused(config(**extra))
        raw = config("ollama")
        raw["backend_config"]["token"] = "CANARY"
        self.assert_refused(raw)
        for value in (None, [], True, config() | {"backend": []}, config() | {"context": []}):
            with self.subTest(type=type(value)):
                self.assert_refused(value)

    def test_executable_and_model_identities_are_operator_supplied_not_discovered(self):
        for path in ("claude", "/opt/../bin/claude", "/opt//claude", "/opt/claude\n", "/"):
            raw = config(); raw["executable"]["path"] = path
            self.assert_refused(raw)
        for value in ("--model", "a b", "x\n", "", None, []):
            self.assert_refused(config(model=value))
        raw = config(); raw["executable"]["sha256"] = "A" * 64
        self.assert_refused(raw)

    def test_backends_and_auth_sources_cannot_fall_back(self):
        raw = config()
        for route in ({"transport": "native", "endpoint": "https://ollama.com", "auth_mode": "api-key"},
                      {"transport": "native", "endpoint": "https://api.anthropic.com", "auth_mode": "automatic"}):
            self.assert_refused(raw | {"backend_config": route}, "claude_local_backend_unsupported")
        raw = config("ollama"); raw["backend_config"]["transport"] = "direct"
        self.assert_refused(raw, "claude_local_backend_unsupported")
        self.assert_refused(config(backend="automatic"), "claude_local_backend_unsupported")

    def test_loopback_endpoint_does_not_select_local_inference(self):
        cloud = validate_config(config("ollama"))
        self.assertEqual(cloud["backend_config"]["inference"], "cloud")
        raw = config("ollama"); raw["backend_config"]["inference"] = "local"
        self.assert_refused(raw, "claude_local_route_conflict")
        raw["model"] = raw["backend_config"]["saved_model"] = "synthetic-local-model"
        self.assertEqual(validate_config(raw)["backend_config"]["inference"], "local")
        for endpoint in ("https://ollama.com", "http://127.0.0.1", "http://127.0.0.1:11434/",
                         "http://user:secret@127.0.0.1:11434", "http://localhost:11434?q=x",
                         "http://evil.invalid:11434", "http://localhost:0", "http://localhost:11434#fragment"):
            raw = config("ollama"); raw["backend_config"]["endpoint"] = endpoint
            self.assert_refused(raw, "claude_local_endpoint_invalid")
        for endpoint in ("http://localhost:11434", "http://[::1]:11434"):
            raw = config("ollama"); raw["backend_config"]["endpoint"] = endpoint
            self.assertEqual(validate_config(raw)["backend_config"]["endpoint"], endpoint)

    def test_no_selection_change_effort_translation_or_hard_guarantee(self):
        raw = config("ollama"); raw["backend_config"]["saved_model"] = "other-model"
        self.assert_refused(raw, "claude_local_launcher_model_change")
        self.assert_refused(config(context="exclude"), "claude_local_context_exclusion_unsupported")
        for effort in ("auto", "highest", [], True):
            self.assert_refused(config(effort=effort), "claude_local_effort_unsupported")
        for turns in (0, 65, True, 1.5):
            self.assert_refused(config(max_turns=turns))
        for backend in ("anthropic", "ollama"):
            raw = config(backend, effort="xhigh")
            invocation = self.adapter.build_invocation(raw, binding(raw), LOCATIONS)
            self.assertEqual(invocation["native_effort_argument"], "xhigh")
            with self.assertRaises(TaskAlongError) as error:
                self.adapter.build_invocation(raw, binding(raw, required_guarantees=["hard_cost_cap"]), LOCATIONS)
            self.assertEqual(error.exception.code, "claude_local_guarantee_unsupported")

    def test_native_invocation_is_literal_and_proposal_only(self):
        spec = self.adapter.build_invocation(config(), binding(), LOCATIONS)
        self.assertEqual(spec["argv"][:3], ["/opt/claude", "--model", "synthetic-model"])
        self.assertFalse(spec["shell"])
        self.assertEqual(spec["argv"][spec["argv"].index("--tools") + 1], "")
        self.assertEqual(spec["argv"][spec["argv"].index("--permission-mode") + 1], "dontAsk")
        self.assertIn("--strict-mcp-config", spec["argv"])
        self.assertEqual(spec["argv"][spec["argv"].index("--mcp-config") + 1], '{"mcpServers":{}}')
        self.assertEqual(spec["stdin_path"], LOCATIONS["prompt_file"])
        self.assertEqual(spec["cwd"], LOCATIONS["workspace"])
        self.assertIsNone(spec["result_path"])
        self.assertNotIn("--safe-mode", spec["argv"])
        for flag in ("--resume", "--continue", "--fallback-model", "--dangerously-skip-permissions", "--bare"):
            self.assertNotIn(flag, spec["argv"])
        schema = json.loads(spec["argv"][spec["argv"].index("--json-schema") + 1])
        self.assertEqual(set(schema["properties"]["changes"]["properties"]), set(binding()["writable_outputs"]))
        self.assertFalse(schema["additionalProperties"])

    def test_ollama_is_an_actual_launcher_spec_and_both_executables_are_bound(self):
        raw = config("ollama")
        spec = self.adapter.build_invocation(raw, binding(raw), LOCATIONS)
        self.assertEqual(spec["argv"][:7], ["/opt/ollama", "launch", "claude", "--model", "synthetic-model:cloud", "--", "--print"])
        self.assertEqual(spec["configured_inference"], "cloud")
        self.assertEqual(len(spec["executable_bindings"]), 2)
        self.assertEqual(spec["environment_overrides"]["OLLAMA_HOST"], "http://127.0.0.1:11434")
        for flag in ("--yes", "-y", "--config", "--restore"):
            self.assertNotIn(flag, spec["argv"])
        self.assertNotIn("ANTHROPIC_AUTH_TOKEN", spec["environment_overrides"])
        self.assertIn("recheck_saved_ollama_model", spec["owner_requirements"])

    def test_partial_native_context_uses_actual_installed_spelling_without_changing_auth_mode(self):
        raw = config(context="native-only")
        spec = self.adapter.build_invocation(raw, binding(raw), LOCATIONS)
        self.assertIn("--setting-sources=", spec["argv"])
        self.assertNotIn("--settings-sources=", spec["argv"])
        self.assertIn("--safe-mode", spec["argv"])
        self.assertIn("context_native_only_is_partial", spec["limitations"])
        self.assertEqual(spec["auth_mode"], "existing-account")

    def test_binding_mismatches_or_unsafe_owned_locations_refuse_before_dispatch(self):
        for change in ({"backend": "ollama"}, {"requested_model": "other"},
                       {"expected_reported_model": "other"}, {"requested_effort": "high"},
                       {"context": "native-only"}):
            with self.subTest(change=change), self.assertRaises(TaskAlongError) as error:
                self.adapter.build_invocation(config(), binding(**change), LOCATIONS)
            self.assertEqual(error.exception.code, "claude_local_configuration_mismatch")
        for change in ({"prompt_file": "/elsewhere/prompt"}, {"workspace": "/private/task/control/work"},
                       {"control_root": "/private/task/work/control"}, {"workspace": "relative"}):
            with self.subTest(change=change), self.assertRaises(TaskAlongError):
                self.adapter.build_invocation(config(), binding(), LOCATIONS | change)

    def test_pure_seams_do_not_open_files_run_processes_or_read_auth(self):
        with patch("builtins.open", side_effect=AssertionError("file I/O")), \
                patch("subprocess.Popen", side_effect=AssertionError("process")), \
                patch("socket.create_connection", side_effect=AssertionError("network")):
            for backend in ("anthropic", "ollama"):
                raw = config(backend)
                self.adapter.validate_config(raw)
                self.adapter.capabilities(raw)
                self.adapter.build_invocation(raw, binding(raw), LOCATIONS)
        self.assertFalse(hasattr(self.adapter, "run"))

    def test_capabilities_never_promote_flags_or_synthetic_tests_to_guarantees(self):
        for backend in ("anthropic", "ollama"):
            value = self.adapter.capabilities(config(backend))
            self.assertEqual(value["production_dispatch"]["status"], "unsupported")
            self.assertEqual(value["context_exclude"]["status"], "unsupported")
            self.assertEqual(value["cost_cap"]["status"], "unsupported")
            self.assertEqual(value["remote_cancel"]["status"], "unknown")
            self.assertEqual(value["effort_observation"]["status"], "unknown")
            self.assertTrue(all(set(x) == {"status", "evidence", "scope"} for x in value.values()))


if __name__ == "__main__":
    unittest.main()
