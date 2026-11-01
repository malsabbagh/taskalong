"""Offline native CLI argument plans; no agy process or account is used."""
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import unittest

from taskalong.errors import TaskAlongError
from taskalong.executors.antigravity_native import (
    NativeAntigravityConfig, native_capabilities, plan_native_turn,
)
from taskalong.executors.antigravity_native_protocol import encode_native_input


class NativeAntigravityPlanTests(unittest.TestCase):
    def setUp(self):
        self.config = NativeAntigravityConfig("/synthetic/agy", "a" * 64, "synthetic-native-model", "high", 1200)
        self.schema = {"type": "object", "properties": {"answer": {"type": "string"}}, "required": ["answer"]}

    def plan(self, **changes):
        return plan_native_turn(self.config, **({"prompt": "A scoped task", "result_schema": self.schema,
                                                "remaining_seconds": 720} | changes))

    def test_explicit_native_framing_and_deadline_without_permission_bypass(self):
        plan = self.plan(prompt='A task with Unicode \u03b1, newlines\nand "quotes".')
        self.assertEqual(plan.print_timeout_seconds, 720)
        self.assertEqual(plan.argv[plan.argv.index("--print-timeout") + 1], "720s")
        self.assertEqual(plan.argv[plan.argv.index("--model") + 1], self.config.model)
        self.assertEqual(plan.argv[plan.argv.index("--effort") + 1], "high")
        self.assertEqual(json.loads(plan.stdin), {"event": "user", "message": {
            "content": 'A task with Unicode \u03b1, newlines\nand "quotes".'}})
        self.assertEqual(plan.stdin.count(b"\n"), 1)
        self.assertEqual(plan.stdin_sha256, hashlib.sha256(plan.stdin).hexdigest())
        self.assertEqual(plan.executable_sha256, "a" * 64)
        for flag in ("--continue", "--conversation", "--dangerously-skip-permissions", "--mode", "--print"):
            self.assertNotIn(flag, plan.argv)
        self.assertIn("--disable-slash-commands", plan.argv)
        self.assertIn("--sandbox", plan.argv)
        with self.assertRaises(FrozenInstanceError):
            plan.stdin = b"changed"

    def test_timeout_cannot_expand_configured_or_remaining_budget(self):
        self.assertEqual(self.plan(remaining_seconds=3600).print_timeout_seconds, 1200)
        self.assertEqual(self.plan(remaining_seconds=1).print_timeout_seconds, 1)
        for value in (0, -1, True, 1.5, "720", None):
            with self.subTest(value=value), self.assertRaises(TaskAlongError) as failure:
                self.plan(remaining_seconds=value)
            self.assertEqual(failure.exception.effect_outcome, "not_sent")

    def test_configuration_refuses_unbounded_ambiguous_and_injected_options(self):
        for change in ({"print_timeout_seconds": 0}, {"print_timeout_seconds": True},
                       {"print_timeout_seconds": 86401}, {"model": "--continue"},
                       {"model": "model\n--continue"}, {"effort": "ultra"}, {"effort": []},
                       {"executable": "relative/agy"}, {"executable": "/"},
                       {"executable": "/synthetic/../agy"}, {"executable": "/synthetic//agy"},
                       {"executable": "/synthetic/agy\x00"}, {"executable_sha256": "A" * 64}):
            with self.subTest(change=change), self.assertRaises(TaskAlongError) as failure:
                replace(self.config, **change)
            self.assertEqual(failure.exception.code, "agy_native_plan_invalid")
        self.assertEqual(replace(self.config, executable="C:\\synthetic\\agy.exe").executable,
                         "C:\\synthetic\\agy.exe")
        for effort in ("low", "medium", "high", "xhigh", "max"):
            self.assertEqual(replace(self.config, effort=effort).effort, effort)

    def test_schema_is_a_snapshot_and_external_resolution_is_unavailable(self):
        plan = self.plan()
        self.schema["properties"]["answer"]["type"] = "integer"
        self.assertEqual(json.loads(plan.argv[plan.argv.index("--json-schema") + 1])["properties"]["answer"]["type"],
                         "string")
        for schema in ({"$ref": "https://example.invalid/schema"}, {"$ref": "file:///private/schema"},
                       {"$defs": {"nested": {"$id": "https://example.invalid/nested", "$ref": "#x"}}},
                       {"type": "imaginary"}, {"const": float("nan")}, {1: "invalid key"}):
            with self.subTest(schema=schema), self.assertRaises(TaskAlongError) as failure:
                self.plan(result_schema=schema)
            self.assertEqual(failure.exception.code, "agy_native_schema_invalid")

    def test_input_is_bounded_and_no_capability_can_enable_production(self):
        for prompt in ("", None, b"task", "\ud800", "x" * (8 * 1024 * 1024 + 1)):
            with self.assertRaises(TaskAlongError) as failure:
                encode_native_input(prompt)
            self.assertEqual(failure.exception.code, "agy_native_input_invalid")
        capabilities = native_capabilities()
        for name in ("native_resume", "provider_start_lookup", "remote_cancellation", "hard_cost_cap",
                     "hard_token_cap", "effective_effort_verified", "context_isolation_verified",
                     "local_cessation_verified", "live_inference_qualified", "production_dispatch_allowed"):
            self.assertIs(capabilities[name], False, name)


if __name__ == "__main__":
    unittest.main()
