"""Closed executor selection; presence is never production qualification."""
from pathlib import Path
import unittest
from unittest.mock import patch

from taskalong.command_sandbox import command_sandbox_for
from taskalong.errors import TaskAlongError
from taskalong.executors.registry import executor_for
from test_codex_cli import fixture_profile


class ExecutorRegistryTests(unittest.TestCase):
    def test_unknown_adapter_never_falls_back_or_launches(self):
        for adapter in (None, [], "", "claude-code", "cursor-cli", "antigravity-cli", "package.module:Driver"):
            with self.subTest(adapter=adapter), patch("taskalong.executors.codex_cli.run_bounded") as launch:
                with self.assertRaises(TaskAlongError) as raised:
                    executor_for({"adapter": adapter})
                self.assertEqual((raised.exception.code, raised.exception.exit_code,
                                  raised.exception.effect_outcome), ("adapter_unavailable", 3, "not_sent"))
                launch.assert_not_called()

    def test_selected_driver_keeps_production_and_hard_budget_refusal(self):
        profile = fixture_profile(Path("/usr/bin/true"))
        for qualification, budget, code in (
                ("production", {}, "runtime_policy_unsupported"),
                ("synthetic", {"hard_tokens": 1}, "hard_budget_unsupported")):
            selected = executor_for(profile | {"qualification": qualification})
            with self.subTest(code=code), patch("taskalong.executors.codex_cli.run_bounded") as launch:
                with self.assertRaises(TaskAlongError) as raised:
                    selected.preflight(qualification=qualification, budget=budget)
                self.assertEqual(raised.exception.code, code)
                launch.assert_not_called()

    def test_check_policy_rejects_an_unimplemented_harness_without_fallback(self):
        with patch("taskalong.executors.codex_cli.run_bounded") as launch:
            with self.assertRaises(TaskAlongError) as raised:
                command_sandbox_for({"adapter": "claude-code"})
            self.assertEqual((raised.exception.code, raised.exception.effect_outcome),
                             ("command_sandbox_unsupported", "not_sent"))
            launch.assert_not_called()

    def test_prepared_check_keeps_protected_roots_and_network_denial(self):
        profile = fixture_profile(Path("/usr/bin/true"))
        profile["permission_policy"] = {"credential_deny_roots": ["/synthetic/credentials"]}
        with patch("taskalong.executors.codex_cli.run_bounded") as launch:
            argv = command_sandbox_for(profile).prepare_check(
                ["/usr/bin/true"], workspace="/synthetic/workspace",
                git_common_dir="/synthetic/git", control_dir="/synthetic/control")
            launch.assert_not_called()
        self.assertEqual(argv[:5], ["/usr/bin/true", "--no-daemon", "sandbox", "-P", "taskalong"])
        self.assertEqual(argv[-2:], ["--", "/usr/bin/true"])
        policy = next(value for value in argv if value.startswith("permissions.taskalong="))
        for required in ('"/synthetic/workspace"="write"', '"/synthetic/git"="read"',
                         '"/synthetic/control"="deny"', '"/synthetic/credentials"="deny"',
                         'network={enabled=false}'):
            self.assertIn(required, policy)
        self.assertNotIn("--strict-config", argv)
