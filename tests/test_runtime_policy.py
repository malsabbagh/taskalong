"""Pre-dispatch refusal and exact permission-argv controls."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong.executors.codex_cli import CodexCLI
from taskalong.process import fingerprint
from taskalong.validation import canonical_bytes, digest, seal
from test_codex_cli import fixture_profile


class RuntimePolicyTests(unittest.TestCase):
    def setUp(self):
        self.profile = fixture_profile(Path("/usr/bin/true"))

    def test_hard_money_or_tokens_fail_before_dispatch(self):
        for budget in ({"hard_cost_usd": "0.01", "hard_tokens": None}, {"hard_cost_usd": None, "hard_tokens": 1}):
            with self.assertRaises(TaskAlongError) as result:
                CodexCLI(self.profile).preflight(qualification="synthetic", budget=budget)
            self.assertEqual(result.exception.code, "hard_budget_unsupported")

    def test_synthetic_profile_and_receipt_strings_do_not_qualify_production(self):
        profile = self.profile | {"qualification": "production", "qualification_receipt_ids": ["operator-claimed-pass"]}
        with self.assertRaises(TaskAlongError) as result:
            CodexCLI(profile).preflight(qualification="production", budget={})
        self.assertEqual(result.exception.code, "runtime_policy_unsupported")
        with self.assertRaises(TaskAlongError) as result:
            CodexCLI(self.profile).preflight(qualification="production", budget={})
        self.assertEqual(result.exception.code, "qualification_mismatch")

    def test_production_recovery_names_required_observations_without_weakening_policy(self):
        profile = self.profile | {"qualification": "production"}
        with self.assertRaises(TaskAlongError) as result:
            CodexCLI(profile).preflight(qualification="production", budget={})
        error = result.exception
        self.assertEqual((error.code, error.exit_code, error.effect_outcome),
                         ("runtime_policy_unsupported", 3, "not_sent"))
        self.assertFalse(error.retryable)
        actions = error.recovery
        context = next(action for action in actions if action["action"] == "qualify_effective_start_and_resume_context")
        self.assertEqual(context["modes"], ["start", "native_resume"])
        self.assertTrue(context["preserve_protective_policy"])
        self.assertIn("global_and_project_instruction_sources", context["required_observations"])
        self.assertIn("enabled_user_project_and_bundled_skills", context["required_observations"])
        self.assertIn("advertised_tools_and_forbidden_tool_dispatch", context["required_observations"])
        self.assertNotIn(b"--ignore-rules", canonical_bytes(actions))
        lifetime = actions[1]
        self.assertEqual(lifetime["required_backend"], "linux-child-subreaper")
        self.assertIn("worker_and_all_descendant_cessation", lifetime["required_observations"])
        if sys.platform == "darwin":
            self.assertEqual(lifetime["action"], "qualify_existing_linux_adapter")

    def version_profile(self, qualification="synthetic"):
        root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        executable = root / "fixture-runtime"
        executable.write_text("#!" + sys.executable + "\nprint('codex-cli 0.163.0')\n")
        executable.chmod(0o700)
        return seal("runtime-profile", fixture_profile(executable) | {"qualification": qualification})

    def test_doctor_separates_observed_identity_from_unperformed_qualification(self):
        report = CodexCLI(self.version_profile()).doctor()
        self.assertTrue(report["ok"])
        self.assertFalse(report["qualified"])
        observed = {item["check"]: item["status"] for item in report["observations"]}
        self.assertEqual(observed["runtime_identity"], "passed")
        self.assertEqual(observed["model_free_command_canaries"], "not_run")
        self.assertTrue(all(item["status"] == "not_run" for item in report["unperformed_qualification_checks"]))
        self.assertTrue(all(item["basis"] == "static_runtime_contract" and not item["observed_by_this_call"]
                            for item in report["blocker_details"]))
        self.assertEqual(report["blockers"], ["exec_discovery_isolation_unqualified", "owned_no_daemon_lifetime_unqualified"])
        if sys.platform == "darwin":
            detail = next(item for item in report["blocker_details"] if item["code"] == "owned_no_daemon_lifetime_unqualified")
            self.assertEqual(detail["backend"], "darwin-kqueue-no-fork")
            self.assertIn("every observed fork", detail["limitation"])

    def test_passed_command_probe_does_not_claim_context_or_lifetime_qualification(self):
        adapter = CodexCLI(self.version_profile("production"))
        # Fault-inject just this external command-probe result. It is not a
        # stored receipt and cannot prove either independent qualification gate.
        with patch.object(adapter, "probe_sandbox", return_value={"passed": True, "status": "command_canaries_only", "checks": []}):
            report = adapter.doctor()
        self.assertFalse(report["qualified"])
        self.assertTrue(report["command_canaries"]["passed"])
        observed = {item["check"]: item["status"] for item in report["observations"]}
        self.assertEqual(observed["profile_preflight"], "blocked")
        self.assertEqual(observed["model_free_command_canaries"], "passed")
        self.assertTrue(all(item["status"] == "not_run" for item in report["unperformed_qualification_checks"]))

    def test_failed_profile_is_reported_before_any_runtime_observation(self):
        profile = self.version_profile() | {"executable_sha256": "0" * 64}
        report = CodexCLI(profile).doctor()
        self.assertFalse(report["ok"])
        self.assertFalse(report["qualified"])
        self.assertEqual(report["errors"][0]["code"], "runtime_changed")
        observed = {item["check"]: item["status"] for item in report["observations"]}
        self.assertEqual(observed["profile_preflight"], "failed")
        self.assertEqual(observed["runtime_identity"], "not_run")
        self.assertEqual(observed["model_free_command_canaries"], "not_run")

    def test_changed_executable_or_policy_is_rejected(self):
        for changes, code in (({"executable_sha256":"0"*64}, "runtime_changed"),
                              ({"permission_policy_digest":"0"*64}, "runtime_policy_changed"),
                              ({"runtime_version":"0.164.0"}, "runtime_version_unsupported")):
            with self.assertRaises(TaskAlongError) as result:
                CodexCLI(self.profile|changes).preflight(qualification="synthetic", budget={})
            self.assertEqual(result.exception.code, code)

    def test_named_profile_uses_exact_roots_and_no_legacy_sandbox_flags(self):
        adapter = CodexCLI(self.profile)
        argv = adapter.sandbox_argv(["/usr/bin/true"], workspace="/tmp/workspace", git_common_dir="/tmp/common.git", control_dir="/tmp/control")
        self.assertEqual(argv[1:7], ["--no-daemon", "sandbox", "-P", "taskalong", "-C", str(Path("/tmp/workspace").resolve())])
        self.assertNotIn("--strict-config", argv)
        combined = " ".join(argv)
        self.assertIn('":minimal"="read"', combined)
        self.assertIn('":slash_tmp"="read"', combined)
        self.assertIn('network={enabled=false}', combined)
        self.assertNotIn(":workspace_roots", combined)
        self.assertNotIn("sandbox_mode", combined)
        self.assertNotIn("approve-for-me", combined)

    def test_unknown_permission_policy_escape_hatch_is_rejected(self):
        profile = self.profile | {"permission_policy": {"extra_args": ["--dangerously-bypass-approvals-and-sandbox"]}}
        with self.assertRaises(TaskAlongError):
            CodexCLI(profile).sandbox_argv(["/usr/bin/true"], workspace="/tmp/workspace", git_common_dir="/tmp/common.git", control_dir="/tmp/control")


if __name__ == "__main__": unittest.main()
