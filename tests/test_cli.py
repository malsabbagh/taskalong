"""Real CLI processes preserve versioned envelopes and read-only observations."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from taskalong.paths import default_state_dir

from taskalong.validation import canonical_bytes, seal, validate
from test_store import StoreFixture


class NamespaceTests(unittest.TestCase):
    def test_default_state_directories_use_taskalong_namespace(self):
        home = Path("/synthetic-home")
        with patch("taskalong.paths.Path.home", return_value=home):
            with patch("taskalong.paths.sys.platform", "darwin"):
                self.assertEqual(default_state_dir(), home / "Library/Application Support/TaskAlong")
            with patch("taskalong.paths.sys.platform", "linux"):
                with patch.dict(os.environ, {"XDG_STATE_HOME": "/synthetic-state"}, clear=True):
                    self.assertEqual(default_state_dir(), Path("/synthetic-state/taskalong"))
                with patch.dict(os.environ, {"XDG_STATE_HOME": "relative"}, clear=True):
                    self.assertEqual(default_state_dir(), home / ".local/state/taskalong")


class CLITests(StoreFixture):
    def setUp(self):
        super().setUp()
        self.cwd = self.root / "empty-cwd"
        self.cwd.mkdir()
        self.environment = dict(os.environ)
        # Source-suite callers may supply PYTHONPATH=src; preserve that explicit
        # development setup across an external CWD. Installed qualification has
        # PYTHONPATH unset and therefore takes no source fallback here.
        if self.environment.get("PYTHONPATH"):
            self.environment["PYTHONPATH"] = os.pathsep.join(str(Path(x).absolute()) for x in self.environment["PYTHONPATH"].split(os.pathsep) if x)
        self.environment["PYTHONDONTWRITEBYTECODE"] = "1"

    def cli(self, *arguments, expected=0, with_state=True):
        argv = [sys.executable, "-m", "taskalong"]
        if with_state:
            argv += ["--state-dir", str(self.state)]
        result = subprocess.run([*argv, *arguments], cwd=self.cwd, env=self.environment,
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, expected, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        return result

    def envelope(self, *arguments, expected=0):
        result = self.cli(*arguments, "--json", expected=expected)
        lines = result.stdout.strip().splitlines()
        self.assertEqual(len(lines), 1)
        document = json.loads(lines[0])
        self.assertEqual(validate("command-result", document), document)
        return document

    def test_version_and_help_work_in_empty_cwd_without_creating_state(self):
        new = self.root / "must-not-exist"
        for flag in ("--version", "--help"):
            result = self.cli("--state-dir", str(new), flag, with_state=False)
            self.assertIn("taskalong", result.stdout.lower())
            self.assertFalse(new.exists())

    def test_status_and_events_do_not_change_revision_or_launch_work(self):
        before = self.store.run(self.run["run_id"])
        observed = self.envelope("status", self.run["run_id"])
        self.assertTrue(observed["ok"])
        self.assertEqual(observed["data"], before)
        event_lines = self.cli("events", self.run["run_id"], "--jsonl").stdout.splitlines()
        self.assertEqual(len(event_lines), 1)
        event = json.loads(event_lines[0])
        self.assertEqual(event["type"], "run.created")
        self.assertEqual(validate("run-event", event), event)
        self.assertEqual(self.store.run(self.run["run_id"]), before)
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM attempts").fetchone()[0], 0)
        self.assertEqual(self.cli("events", self.run["run_id"], "--after-seq", "1", "--jsonl").stdout, "")

    def test_doctor_names_unmet_contracts_without_launching_or_claiming_qualification(self):
        before = self.store.run(self.run["run_id"])
        result = self.envelope("doctor")
        self.assertTrue(result["ok"])  # A read-only diagnostic was fulfilled.
        self.assertFalse(result["data"]["production_dispatch_qualified"])
        self.assertFalse(result["data"]["live_inference"])
        self.assertEqual(result["next_actions"], result["data"]["next_actions"])
        self.assertEqual(len(result["next_actions"]), 2)
        self.assertTrue(all(not b["observed_by_this_call"] for b in result["data"]["blocker_details"]))
        self.assertIn("production dispatch blocked", self.cli("doctor").stdout)
        self.assertEqual(self.store.run(self.run["run_id"]), before)
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM attempts").fetchone()[0], 0)

    def test_schema_and_cli_errors_are_single_bounded_json_envelopes(self):
        raw = self.root / "duplicate.json"
        raw.write_text('{"kind":"task_spec","kind":"task_spec"}')
        result = self.envelope("submit", "--spec", str(raw), "--key", "one", expected=2)
        self.assertEqual(result["errors"][0]["code"], "duplicate_key")
        changed = self.spec | {"schema_version": "2.0"}
        raw.write_bytes(canonical_bytes(changed))
        result = self.envelope("submit", "--spec", str(raw), "--key", "two", expected=2)
        self.assertEqual(result["errors"][0]["code"], "schema_validation")
        result = self.envelope("start", self.run["run_id"], "--key", "missing-revision", expected=2)
        self.assertEqual(result["errors"][0]["code"], "invalid_cli")
        result = self.envelope("resume", self.run["run_id"], "--mode", "latest", "--expected-revision", "1", "--key", "never-latest", expected=2)
        self.assertEqual(result["errors"][0]["code"], "invalid_cli")

    def test_missing_authority_and_revision_conflict_have_distinct_exits(self):
        missing = self.envelope("start", self.run["run_id"], "--expected-revision", "1", "--key", "no-authority", expected=3)
        self.assertEqual(missing["errors"][0]["code"], "authority_missing")
        conflict = self.envelope("start", self.run["run_id"], "--expected-revision", "9", "--key", "wrong-revision", expected=4)
        self.assertEqual(conflict["errors"][0]["code"], "revision_conflict")
        self.assertEqual(self.store.run(self.run["run_id"]), self.run)

    def test_read_only_status_succeeds_for_blocked_run(self):
        def block(run, db):
            run["state"] = "blocked"
            run["blocked_from"] = "running"
            run["blockers"] = [{"code": "synthetic_blocker", "message": "Synthetic prerequisite is missing.", "recovery": [{"action": "inspect"}], "effect_outcome": "not_sent"}]
        blocked = self.store.mutate(self.run["run_id"], "block", "block-once", 1, {}, block)
        result = self.envelope("status", self.run["run_id"])
        self.assertEqual(result["state"], "blocked")
        self.assertTrue(result["ok"])
        self.assertEqual(self.store.run(self.run["run_id"]), blocked)

    def test_future_store_integrity_error_uses_exit70_without_overwrite(self):
        self.store.db.execute("PRAGMA user_version=27")
        result = self.envelope("status", self.run["run_id"], expected=70)
        self.assertEqual(result["errors"][0]["code"], "unsupported_store_version")
        self.assertEqual(self.store.db.execute("PRAGMA user_version").fetchone()[0], 27)

    def test_corrupt_store_integrity_error_has_no_traceback(self):
        corrupt = self.root / "corrupt-state"
        corrupt.mkdir(mode=0o700)
        path = corrupt / "state.sqlite3"
        path.write_bytes(b"synthetic corrupt sqlite bytes")
        path.chmod(0o600)
        result = self.cli("--state-dir", str(corrupt), "status", self.run["run_id"], "--json", expected=70, with_state=False)
        document = json.loads(result.stdout)
        self.assertFalse(document["ok"])
        self.assertEqual(validate("command-result", document), document)
        self.assertEqual(path.read_bytes(), b"synthetic corrupt sqlite bytes")


    def test_packaged_guides_work_without_opening_a_state_store(self):
        unused = self.root / "guide-must-not-create-state"
        result = self.cli("--state-dir", str(unused), "guide", "fixture", "--json", with_state=False)
        document = json.loads(result.stdout)
        self.assertTrue(document["ok"])
        self.assertEqual(document["data"]["name"], "fixture")
        self.assertIn("runtime_policy_unsupported", document["data"]["markdown"])
        self.assertIn("configure_command_sandbox", document["data"]["markdown"])
        self.assertIn("native-example", document["data"]["markdown"])
        self.assertFalse(unused.exists())
        for name in ("operations", "contracts", "qualification"):
            self.assertIn("#", self.cli("guide", name, with_state=False).stdout)

    def test_missing_review_executable_is_an_actionable_prerequisite(self):
        config = self.root / "missing-review.yml"
        config.write_text("schema: 1\n")
        previous = self.environment.get("PATH")
        self.environment["PATH"] = "/usr/bin:/bin"
        try:
            for extra in ((), ("--executable", str(self.root))):
                result = self.cli("configure-review", "--config", str(config), "--python-executable", sys.executable,
                                  *extra, "--json", expected=3)
                error = json.loads(result.stdout)["errors"][0]
                self.assertEqual(error["code"], "review_executable_missing")
                self.assertEqual(error["effect_outcome"], "not_sent")
                self.assertEqual(error["recovery"][0]["option"], "--executable")
        finally:
            if previous is None:
                self.environment.pop("PATH", None)
            else:
                self.environment["PATH"] = previous


if __name__ == "__main__":
    unittest.main()
