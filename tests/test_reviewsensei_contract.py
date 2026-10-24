"""Actual released CLI + offline schema admission; no live inference."""
import copy
import hashlib
import importlib.metadata
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong.process import ProcessBoundaryError, run_bounded as actual_run_bounded
from taskalong.integrations.reviewsensei import ReviewSenseiAdapter, diff_inventory, validate_review_documents

DIFF = (b"diff --git a/answer.py b/answer.py\nindex 1111111..2222222 100644\n--- a/answer.py\n+++ b/answer.py\n"
        b"@@ -1 +1 @@\n-answer = 1\n+answer = 2\n")


class DiffInventoryTests(unittest.TestCase):
    def test_git_diff_keeps_source_separators_inside_physical_hunk_lines(self):
        for configuration in ("normal", "conflicting"):
            for separator in ("\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"):
                with self.subTest(configuration=configuration, separator=repr(separator)), tempfile.TemporaryDirectory() as name:
                    root = Path(name)
                    for directory, value in (("old", "before"), ("new", "after")):
                        (root / directory).mkdir()
                        (root / directory / "answer.py").write_bytes(
                            f'answer = "{value}{separator}text"\n'.encode("utf-8"))
                    overrides = {}
                    if configuration == "conflicting":
                        config = root / "conflicting.gitconfig"
                        config.write_text("[color]\n\tui = always\n[diff]\n\tnoprefix = true\n"
                                          "\toutputIndicatorNew = !\n\toutputIndicatorOld = ?\n")
                        overrides = {"GIT_CONFIG_GLOBAL": str(config), "GIT_CONFIG_COUNT": "2",
                                     "GIT_CONFIG_KEY_0": "color.ui", "GIT_CONFIG_VALUE_0": "always",
                                     "GIT_CONFIG_KEY_1": "diff.noprefix", "GIT_CONFIG_VALUE_1": "true"}
                    with patch.dict(os.environ, overrides):
                        # This generated no-index fixture must not inherit Git
                        # configuration or attributes from the developer's host.
                        env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
                        env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", GIT_ATTR_NOSYSTEM="1")
                        result = subprocess.run(
                            ["git", "-c", "core.attributesFile=" + os.devnull, "-c", "core.autocrlf=false",
                             "diff", "--no-index", "--no-ext-diff", "--no-textconv", "--no-color",
                             "--src-prefix=a/", "--dst-prefix=b/", "--", "old/answer.py", "new/answer.py"],
                            cwd=root, env=env, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn(separator.encode("utf-8"), result.stdout)
                    self.assertEqual(diff_inventory(result.stdout),
                                     (["new/answer.py"], [(1, "new/answer.py")]))

    def test_inventory_uses_global_hunk_indices(self):
        second = DIFF.replace(b"answer.py", b"other.py")
        self.assertEqual(diff_inventory(DIFF + second), (["answer.py", "other.py"], [(1, "answer.py"), (2, "other.py")]))

    def test_added_header_like_content_remains_a_hunk_line(self):
        content = DIFF.replace(b"@@ -1 +1 @@\n-answer = 1\n+answer = 2\n",b"@@ -1 +1 @@\n-answer = 1\n+++ b/not-a-header\n")
        self.assertEqual(diff_inventory(content),(["answer.py"],[(1,"answer.py")]))

    def test_unsupported_or_ambiguous_changes_fail_closed(self):
        for value in (b"", DIFF.replace(b"b/answer.py", b"b/../escape"), DIFF + DIFF,
                      DIFF.replace(b"@@ -1 +1 @@", b"@@ invalid"), DIFF + b"GIT binary patch\n"):
            with self.subTest(value=value[:40]), self.assertRaises(TaskAlongError):
                diff_inventory(value)


class ReviewProcessOutcomeTests(unittest.TestCase):
    """Actual external synthetic processes cannot forge review quiescence.

    The schema/version payloads are intentionally synthetic boundary data. No
    result is accepted by these fixtures; released-schema behavior is exercised
    separately by ReleasedReviewTests.
    """
    STAGES = ("schemas", "version", "review")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.subject = {"base_commit": "1" * 40, "candidate_commit": "2" * 40,
                        "candidate_tree": "3" * 40, "diff_sha256": hashlib.sha256(DIFF).hexdigest()}

    def invocation(self, name, *, detached_stage=None, slow_stage=None):
        root = self.root / name
        root.mkdir()
        config = root / "config.yml"
        config.write_text("schema: 1\n")
        fixture = root / "fixture.json"
        fixture.write_text('{"summary":"Synthetic unadmitted boundary output.","comments":[]}')
        schema_executable, executable = root / "observe-schemas", root / "observe-review"
        program = (
            f"#!{sys.executable}\n"
            "import os,sys,time\nfrom pathlib import Path\n"
            f"root=Path({str(root)!r})\n"
            "stage='schemas' if Path(sys.argv[0]).name=='observe-schemas' else ('version' if '--version' in sys.argv else 'review')\n"
            "(root/(stage+'.dispatched')).write_text('synthetic target entered')\n"
            f"if stage=={detached_stage!r}:\n"
            "    child=os.fork()\n"
            "    if child==0:\n"
            "        os.setsid()\n"
            "        null=os.open(os.devnull,os.O_RDWR)\n"
            "        for fd in (0,1,2): os.dup2(null,fd)\n"
            "        if null>2: os.close(null)\n"
            "        time.sleep(0.4)\n"
            "        os._exit(0)\n"
            "print('review-sensei 0.8.8' if stage=='version' else '{}',flush=True)\n"
            f"if stage=={slow_stage!r}: time.sleep(3)\n"
        )
        for path in (schema_executable, executable):
            path.write_text(program)
            path.chmod(0o700)
        adapter = ReviewSenseiAdapter(executable, python_executable=schema_executable)
        def invoke(**kwargs):
            return adapter.review(DIFF, self.subject, config_path=config, qualification="synthetic",
                                  invocation_dir=root / "output", expected_config_digest=hashlib.sha256(config.read_bytes()).hexdigest(),
                                  fixture_response=fixture, **kwargs)
        return root, adapter, invoke

    @staticmethod
    def stage(argv):
        if Path(argv[0]).name == "observe-schemas":
            return "schemas"
        return "version" if "--version" in argv else "review"

    def assert_stopped_before_later_stages(self, root, stage):
        for later in self.STAGES[self.STAGES.index(stage) + 1:]:
            self.assertFalse((root / (later + ".dispatched")).exists(), later + " must not dispatch after an unresolved process")

    @unittest.skipUnless(hasattr(os, "fork"), "Requires the supported POSIX process boundary")
    def test_real_escaped_child_keeps_all_three_process_stages_uncertain(self):
        for stage in self.STAGES:
            with self.subTest(stage=stage):
                root, adapter, invoke = self.invocation("escaped-" + stage, detached_stage=stage)
                with self.assertRaises(TaskAlongError) as failure:
                    invoke()
                self.assertEqual(failure.exception.effect_outcome, "uncertain")
                self.assertEqual(failure.exception.exit_code, 5)
                self.assertEqual(failure.exception.code, "review_process_unreconciled")
                self.assertTrue((root / (stage + ".dispatched")).exists())
                self.assert_stopped_before_later_stages(root, stage)

    def test_lost_cessation_field_never_becomes_a_successful_probe(self):
        for stage in self.STAGES:
            with self.subTest(stage=stage):
                root, adapter, invoke = self.invocation("lost-cessation-" + stage)
                def boundary(argv, **kwargs):
                    process = actual_run_bounded(argv, **kwargs)
                    if self.stage(argv) == stage:
                        # Inject receipt loss after a real external invocation;
                        # never synthesize a successful producer or approval.
                        fields = dict(vars(process))
                        fields.pop("termination_confirmed")
                        return SimpleNamespace(**fields)
                    return process
                with patch("taskalong.integrations.reviewsensei.run_bounded", side_effect=boundary):
                    with self.assertRaises(TaskAlongError) as failure:
                        invoke()
                self.assertEqual(failure.exception.effect_outcome, "uncertain")
                self.assertEqual(failure.exception.exit_code, 5)
                self.assert_stopped_before_later_stages(root, stage)

    def test_real_predispatch_gate_fault_preserves_not_sent_in_every_stage(self):
        for stage in self.STAGES:
            with self.subTest(stage=stage):
                root, adapter, invoke = self.invocation("gate-" + stage)
                def boundary(argv, **kwargs):
                    if self.stage(argv) == stage:
                        def fail_gate(_receipt):
                            raise ProcessBoundaryError("synthetic unavailable gate", code="runtime_lifecycle_unsupported", effect_outcome="not_sent")
                        kwargs["on_spawn"] = fail_gate
                    return actual_run_bounded(argv, **kwargs)
                with patch("taskalong.integrations.reviewsensei.run_bounded", side_effect=boundary):
                    with self.assertRaises(TaskAlongError) as failure:
                        invoke()
                self.assertEqual(failure.exception.effect_outcome, "not_sent")
                self.assertEqual(failure.exception.exit_code, 3)
                self.assertFalse((root / (stage + ".dispatched")).exists())
                self.assert_stopped_before_later_stages(root, stage)

    def test_real_postdispatch_callback_error_preserves_uncertainty_in_every_stage(self):
        for stage in self.STAGES:
            with self.subTest(stage=stage):
                root, adapter, invoke = self.invocation("callback-" + stage)
                def boundary(argv, **kwargs):
                    if self.stage(argv) == stage:
                        def lose_receipt(_line):
                            raise ProcessBoundaryError("synthetic lost receipt", effect_outcome="uncertain")
                        kwargs["on_stdout_line"] = lose_receipt
                    return actual_run_bounded(argv, **kwargs)
                with patch("taskalong.integrations.reviewsensei.run_bounded", side_effect=boundary):
                    with self.assertRaises(TaskAlongError) as failure:
                        invoke()
                self.assertEqual(failure.exception.effect_outcome, "uncertain")
                self.assertEqual(failure.exception.exit_code, 5)
                self.assertTrue((root / (stage + ".dispatched")).exists())
                self.assert_stopped_before_later_stages(root, stage)

    def test_unconfirmed_closed_gate_cleanup_stays_uncertain_in_every_stage(self):
        from taskalong import process as boundary
        tracker_type = boundary._LinuxTracker if sys.platform == "linux" else boundary._DescendantTracker
        real_close = tracker_type.close
        for stage in self.STAGES:
            with self.subTest(stage=stage):
                root, adapter, invoke = self.invocation("unconfirmed-gate-" + stage)
                observed = []
                def fail_close(tracker):
                    real_close(tracker)
                    raise OSError(5, "PRIVATE_REVIEW_CLEANUP")
                def owned_boundary(argv, **kwargs):
                    if self.stage(argv) != stage:
                        return actual_run_bounded(argv, **kwargs)
                    def veto(_receipt):
                        raise ProcessBoundaryError("Synthetic closed gate", effect_outcome="not_sent")
                    kwargs["on_spawn"] = veto
                    try:
                        with patch.object(tracker_type, "close", fail_close):
                            return actual_run_bounded(argv, **kwargs)
                    except ProcessBoundaryError as exc:
                        observed.append(exc)
                        raise
                with patch("taskalong.integrations.reviewsensei.run_bounded", side_effect=owned_boundary):
                    with self.assertRaises(TaskAlongError) as failure:
                        invoke()
                self.assertEqual(len(observed), 1)
                self.assertEqual(observed[0].effect_outcome, "not_sent")
                self.assertFalse(observed[0].process_result.termination_confirmed)
                self.assertIn(("tracker_close", 5), observed[0].boundary_failures)
                self.assertEqual(failure.exception.effect_outcome, "uncertain")
                self.assertEqual(failure.exception.exit_code, 5)
                self.assertNotIn("PRIVATE_REVIEW_CLEANUP", str(failure.exception))
                self.assertFalse((root / (stage + ".dispatched")).exists())
                self.assert_stopped_before_later_stages(root, stage)

    def test_control_callback_default_not_sent_does_not_relabel_dispatched_child(self):
        root, adapter, invoke = self.invocation("heartbeat", slow_stage="schemas")
        def lost_control():
            if (root / "schemas.dispatched").exists():
                raise TaskAlongError("revision_conflict", "Synthetic changed control-plane revision.", exit_code=4)
        with self.assertRaises(TaskAlongError) as failure:
            invoke(heartbeat=lost_control)
        self.assertEqual(failure.exception.effect_outcome, "uncertain")
        self.assertEqual(failure.exception.exit_code, 5)
        self.assertTrue((root / "schemas.dispatched").exists())
        self.assertFalse((root / "version.dispatched").exists())

    def test_confirmed_postdispatch_release_failure_is_known(self):
        root, adapter, invoke = self.invocation("unsupported-version")
        source = Path(adapter.executable)
        source.write_text(source.read_text().replace("review-sensei 0.8.8", "review-sensei 99.0.0"))
        adapter = ReviewSenseiAdapter(source, python_executable=adapter.python_executable)
        with self.assertRaises(TaskAlongError) as failure:
            adapter.review(DIFF, self.subject, config_path=root / "config.yml", qualification="synthetic",
                           invocation_dir=root / "output", expected_config_digest=hashlib.sha256((root / "config.yml").read_bytes()).hexdigest(),
                           fixture_response=root / "fixture.json")
        self.assertEqual(failure.exception.code, "review_release_unsupported")
        self.assertEqual(failure.exception.effect_outcome, "known")
        self.assertEqual(failure.exception.exit_code, 3)
        self.assertFalse((root / "review.dispatched").exists())


class ReleasedReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.python = os.environ.get("TASKALONG_REVIEW_PYTHON", sys.executable)
        cls.executable = os.environ.get("TASKALONG_REVIEW_EXECUTABLE")
        if not cls.executable:
            try:
                if importlib.metadata.version("review-sensei") == "0.8.8":
                    cls.executable = shutil.which("review-sensei")
            except importlib.metadata.PackageNotFoundError:
                pass
        if not cls.executable:
            raise unittest.SkipTest("optional released 0.8.8 integration environment unavailable; installed harness requires it")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / "approved.yml"
        self.config.write_text("schema: 1\n")
        self.fixture = self.root / "response.json"
        self.fixture.write_text('{"summary":"Synthetic clean review.","comments":[]}\n')
        self.config_digest = hashlib.sha256(self.config.read_bytes()).hexdigest()
        self.subject = {"base_commit": "1" * 40, "candidate_commit": "2" * 40,
                        "candidate_tree": "3" * 40, "diff_sha256": hashlib.sha256(DIFF).hexdigest()}
        self.adapter = ReviewSenseiAdapter(self.executable, python_executable=self.python)

    def review(self, name="invocation", **kwargs):
        return self.adapter.review(DIFF, self.subject, config_path=self.config, qualification="synthetic",
                                   invocation_dir=self.root / name, expected_config_digest=self.config_digest,
                                   fixture_response=self.fixture, **kwargs)

    def test_actual_released_fixture_contract(self):
        receipt = self.review()
        self.assertEqual(receipt.version, "0.8.8")
        self.assertEqual(receipt.outcome["provider_calls"], 1)
        self.assertEqual(receipt.result["evidence_policy"], "legacy")
        self.assertEqual(receipt.to_dict()["assurance"], "full-reviewed-diff-v1")
        self.assertNotIn("summary", receipt.to_dict())
        self.assertNotIn("schema_version", receipt.result)  # v1 review-result deliberately has no root version

    def test_existing_output_directory_and_changed_config_block(self):
        (self.root / "stale").mkdir()
        with self.assertRaises(TaskAlongError) as exc:
            self.review("stale")
        self.assertEqual(exc.exception.code, "review_stale_output")
        self.assertEqual(exc.exception.effect_outcome, "not_sent")
        self.config.write_text("schema: 1\n# changed\n")
        with self.assertRaises(TaskAlongError) as exc:
            self.review()
        self.assertEqual(exc.exception.code, "review_config_changed")
        self.assertEqual(exc.exception.effect_outcome, "not_sent")

    def test_aggregate_output_budget_blocks_before_fixture_dispatch(self):
        with self.assertRaises(TaskAlongError) as exc:
            self.review(max_output_bytes=10)
        self.assertEqual(exc.exception.code,"review_output_budget_exhausted")
        self.assertEqual(exc.exception.effect_outcome,"known")
        self.assertFalse((self.root / "invocation" / "result.json").exists())

    def test_unsupported_release_and_missing_fresh_output_block(self):
        for version,expected in (("99.0.0","review_release_unsupported"),("0.8.8","review_output_missing")):
            fake=self.root / ("fake-review-"+version)
            fake.write_text(f"#!{sys.executable}\nimport sys\nif '--version' in sys.argv: print('review-sensei {version}')\n")
            fake.chmod(0o700)
            adapter=ReviewSenseiAdapter(fake,python_executable=self.python)
            with self.subTest(version=version),self.assertRaises(TaskAlongError) as exc:
                adapter.review(DIFF,self.subject,config_path=self.config,qualification="synthetic",
                               invocation_dir=self.root / version,expected_config_digest=self.config_digest,fixture_response=self.fixture)
            self.assertEqual(exc.exception.code,expected)

    def test_fixture_never_enters_production(self):
        with self.assertRaises(TaskAlongError) as exc:
            self.adapter.review(DIFF, self.subject, config_path=self.config, qualification="production",
                                invocation_dir=self.root / "live", expected_config_digest=self.config_digest,
                                fixture_response=self.fixture)
        self.assertEqual(exc.exception.code, "fixture_in_production")
        self.assertFalse((self.root / "live").exists())

    def test_real_nonzero_review_with_blocking_finding(self):
        self.fixture.write_text('{"summary":"Required fix.","comments":[{"path":"answer.py","line":1,"body":"[P1] Synthetic required fix.","blocking":true}]}')
        with self.assertRaises(TaskAlongError) as failure:
            self.review()
        self.assertEqual(failure.exception.effect_outcome, "known")
        self.assertEqual(failure.exception.exit_code, 3)

    def test_exact_output_gate_rejects_each_mandatory_failure(self):
        receipt = self.review()
        schemas = self.adapter._schemas(self.root)
        mutations = [
            ("wrong-head", lambda r, o: o.update(head_sha="4" * 40)),
            ("summary-only", lambda r, o: r.update(review_status="summary-only")),
            ("partial", lambda r, o: r.update(coverage_only_partial=True)),
            ("missing-hunk", lambda r, o: r["coverage"].update(hunks=[])),
            ("missing-file", lambda r, o: r["coverage"].update(files=[])),
            ("incomplete-enumeration", lambda r, o: r["coverage"].update(enumeration_complete=False)),
            ("budget", lambda r, o: r["coverage"]["hunks"][0].update(outcome="budget-exhausted")),
            ("wrong-provider", lambda r, o: r.update(provider="openrouter")),
            ("stale-outcome", lambda r, o: o.update(status="skipped_stale")),
            ("blocking-contradiction", lambda r, o: r["comments"].append({"path":"answer.py","line":1,"body":"fix","blocking":True})),
        ]
        for label, mutate in mutations:
            result, outcome = copy.deepcopy(receipt.result), copy.deepcopy(receipt.outcome)
            mutate(result, outcome)
            with self.subTest(label=label), self.assertRaises(TaskAlongError):
                validate_review_documents(result, outcome, schemas=schemas, diff=DIFF, subject=self.subject,
                                          exit_code=0, qualification="synthetic", expected_provider="fixture")
        for code in (1, 2, 130, None):
            with self.subTest(exit=code), self.assertRaises(TaskAlongError):
                validate_review_documents(receipt.result, receipt.outcome, schemas=schemas, diff=DIFF,
                                          subject=self.subject, exit_code=code,
                                          qualification="synthetic", expected_provider="fixture")


if __name__ == "__main__":
    unittest.main()
