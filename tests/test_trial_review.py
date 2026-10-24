"""Actual released-schema shapes with generated captures; no provider is invoked."""
import copy
import hashlib
import unittest
import uuid
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong.process import ProcessReceipt, ProcessResult
from taskalong.validation import canonical_bytes, seal_versioned
from test_trial_contracts import example_reviewer_profile, reviewer_schema_bytes

DIFF = b"diff --git a/arithmetic.py b/arithmetic.py\n--- a/arithmetic.py\n+++ b/arithmetic.py\n@@ -1 +1 @@\n-old\n+new\n"


def generated_review(comments=None, exit_code=0):
    from taskalong.trial import TrialReviewerProfile
    profile = TrialReviewerProfile.from_dict(seal_versioned("reviewer-profile", example_reviewer_profile(), version="2.8"))
    subject = {"run_id": str(uuid.uuid4()), "spec_digest": "a" * 64, "base_commit": "b" * 40,
               "candidate_commit": "c" * 40, "candidate_tree": "d" * 40,
               "diff_sha256": hashlib.sha256(DIFF).hexdigest()}
    result = {"summary": "Generated complete review", "comments": comments or [], "provider": "ollama",
              "model": "example-review-model", "review_status": "complete", "evidence_policy": "legacy",
              "coverage_mode": "full", "coverage": {"schema_version": "1.0", "enumeration_complete": True,
              "fully_reviewed": True, "enumerated_paths": ["arithmetic.py"],
              "files": [{"path": "arithmetic.py", "outcome": "reviewed"}],
              "hunks": [{"index": 1, "path": "arithmetic.py", "outcome": "reviewed"}]}}
    outcome = {"schema_version": "1.0", "status": "reviewed", "base_sha": subject["base_commit"],
               "head_sha": subject["candidate_commit"], "stage_summary": {"review": "complete"},
               "provider_calls": 1, "retry_attempts": 0, "prompt_bytes": 10, "response_bytes": 10,
               "elapsed_ms": 10, "diagnostic": None}
    process = ProcessResult(exit_code, b"", b"", False, False, True, True, False,
                            ProcessReceipt(str(uuid.uuid4()), 111, 111, 110, 1, profile.to_dict()["entrypoint"]["sha256"]),
                            10, 0, "linux-child-subreaper", False)
    return profile, subject, result, outcome, process


def observe_generated(profile, subject, result, outcome, process, *, schemas=None, stdout=b"", stderr=b""):
    from taskalong.trial_review import TrialReviewEvidence, observe_review
    blobs = {"diff": DIFF, "result": canonical_bytes(result), "outcome": canonical_bytes(outcome),
             "process": canonical_bytes(process.to_dict()), "stdout": stdout, "stderr": stderr}
    refs = {name: {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)} for name, data in blobs.items()}
    evidence = TrialReviewEvidence.from_blobs({hashlib.sha256(data).hexdigest(): data for data in blobs.values()})
    receipt = observe_review(profile, subject=subject, originals=refs, evidence=evidence,
                             schemas=schemas or reviewer_schema_bytes())
    return receipt, evidence


class TrialReviewObservationTests(unittest.TestCase):
    def test_source_separators_preserve_complete_review_capture_inventory(self):
        for separator in (b"\r", b"\v", b"\f", "\x85".encode(), "\u2028".encode(), "\u2029".encode()):
            changed = DIFF.replace(b"-old\n+new\n", b"-old" + separator + b"text\n+new" + separator + b"text\n")
            with self.subTest(separator=separator), patch(__name__ + ".DIFF", changed), \
                    patch("socket.socket", side_effect=AssertionError("No network")), \
                    patch("subprocess.Popen", side_effect=AssertionError("No process")):
                receipt, evidence = observe_generated(*generated_review())
                data = receipt.to_dict()
                self.assertTrue(data["observation_complete"])
                self.assertEqual(data["coverage"], {"files": 1, "hunks": 1})
                self.assertEqual(evidence.get(data["originals"]["diff"]["sha256"]), changed)
                self.assertFalse(data["installation_authenticated"])
                self.assertFalse(data["native_app_approval"])

    def test_review_subject_root_is_typed_and_preserves_closed_validation(self):
        values = generated_review()
        good = copy.deepcopy(values[1])
        with patch('socket.socket', side_effect=AssertionError('No network')), patch('subprocess.Popen', side_effect=AssertionError('No process')):
            for invalid in (None, [], 'subject', 7):
                with self.subTest(root=type(invalid).__name__):
                    with self.assertRaises(TaskAlongError) as caught:
                        observe_generated(values[0], invalid, *values[2:])
                    self.assertEqual(caught.exception.code, 'trial_review_invalid')
            for invalid in ({}, good | {'foreign': True}, good | {'base_commit': None}):
                with self.subTest(closed_subject=invalid):
                    with self.assertRaises(TaskAlongError):
                        observe_generated(values[0], invalid, *values[2:])
            first, evidence = observe_generated(*values)
            second, _ = observe_generated(*values)
        self.assertEqual(values[1], good)
        self.assertEqual(first.to_bytes(), second.to_bytes())
        self.assertTrue(first.to_dict()['observation_complete'])
        self.assertFalse(first.to_dict()['native_app_approval'])
        for ref in first.to_dict()['originals'].values():
            self.assertEqual(len(evidence.get(ref['sha256'])), ref['size_bytes'])

    def test_review_process_capture_root_is_typed_before_container_use(self):
        class CapturedProcess:
            def __init__(self, value): self.value = value
            def to_dict(self): return self.value
        values = generated_review()
        with patch('socket.socket', side_effect=AssertionError('No network')), patch('subprocess.Popen', side_effect=AssertionError('No process')):
            for invalid in (None, [], 'process', 7, list(values[-1].to_dict()), [[]]):
                with self.subTest(root=type(invalid).__name__, value=invalid):
                    with self.assertRaises(TaskAlongError) as caught:
                        observe_generated(*values[:-1], CapturedProcess(invalid))
                    self.assertEqual(caught.exception.code, 'invalid_document')
            receipt, _ = observe_generated(*values)
        self.assertTrue(receipt.to_dict()['observation_complete'])
        self.assertFalse(receipt.to_dict()['native_app_approval'])

    def test_each_original_stream_matches_the_fixed_process_representation(self):
        from taskalong.process import redact
        for stdout, stderr, process_stdout, process_stderr in (
            (b"", b"", b"unrelated", b""),
            (b"a", b"b", b"x", b"b"),
            (b"a", b"b", b"b", b"a"),
        ):
            with self.subTest(stdout=stdout, stderr=stderr):
                profile, subject, result, outcome, process = generated_review()
                process = process.__class__(**(process.__dict__ | {"stdout": process_stdout, "stderr": process_stderr,
                                           "output_bytes": len(stdout) + len(stderr)}))
                receipt, _ = observe_generated(profile, subject, result, outcome, process, stdout=stdout, stderr=stderr)
                self.assertFalse(receipt.to_dict()["observation_complete"])
                self.assertIn("review_stream_mismatch", receipt.to_dict()["reason_codes"])
        for raw in (b"ordinary output", b"invalid UTF-8: \xff", b"Bearer SYNTHETIC_REDACTION_CANARY"):
            with self.subTest(representation=raw):
                profile, subject, result, outcome, process = generated_review()
                process = process.__class__(**(process.__dict__ | {"stdout": redact(raw), "output_bytes": len(raw)}))
                receipt, evidence = observe_generated(profile, subject, result, outcome, process, stdout=raw)
                self.assertTrue(receipt.to_dict()["observation_complete"])
                self.assertEqual(evidence.get(receipt.to_dict()["originals"]["stdout"]["sha256"]), raw)

    def test_closed_released_schema_reader_preserves_exit_and_raw_finding_instances_without_approval(self):
        comments = [{"path": "arithmetic.py", "line": 1, "body": "Generated finding", "blocking": True}] * 2
        values = generated_review(comments, exit_code=2)
        with patch("socket.socket", side_effect=AssertionError("No network")), \
                patch("subprocess.Popen", side_effect=AssertionError("No process")):
            receipt, evidence = observe_generated(*values)
        data = receipt.to_dict()
        self.assertTrue(data["observation_complete"])
        self.assertEqual(data["observed"]["exit_code"], 2)
        self.assertEqual(data["observed"]["review_status"], "complete")
        self.assertEqual(len(data["findings"]), 2)
        self.assertNotEqual(data["findings"][0]["fingerprint"], data["findings"][1]["fingerprint"])
        self.assertFalse(data["native_app_approval"])
        self.assertTrue(data["observation_only"])
        self.assertEqual(evidence.get(data["originals"]["result"]["sha256"]), canonical_bytes(values[2]))
        self.assertIsNone(data["usage"]["tokens"])
        self.assertIsNone(data["usage"]["cost_usd"])

    def test_partial_errors_wrong_subject_model_schema_and_lost_cessation_cannot_be_complete(self):
        for defect in ("partial", "coverage", "excluded", "unknown_prior", "budget", "stage", "subject", "model", "provider", "cessation", "output_limit", "exit", "transaction"):
            with self.subTest(defect=defect):
                profile, subject, result, outcome, process = generated_review()
                if defect == "partial": result["review_status"] = "partial"
                elif defect == "coverage": result["coverage"]["fully_reviewed"] = False
                elif defect == "excluded": result["coverage"]["files"][0]["reason"] = "binary"
                elif defect == "unknown_prior": result["finding_lifecycles"] = [{"fingerprint": "f" * 64, "state": "uncertain"}]
                elif defect == "budget": outcome["status"] = "budget_exhausted"
                elif defect == "stage": outcome["stage_summary"] = {}
                elif defect == "subject": outcome["head_sha"] = "e" * 40
                elif defect == "model": result["model"] = None
                elif defect == "provider": result["provider"] = "fixture"
                elif defect == "cessation": process = process.__class__(**(process.__dict__ | {"group_termination_confirmed": False}))
                elif defect == "output_limit": process = process.__class__(**(process.__dict__ | {"output_limited": True}))
                elif defect == "exit": process = process.__class__(**(process.__dict__ | {"exit_code": 3}))
                elif defect == "transaction": result["transaction"] = {"foreign": True}
                try:
                    receipt, _ = observe_generated(profile, subject, result, outcome, process)
                except TaskAlongError:
                    continue  # Invalid raw schemas refuse instead of being repaired.
                self.assertFalse(receipt.to_dict()["observation_complete"])
                self.assertTrue(receipt.to_dict()["reason_codes"])
        values = generated_review()
        changed = reviewer_schema_bytes()
        changed["review-result"] += b" "
        with self.assertRaises(TaskAlongError):
            observe_generated(*values, schemas=changed)

    def test_empty_original_streams_are_valid_but_evidence_is_immutable_hash_bound_and_bounded(self):
        from taskalong.trial_review import TrialReviewEvidence
        value = b"original private bytes"
        key = hashlib.sha256(value).hexdigest()
        blobs = {key: value, hashlib.sha256(b"").hexdigest(): b""}
        evidence = TrialReviewEvidence.from_blobs(blobs)
        blobs[key] = b"changed"
        self.assertEqual(evidence.get(key), value)
        for invalid in ({"0" * 64: value}, {key: bytearray(value)}, {key: b"x" * 1_048_577}):
            with self.assertRaises(TaskAlongError):
                TrialReviewEvidence.from_blobs(invalid)


if __name__ == "__main__":
    unittest.main()
