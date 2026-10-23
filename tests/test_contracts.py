"""Original public document fixtures and adversarial boundary tests."""

from __future__ import annotations

import copy
import dataclasses
import json
import tempfile
import unittest
from pathlib import Path

from taskalong.contracts import TaskSpec
from taskalong.errors import TaskAlongError
from taskalong.paths import contained_path, private_directory, safe_relative
from taskalong.validation import canonical_bytes, digest, loads, seal, screen_sensitive, validate


def example_spec() -> dict:
    return seal("task-spec", {
        "task_id": "synthetic-task", "revision": 1,
        "goal": "Correct the bounded synthetic arithmetic function.", "non_goals": [],
        "repository": {"registration_id": "11111111-1111-4111-8111-111111111111", "base_commit": "a" * 40, "base_ref": "main"},
        "scope": {"files": ["arithmetic.py"], "operations": ["modify"]},
        "criteria": [{"id": "arithmetic", "description": "The function passes its declared unittest.", "check_ids": ["unit"]}],
        "checks": [{"id": "unit", "argv": ["python3", "-m", "unittest"], "cwd": ".", "timeout_seconds": 20, "expected_exit_code": 0, "criterion_ids": ["arithmetic"], "required": True}],
        "execution": {"adapter": "codex-cli", "profile_id": "fixture", "profile_digest": "b" * 64},
        "permissions": {"local_edit": True, "local_commit": True, "inference_destination_id": "fixture", "allowed_effects": ["execute", "verify", "commit_candidate"]},
        "budget": {"max_attempts": 2, "attempt_seconds": 30, "total_active_seconds": 60, "max_output_bytes": 1048576, "hard_cost_usd": None, "hard_tokens": None},
        "review": {"required": True, "integration": "reviewsensei", "contract": "0.8.8/v1", "config_digest": "c" * 64, "require_full_coverage": True},
        "publication": None, "qualification": "synthetic",
    })


def example_profile(executable: str = "/usr/bin/false") -> dict:
    policy = {"workspace_write": True, "network": False}
    return seal("runtime-profile", {
        "profile_id": "fixture", "qualification": "synthetic", "adapter": "codex-cli",
        "executable_path": executable, "executable_sha256": "d" * 64,
        "runtime_version": "0.163.0", "model": "fixture", "reasoning_effort": "low", "service_tier": None,
        "inference_destination_id": "fixture", "permission_policy": policy,
        "permission_policy_digest": digest(policy), "toolchain_read_roots": [],
        "credential_source_ref": None, "qualification_receipt_ids": [],
    })


class ContractTests(unittest.TestCase):
    def test_frozen_document_cannot_be_changed_through_nested_data(self):
        spec = TaskSpec.from_dict(example_spec())
        exposed = spec.to_dict()
        exposed["scope"]["files"].append("outside.py")
        self.assertEqual(spec.to_dict()["scope"]["files"], ["arithmetic.py"])
        with self.assertRaises(dataclasses.FrozenInstanceError):
            spec._canonical = b"{}"

    def test_duplicate_keys_and_noncanonical_numbers_are_rejected(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":1.0}', b'{"x":NaN}', b'{"x":Infinity}', b'[]', b'{"x":"\xff"}'):
            with self.subTest(raw=raw), self.assertRaises(TaskAlongError):
                loads(raw)
        for value in ({"x": 0.0}, {"x": float("nan")}, {"x": 2**80}, {1: "x"}):
            with self.subTest(value=type(value)), self.assertRaises(TaskAlongError):
                canonical_bytes(value)

    def test_unknown_fields_versions_boolean_integer_and_ids_fail(self):
        for update in ({"unexpected": True}, {"schema_version": "1.1"}, {"revision": True}, {"task_id": "bad\nidentity"}):
            document = example_spec() | update
            document["digest"] = digest(document)
            with self.subTest(update=update), self.assertRaises(TaskAlongError):
                validate("task-spec", document)

    def test_nested_unknown_fields_and_unbound_criteria_fail(self):
        document = example_spec()
        document["checks"][0]["shell"] = True
        with self.assertRaises(TaskAlongError):
            seal("task-spec", document)
        document = example_spec()
        document["checks"][0]["criterion_ids"] = ["missing"]
        with self.assertRaises(TaskAlongError):
            seal("task-spec", document)
        document = example_spec()
        document["checks"][0]["required"] = False
        with self.assertRaises(TaskAlongError):
            seal("task-spec", document)

    def test_set_normalization_and_unicode_preservation(self):
        original = example_spec()
        duplicate = copy.deepcopy(original)
        duplicate["scope"]["files"] *= 2
        duplicate["permissions"]["allowed_effects"].reverse()
        self.assertEqual(seal("task-spec", duplicate)["digest"], original["digest"])
        changed = original | {"goal": "A different semantic instruction."}
        self.assertNotEqual(seal("task-spec", changed)["digest"], original["digest"])
        self.assertNotEqual(digest({"x": "é"}), digest({"x": "e\u0301"}))
        self.assertEqual(canonical_bytes({"z": "é", "a": 1}), b'{"a":1,"z":"\xc3\xa9"}')

    def test_digest_tampering_fails(self):
        document = example_spec()
        document["goal"] = "Modified without a new digest."
        with self.assertRaises(TaskAlongError) as failure:
            validate("task-spec", document)
        self.assertEqual(failure.exception.code, "digest_mismatch")

    def test_oversized_and_deep_documents_fail(self):
        with self.assertRaises(TaskAlongError):
            loads(b'{"x":"' + b'x' * 1048576 + b'"}')
        with self.assertRaises(TaskAlongError):
            loads('{"x":' + '[' * 66 + 'null' + ']' * 66 + '}')
        document = example_spec()
        document["non_goals"] = ["z" * 16384]
        with self.assertRaises(TaskAlongError):
            seal("task-spec", document)

    def test_path_validation_and_symlink_containment(self):
        for path in ("/tmp/x", "../x", "a/../b", "a//b", "a\\b", ".git/config", "docs/AGENTS.md", ".codex/config.toml", ".env", "a*.py", "a\nx", "a/./b"):
            with self.subTest(path=path), self.assertRaises(TaskAlongError):
                safe_relative(path)
        self.assertEqual(safe_relative("src/", allow_directory=True), "src/")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            (root / "target").mkdir()
            (root / "link").symlink_to(root / "target", target_is_directory=True)
            with self.assertRaises(TaskAlongError):
                contained_path(root, "link/file.py")
            state = private_directory(root / "state")
            self.assertEqual(state.stat().st_mode & 0o777, 0o700)
            state.chmod(0o755)
            with self.assertRaises(TaskAlongError):
                private_directory(state)

    def test_credential_screen_has_safe_error_and_no_hash(self):
        for secret in ("ghp_" + "x" * 30, "-----BEGIN PRIVATE KEY-----", "https://user:password@example.invalid/path"):
            with self.assertRaises(TaskAlongError) as failure:
                screen_sensitive({"goal": secret})
            self.assertNotIn(secret, str(failure.exception))
            self.assertNotIn(digest({"secret": secret}), json.dumps(failure.exception.to_dict()))

    def test_malformed_nested_types_fail_with_stable_errors(self):
        for field, value in (("scope", []), ("checks", None), ("criteria", "invalid"), ("permissions", [])):
            document = example_spec() | {field: value}
            with self.subTest(field=field), self.assertRaises(TaskAlongError):
                seal("task-spec", document)
        for value in ([], None, True):
            with self.assertRaises(TaskAlongError):
                validate("task-spec", value)

    def test_identifier_unicode_controls_and_credentials_in_extension_maps_fail(self):
        with self.assertRaises(TaskAlongError):
            seal("task-spec", example_spec() | {"task_id": "control\u0085identity"})
        for key in ("password", "api_key", "authorization", "private_key"):
            with self.subTest(key=key), self.assertRaises(TaskAlongError):
                screen_sensitive({"extensions": {"org:metadata": {key: "synthetic credential"}}})

    def test_timestamp_validation_is_offline_and_strict_utc(self):
        base = {
            "authority_id": "22222222-2222-4222-8222-222222222222", "run_id": "11111111-1111-4111-8111-111111111111",
            "source": "local_operator", "principal": "synthetic", "decision": "authorized", "scope": ["execute"],
            "intent_digest": "f" * 64, "issued_at": "2026-10-22T10:00:00Z", "expires_at": "2026-10-22T11:00:00Z",
            "human_decision_observed": False, "qualification": "synthetic",
        }
        self.assertEqual(seal("authority", base)["issued_at"], base["issued_at"])
        for timestamp in ("Z", "2026-99-22T10:00:00Z", "2026-10-22T10:00:00+00:00", "2026-10-22 10:00:00Z"):
            with self.subTest(timestamp=timestamp), self.assertRaises(TaskAlongError):
                seal("authority", base | {"issued_at": timestamp})

    def test_profile_policy_digest_is_required(self):
        profile = example_profile()
        profile["permission_policy"]["network"] = True
        with self.assertRaises(TaskAlongError):
            seal("runtime-profile", profile)


if __name__ == "__main__":
    unittest.main()
