"""Public adapter seams remain finite data and carry no execution authority."""
from dataclasses import FrozenInstanceError
from pathlib import Path
import unittest

from taskalong.errors import TaskAlongError
from taskalong.local_provider_contract import PreparedProviderTask, ProviderLimits
from taskalong.validation import canonical_bytes


class LocalProviderContractTests(unittest.TestCase):
    def task(self):
        root = Path.cwd().resolve()
        return {
            "provider": "codex", "backend": None, "run_id": "run-example",
            "attempt_id": "attempt-example", "operation_key": "start-example",
            "request_digest": "a" * 64, "configuration_digest": "b" * 64,
            "read_context": {"reference.txt": {"content": "reference\n"}},
            "writable_outputs": {"new.py": None}, "workspace": str(root / "workspace"),
            "control_root": str(root / "control"), "prompt_file": str(root / "control/prompt.txt"),
            "result_file": None, "absolute_deadline": 1,
            "remaining_budget": ProviderLimits().to_dict(), "context_policy": "include",
            "requested_model": "example-model", "requested_effort": "high",
        }

    def test_limits_are_explicit_finite_and_closed(self):
        defaults = ProviderLimits()
        self.assertEqual(ProviderLimits.from_dict(defaults.to_dict()), defaults)
        for field, values in {
            "attempt_seconds": (True, 0, 1441, float("inf")),
            "max_output_bytes": (False, 0, 64 * 1024 * 1024 + 1),
            "max_protocol_records": (0, 131073, 1.5),
            "max_record_bytes": (0, 16 * 1024 * 1024 + 1),
            "max_proposal_bytes": (0, 1048577),
            "max_controller_submissions": (0, 2, True),
        }.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(TaskAlongError):
                    ProviderLimits.from_dict(defaults.to_dict() | {field: value})
        for value in ({}, defaults.to_dict() | {"hard_cost_usd": 1}, []):
            with self.subTest(value=value), self.assertRaises(TaskAlongError):
                ProviderLimits.from_dict(value)
        with self.assertRaises(TaskAlongError):
            ProviderLimits(max_output_bytes=16, max_record_bytes=17)

    def test_prepared_value_is_a_deep_immutable_copy(self):
        original = self.task()
        prepared = PreparedProviderTask.from_dict(original)
        original["writable_outputs"]["new.py"] = "changed\n"
        copy = prepared.to_dict()
        copy["read_context"]["reference.txt"]["content"] = "changed\n"
        self.assertIsNone(prepared.to_dict()["writable_outputs"]["new.py"])
        self.assertEqual(prepared.to_dict()["read_context"]["reference.txt"]["content"], "reference\n")
        with self.assertRaises(FrozenInstanceError):
            prepared.payload_json = b"{}"
        self.assertNotIn("acceptance_allowed", prepared.to_dict())
        self.assertNotIn("production_dispatch_allowed", prepared.to_dict())

    def test_unknown_fields_and_unsafe_shapes_are_rejected(self):
        for patch in (
            {"dispatch_authorized": True}, {"read_context": []}, {"writable_outputs": {}},
            {"absolute_deadline": True}, {"request_digest": "bad"}, {"context_policy": []},
            {"context_policy": "silent-exclude"}, {"workspace": "relative"},
            {"prompt_file": str(Path.cwd() / "a/../prompt")}, {"requested_model": "x\nflag"},
            {"remaining_budget": {}},
        ):
            with self.subTest(patch=patch), self.assertRaises(TaskAlongError):
                PreparedProviderTask.from_dict(self.task() | patch)
        with self.assertRaises(TaskAlongError):
            PreparedProviderTask(canonical_bytes(self.task()) + b"\n")
        with self.assertRaises(TaskAlongError):
            PreparedProviderTask(bytearray(canonical_bytes(self.task())))


if __name__ == "__main__":
    unittest.main()
