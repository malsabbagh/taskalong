"""Original Cursor fixture contracts; no installed vendor execution is implied."""
from dataclasses import FrozenInstanceError
import hashlib
import json
from importlib import resources
from pathlib import Path
import unittest
import uuid

from jsonschema import Draft202012Validator

from taskalong.errors import TaskAlongError
from taskalong.validation import loads, schema, schema_names, seal_versioned


def example_cursor_config():
    return {
        "driver_id": "cursor-cli", "driver_version": "cursor-print-fixture-1",
        "projection": "cursor-print-fixture/1", "wire_version": "2.5",
        "installation_digest": "a" * 64, "provider_profile_digest": "b" * 64,
        "qualification": "synthetic", "registration": "operator_registered_fixture",
        "executable": {"path": "/opt/taskalong/fixture-cursor", "sha256": "c" * 64},
        "credential_ref": "fixture-cursor-account",
        "expected_reported_model": "taskalong-fixture-cursor-model",
        "policy_digests": {"instructions": "d" * 64, "tools": "e" * 64,
                           "worker_sandbox": "f" * 64, "check_binding": "1" * 64},
        "launch": {"mode": "print", "input_format": "text", "output_format": "stream-json",
                   "session_policy": "fresh"},
    }


def cursor_packet():
    from test_contracts import example_spec
    task = example_spec()
    return seal_versioned("worker-packet", {
        "packet_id": str(uuid.uuid4()), "run_id": str(uuid.uuid4()), "attempt_id": str(uuid.uuid4()),
        "spec_digest": "2" * 64, "goal": task["goal"], "non_goals": task["non_goals"],
        "scope": task["scope"], "checks": task["checks"], "bindings": {
            "base_commit": "a" * 40, "initial_head": "a" * 40, "initial_content_digest": "b" * 64,
            "workspace_id": str(uuid.uuid4()), "lease_generation": 1,
            "driver_config_digest": "a" * 64, "provider_profile_digest": "b" * 64},
        "remaining_budget": task["budget"], "qualification": "synthetic", "extensions": {},
        "result_schema_id": "urn:taskalong:schema:v2.5:worker-result",
        "binding_digest": "4" * 64, "admission_digest": "3" * 64,
        "projection": "cursor-print-fixture/1", "session_policy": "fresh", "allowed_tools": ["Edit"],
    }, version="2.5")


def cursor_worker(packet):
    return {"kind": "worker_result", "schema_version": "2.5", "extensions": {},
        "result_id": str(uuid.uuid4()), "packet_id": packet["packet_id"], "packet_digest": packet["digest"],
        "run_id": packet["run_id"], "attempt_id": packet["attempt_id"], "spec_digest": packet["spec_digest"],
        "driver_config_digest": packet["bindings"]["driver_config_digest"],
        "provider_profile_digest": packet["bindings"]["provider_profile_digest"],
        "status": "completed", "changed_files": [], "command_claims": [], "summary": "Synthetic Cursor result.",
        "blockers": [], "deviations": [], "residual_risks": [], "qualification": "synthetic"}


class CursorContractTests(unittest.TestCase):
    def test_explicit_cursor_family_preserves_old_resources_and_closed_config(self):
        self.assertEqual(schema_names(version="2.5"),
            ("driver-config", "task-spec", "worker-packet", "packet-projection", "worker-result"))
        for name in schema_names(version="2.5"):
            with self.subTest(resource=name):
                value = schema(name, version="2.5")
                self.assertEqual(value["$id"], "urn:taskalong:schema:v2.5:" + name)
                Draft202012Validator.check_schema(value)
        from taskalong.executors.config import CursorDriverConfig, DriverConfig, read_driver_config
        value = seal_versioned("driver-config", example_cursor_config(), version="2.5")
        document = read_driver_config(value)
        self.assertIsInstance(document, CursorDriverConfig)
        before = document.to_bytes()
        value["launch"]["session_policy"] = "latest"
        self.assertEqual(document.to_bytes(), before)
        with self.assertRaises(FrozenInstanceError):
            document._canonical = b"{}"
        with self.assertRaises(TaskAlongError):
            DriverConfig.from_dict(document.to_dict())
        with self.assertRaises(TaskAlongError) as failure:
            seal_versioned("driver-config", example_cursor_config() | {
                "launch": example_cursor_config()["launch"] | {"extra_args": ["--force"]}}, version="2.5")
        self.assertEqual(failure.exception.code, "schema_validation")
        prior = json.loads((Path(__file__).parent / "fixtures/m6-contract-hashes.json").read_text())
        self.assertEqual(len(prior), 42)
        for path, expected in prior.items():
            resource = path.removeprefix("src/taskalong/resources/")
            self.assertEqual(hashlib.sha256(resources.files("taskalong.resources").joinpath(resource).read_bytes()).hexdigest(), expected)


class CursorProtocolTests(unittest.TestCase):
    def setUp(self):
        self.packet = cursor_packet()
        self.worker = cursor_worker(self.packet)
        self.session = str(uuid.uuid4())
        self.model = "taskalong-fixture-cursor-model"
        self.init = {"type": "system", "subtype": "init", "session_id": self.session, "model": self.model}
        self.terminal = {"type": "result", "subtype": "success", "is_error": False,
                         "session_id": self.session, "result": " \n" + json.dumps(self.worker) + "\t"}

    def wire(self, *events):
        return b"".join((json.dumps(event, ensure_ascii=False) + "\n").encode() for event in events)

    def decoder(self, **limits):
        from taskalong.executors.cursor_protocol import CursorStreamDecoder
        return CursorStreamDecoder(self.packet, expected_model=self.model, **limits)

    def expect_wire_failure(self, events, code=None, *, exit_code=0, **limits):
        decoder = self.decoder(**limits)
        with self.assertRaises(TaskAlongError) as failure:
            decoder.feed(self.wire(*events))
            decoder.finish(exit_code=exit_code)
        if code is not None:
            self.assertEqual(failure.exception.code, code)
        self.assertEqual(failure.exception.effect_outcome, "uncertain")

    def test_fresh_session_is_observed_separately_from_untouched_worker_result(self):
        from taskalong.executors.cursor_protocol import CursorStreamDecoder
        decoder = CursorStreamDecoder(self.packet, expected_model=self.model)
        raw = self.wire(self.init, self.terminal)
        self.packet["digest"] = "f" * 64
        for offset in range(0, len(raw), 7):
            decoder.feed(raw[offset:offset + 7])
        turn = decoder.finish(exit_code=0)
        self.assertEqual(loads(turn.worker_result_json), self.worker)
        self.assertNotIn("session_id", loads(turn.worker_result_json))
        self.assertNotIn(self.session, turn.worker_result_json.decode())
        self.assertEqual((turn.session_id, turn.reported_model), (self.session, self.model))
        self.assertNotEqual(turn.session_id, self.worker["attempt_id"])
        self.assertEqual((turn.wire_sha256, turn.wire_bytes, turn.frames), (hashlib.sha256(raw).hexdigest(), len(raw), 2))
        with self.assertRaises(FrozenInstanceError):
            turn.session_id = self.worker["attempt_id"]
        for forbidden in ("acceptance", "termination_confirmed", "resolved_model_digest", "qualified"):
            self.assertFalse(hasattr(turn, forbidden))

    def test_only_balanced_scoped_edit_calls_and_terminal_result_can_complete(self):
        assistant = {"type": "assistant", "session_id": self.session, "message": {
            "model": self.model, "content": [{"type": "text", "text": json.dumps(
                self.worker | {"packet_digest": "f" * 64})}]}}
        started = {"type": "tool_call", "subtype": "started", "session_id": self.session,
                   "call_id": "edit-1", "tool": "Edit", "path": "arithmetic.py"}
        completed = started | {"subtype": "completed", "is_error": False}
        decoder = self.decoder()
        decoder.feed(self.wire(self.init, assistant, started, completed, self.terminal))
        turn = decoder.finish(exit_code=0)
        self.assertEqual(loads(turn.worker_result_json), self.worker)
        self.assertEqual(turn.frames, 5)
        incomplete = self.decoder()
        incomplete.feed(self.wire(self.init, assistant))
        with self.assertRaises(TaskAlongError) as failure:
            incomplete.finish(exit_code=0)
        self.assertEqual(failure.exception.code, "cursor_stream_incomplete")
        self.assertEqual(failure.exception.effect_outcome, "uncertain")

    def test_unknown_nested_types_are_typed_refusals(self):
        tool = {"type": "tool_call", "subtype": "started", "session_id": self.session,
                "call_id": "edit-1", "tool": "Edit", "path": "arithmetic.py"}
        invalid = [
            {"type": value, "session_id": self.session} for value in ([], {})
        ] + [tool | {"subtype": value} for value in ([], {})]
        invalid += [tool | {"path": {}}, tool | {"call_id": []}, tool | {"tool": []},
            {"type": "assistant", "session_id": self.session, "message": []},
            {"type": "user", "session_id": self.session, "message": {"content": [{}]}},
            self.terminal | {"result": []}, self.terminal | {"is_error": []}]
        for event in invalid:
            with self.subTest(event=event):
                self.expect_wire_failure([self.init, event, self.terminal])

    def test_terminal_requires_one_whole_worker_document_without_repairs(self):
        valid = json.dumps(self.worker)
        for text in ("answer: " + valid, "```json\n" + valid + "\n```", valid + valid,
                     "[]", "null", "", '{"status":"completed"}', valid[:-1]):
            with self.subTest(text=text[:30]):
                self.expect_wire_failure([self.init, self.terminal | {"result": text}], "cursor_result_invalid")
        for key in self.worker:
            missing = {k: value for k, value in self.worker.items() if k != key}
            with self.subTest(missing=key):
                self.expect_wire_failure([self.init, self.terminal | {"result": json.dumps(missing)}], "cursor_result_invalid")
        self.expect_wire_failure([self.init, self.terminal | {
            "result": json.dumps(self.worker | {"session_id": self.session})}], "cursor_result_invalid")
        duplicate = '{"packet_id":' + json.dumps(self.worker["packet_id"]) + ',' + valid[1:]
        self.expect_wire_failure([self.init, self.terminal | {"result": duplicate}], "cursor_result_invalid")
        deep = 0
        for _ in range(33):
            deep = [deep]
        self.expect_wire_failure([self.init, self.terminal | {
            "result": json.dumps(self.worker | {"extensions": {"fixture:deep": deep}})}], "cursor_result_invalid")
        for value in (True, 0, None, "false"):
            with self.subTest(error=value):
                self.expect_wire_failure([self.init, self.terminal | {"is_error": value}], "cursor_result_failed")
        self.expect_wire_failure([self.init, self.terminal | {"subtype": "permission_denied"}], "cursor_result_failed")
        self.expect_wire_failure([self.init, self.terminal], "cursor_exit_failed", exit_code=1)

    def test_session_model_and_every_core_result_binding_are_exact(self):
        self.expect_wire_failure([self.terminal], "cursor_init_required")
        self.expect_wire_failure([self.init, self.init, self.terminal], "cursor_duplicate_init")
        self.expect_wire_failure([self.init | {"session_id": "not-a-uuid"}], "cursor_session_invalid")
        for key in ("run_id", "attempt_id", "packet_id"):
            self.expect_wire_failure([self.init | {"session_id": self.packet[key]}], "cursor_session_conflict")
        self.expect_wire_failure([self.init | {"model": "different-model"}], "cursor_model_mismatch")
        self.expect_wire_failure([self.init, self.terminal | {"session_id": str(uuid.uuid4())}], "cursor_session_mismatch")
        self.expect_wire_failure([self.init, self.terminal, self.terminal], "cursor_event_after_terminal")
        for key in ("packet_id", "run_id", "attempt_id", "spec_digest", "packet_digest",
                    "driver_config_digest", "provider_profile_digest"):
            replacement = str(uuid.uuid4()) if key.endswith("_id") else "f" * 64
            with self.subTest(binding=key):
                self.expect_wire_failure([self.init, self.terminal | {
                    "result": json.dumps(self.worker | {key: replacement})}], "cursor_result_binding_mismatch")
        for change in ({"status": "blocked"}, {"blockers": ["permission denied"]}, {"deviations": ["wrong scope"]}):
            self.expect_wire_failure([self.init, self.terminal | {
                "result": json.dumps(self.worker | change)}], "cursor_result_failed")

    def test_edit_order_scope_and_denial_cannot_be_hidden_by_exit_zero(self):
        started = {"type": "tool_call", "subtype": "started", "session_id": self.session,
                   "call_id": "edit-1", "tool": "Edit", "path": "arithmetic.py"}
        completed = started | {"subtype": "completed", "is_error": False}
        self.expect_wire_failure([self.init, started, self.terminal], "cursor_tool_pending")
        self.expect_wire_failure([self.init, completed, self.terminal], "cursor_tool_order_invalid")
        self.expect_wire_failure([self.init, started, started, completed, self.terminal], "cursor_tool_duplicate")
        self.expect_wire_failure([self.init, started, completed, completed, self.terminal], "cursor_tool_order_invalid")
        self.expect_wire_failure([self.init, started, completed, started, completed, self.terminal], "cursor_tool_duplicate")
        self.expect_wire_failure([self.init, started | {"path": "../escape.py"}], "cursor_tool_scope_mismatch")
        for tool in ("Bash", "WebFetch", "Agent", "Read"):
            with self.subTest(tool=tool):
                self.expect_wire_failure([self.init, started | {"tool": tool}], "cursor_tool_unsupported")
        for error in (True, 0, None, "false"):
            with self.subTest(error=error):
                self.expect_wire_failure([self.init, started, completed | {"is_error": error}, self.terminal], "cursor_tool_failed")
        self.expect_wire_failure([self.init, started, completed | {"call_id": "other"}], "cursor_tool_order_invalid")
        self.expect_wire_failure([self.init, started, completed | {"session_id": str(uuid.uuid4())}], "cursor_session_mismatch")
        self.packet = seal_versioned("worker-packet", self.packet | {
            "scope": {"files": ["arithmetic.py", "second.py"], "operations": ["modify"]}}, version="2.5")
        terminal = self.terminal | {"result": json.dumps(cursor_worker(self.packet))}
        self.expect_wire_failure([self.init, started, completed | {"path": "second.py"}, terminal], "cursor_tool_mismatch")

    def test_strict_raw_frames_limits_and_eof_remain_failures(self):
        raw = self.wire(self.init, self.terminal)
        duplicate_init = b'{"type":"system",' + json.dumps(self.init)[1:].encode() + b'\n'
        malformed = [duplicate_init, b'[]\n', b'{"x":NaN}\n',
                     b'{"x":1.5}\n', b'{"x":9007199254740992}\n', b'{"x":"\xff"}\n',
                     b'{"x":' + b'[' * 33 + b'0' + b']' * 33 + b'}\n']
        for content in malformed:
            with self.subTest(raw=content[:40]):
                decoder = self.decoder()
                with self.assertRaises(TaskAlongError) as failure:
                    decoder.feed(content)
                self.assertEqual(failure.exception.code, "cursor_frame_invalid")
                self.assertEqual(failure.exception.effect_outcome, "uncertain")
        decoder = self.decoder()
        decoder.feed(raw[:-1])
        with self.assertRaises(TaskAlongError) as failure:
            decoder.finish(exit_code=0)
        self.assertEqual(failure.exception.code, "cursor_truncated_frame")
        self.expect_wire_failure([self.init, self.terminal], "cursor_output_limit", max_output_bytes=len(raw) - 1)
        self.expect_wire_failure([self.init], "cursor_line_limit", max_line_bytes=8)
        self.expect_wire_failure([self.init, self.terminal], "cursor_frame_limit", max_frames=1)

    def test_invalid_limits_and_sticky_errors_cannot_create_a_repaired_turn(self):
        for limits in ({"max_output_bytes": True}, {"max_output_bytes": 0},
                       {"max_line_bytes": 0}, {"max_line_bytes": 2 * 1024 * 1024},
                       {"max_frames": False}, {"max_frames": 4097}):
            with self.subTest(limits=limits), self.assertRaises(TaskAlongError) as failure:
                self.decoder(**limits)
            self.assertEqual(failure.exception.code, "cursor_decoder_limits_invalid")
        decoder = self.decoder()
        with self.assertRaises(TaskAlongError) as original:
            decoder.feed(self.wire(self.init, self.terminal | {"is_error": True}))
        with self.assertRaises(TaskAlongError) as subsequent:
            decoder.feed(self.wire(self.terminal))
        self.assertIs(original.exception, subsequent.exception)
        with self.assertRaises(TaskAlongError) as eof:
            decoder.finish(exit_code=0)
        self.assertIs(original.exception, eof.exception)


if __name__ == "__main__":
    unittest.main()
