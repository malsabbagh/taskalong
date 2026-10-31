"""Original offline examples of native event envelopes, not runtime proof."""
import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
import unittest

from taskalong.errors import TaskAlongError
from taskalong.executors.antigravity_native_protocol import NativeAntigravityDecoder


class NativeAntigravityProtocolTests(unittest.TestCase):
    def setUp(self):
        self.session = "b643e889-7a21-4d5a-8f71-aa1760db5196"
        self.schema = {"type": "object", "additionalProperties": False,
                       "properties": {"answer": {"type": "integer"}}, "required": ["answer"]}
        self.init = {"event": "init", "conversation_id": self.session, "init": {
            "cwd": "/synthetic/workspace", "model": "synthetic-native-model", "tools": ["write_to_file", "run_command"],
            "permission_mode": "request-review", "json_schema": self.schema}}
        self.result = {"event": "result", "result": {
            "conversation_id": self.session, "status": "SUCCESS", "num_turns": 1, "response": "private-response",
            "duration_seconds": 6.88, "structured_output": {"answer": 42}, "json_schema": self.schema,
            "usage": {"input_tokens": 100, "output_tokens": 9, "thinking_tokens": 4,
                      "cache_read_tokens": 32, "total_tokens": 109}}}

    def decoder(self, **changes):
        return NativeAntigravityDecoder(**({"expected_model": "synthetic-native-model", "expected_cwd": "/synthetic/workspace",
                                           "result_schema": self.schema} | changes))

    def wire(self, *events):
        return b"".join((json.dumps(event, ensure_ascii=False) + "\n").encode() for event in events)

    def step(self, index=3, state="DONE", kind="tool", **changes):
        data = {"conversation_id": self.session, "step_index": index, "state": state, "step_type": kind}
        if kind == "tool":
            data.update(tool_name="write_to_file", duration_seconds=0.07, tool_info={
                "name": "write_to_file", "parameters": {"path": "result.txt"}, "output": "private-output"})
        return {"event": "step_update", "step_update": data | changes}

    def failure(self, *events, code=None):
        decoder = self.decoder()
        with self.assertRaises(TaskAlongError) as failure:
            decoder.feed(self.wire(*events))
            decoder.finish(exit_code=0)
        if code:
            self.assertEqual(failure.exception.code, code)
        self.assertEqual(failure.exception.effect_outcome, "uncertain")
        return failure.exception

    def test_fragmented_native_stream_preserves_identity_decimal_metadata_and_cumulative_usage(self):
        decoder = self.decoder()
        self.assertIsNone(decoder.conversation_id)
        decoder.feed(self.wire(self.init))
        self.assertEqual(decoder.conversation_id, self.session)
        events = [self.step(index=0, kind="user_input"), self.step(index=3, kind="agent_response", state="ACTIVE", text_delta="a"),
                  self.step(index=3, kind="agent_response", state="DONE", text_delta="b", usage={"input_tokens": 999}),
                  self.step(index=8), self.step(index=11, kind="checkpoint", duration_seconds=0.53), self.result]
        rest = self.wire(*events)
        for offset in range(0, len(rest), 7):
            decoder.feed(rest[offset:offset + 7])
        turn = decoder.finish(exit_code=0)
        self.assertTrue(turn.successful)
        self.assertEqual(turn.conversation_id, self.session)
        self.assertEqual(json.loads(turn.structured_output_json), {"answer": 42})
        self.assertEqual(json.loads(turn.reported_usage_json)["input_tokens"], 100)
        self.assertEqual(turn.stdout_sha256, hashlib.sha256(self.wire(self.init) + rest).hexdigest())
        self.assertEqual(turn.frame_count, 7)
        self.assertEqual(turn.observation()["usage_scope"], "provider_reported_cumulative_session_snapshot")
        self.assertIsNone(turn.observation()["effective_effort"])
        self.assertNotIn("private-response", json.dumps(turn.observation()))
        self.assertNotIn("private-output", json.dumps(turn.observation()))
        self.assertIs(decoder.finish(exit_code=0), turn)
        with self.assertRaises(FrozenInstanceError):
            turn.successful = False

    def test_missing_identity_configuration_drift_and_implicit_permission_bypass_are_rejected(self):
        self.failure(self.result, code="agy_native_init_required")
        self.failure(self.init, self.init, code="agy_native_duplicate_init")
        for change in ({"cwd": "/other"}, {"model": "other"}, {"permission_mode": "always-proceed"},
                       {"json_schema": {}}, {"agent": []}, {"unknown": True}, {"tools": ["run_command", "run_command"]},
                       {"tools": [["invalid"]]}):
            with self.subTest(change=change):
                self.failure(self.init | {"init": self.init["init"] | change}, self.result)
        missing = copy.deepcopy(self.init)
        del missing["init"]["model"]
        self.failure(missing, self.result)

    def test_tool_error_or_permission_denial_cannot_be_erased_by_success(self):
        for change in ({"error": {"type": "permission_denied", "message": "private-denial"}}, {"permission_denied": True}):
            event = self.step()
            event["step_update"]["tool_info"].update(change)
            decoder = self.decoder()
            decoder.feed(self.wire(self.init, event, self.result))
            turn = decoder.finish(exit_code=0)
            self.assertFalse(turn.successful)
            self.assertEqual(turn.error_code, "agy_native_tool_failed")
            self.assertNotIn("private-denial", json.dumps(turn.observation()))
        event = self.step()
        event["step_update"]["tool_info"]["permission_denied"] = 1
        self.failure(self.init, event, self.result, code="agy_native_tool_invalid")

    def test_terminal_success_cannot_override_exit_failure_or_unknown_diagnostics(self):
        for options, code in (({"exit_code": 1}, "agy_native_exit_failed"),
                              ({"exit_code": 0, "stderr": b"a soft-denied tool"}, "agy_native_diagnostics_unqualified")):
            decoder = self.decoder()
            decoder.feed(self.wire(self.init, self.result))
            turn = decoder.finish(**options)
            self.assertFalse(turn.successful)
            self.assertEqual(turn.error_code, code)

    def test_all_documented_nonsuccess_statuses_retain_observed_identity_without_success(self):
        for status in ("ERROR", "CANCELED", "INTERRUPTED", "INVALID", "WAITING", "RUNNING"):
            result = {"event": "result", "result": {"conversation_id": self.session, "status": status,
                      "num_turns": 0, "response": "", "error": "private-provider-error", "duration_seconds": 0}}
            decoder = self.decoder()
            decoder.feed(self.wire(self.init, result))
            turn = decoder.finish(exit_code=1)
            self.assertFalse(turn.successful)
            self.assertEqual(turn.provider_status, status)
            self.assertEqual(turn.conversation_id, self.session)
            self.assertIsNone(turn.structured_output_json)
            self.assertTrue(all(count is None for count in json.loads(turn.reported_usage_json).values()))
            self.assertNotIn("private-provider-error", json.dumps(turn.observation()))

    def test_result_requires_exact_session_single_turn_schema_and_whole_structured_output(self):
        for change in ({"conversation_id": "different"}, {"num_turns": True}, {"num_turns": 2}, {"num_turns": 0},
                       {"json_schema": {}}, {"structured_output": {"answer": "42"}}, {"structured_output": {"extra": 42}},
                       {"status": "NEW_STATUS"}, {"error": "error despite success"}, {"response": []}):
            with self.subTest(change=change):
                self.failure(self.init, self.result | {"result": self.result["result"] | change})
        missing = copy.deepcopy(self.result)
        del missing["result"]["structured_output"]
        missing["result"]["response"] = '{"answer":42}'
        self.failure(self.init, missing, code="agy_native_result_inconsistent")
        wrong_type_schema = copy.deepcopy(self.result)
        wrong_type_schema["result"]["json_schema"] = {"const": True}
        self.failure(self.init, wrong_type_schema, code="agy_native_schema_mismatch")

    def test_step_transitions_extra_turns_and_subagents_require_explicit_new_contract(self):
        for events in ([self.step(), self.step()], [self.step(), self.step(state="ACTIVE")],
                       [self.step(state="ACTIVE")], [self.step(state="ACTIVE"), self.step(kind="checkpoint")],
                       [self.step(index=0, kind="user_input"), self.step(index=1, kind="user_input")],
                       [self.step(kind="checkpoint", subagent_info={"subagents": []})],
                       [self.step(kind="new-category")], [self.step(index=True)]):
            with self.subTest(events=events):
                self.failure(self.init, *events, self.result)
        active, done = self.step(state="ACTIVE"), self.step()
        done["step_update"]["tool_info"]["parameters"]["path"] = "other.txt"
        self.failure(self.init, active, done, self.result, code="agy_native_step_transition_invalid")
        decoder = self.decoder()
        decoder.feed(self.wire(self.init, self.step(state="ACTIVE"), self.step(), self.result))
        self.assertTrue(decoder.finish(exit_code=0).successful)

    def test_nonfinite_bool_and_negative_duration_or_usage_are_refused(self):
        for value in (True, -1, "0.2", float("nan"), float("inf")):
            with self.subTest(value=value):
                self.failure(self.init, self.result | {"result": self.result["result"] | {"duration_seconds": value}})
        for usage in ({"input_tokens": True}, {"total_tokens": -1}, {"cost_usd": 0}, {"input_tokens": None},
                      {"input_tokens": 0.1}, {"input_tokens": 2**53}):
            with self.subTest(usage=usage):
                self.failure(self.init, self.result | {"result": self.result["result"] | {"usage": usage}})
        decoder = self.decoder()
        result = copy.deepcopy(self.result)
        result["result"].pop("usage")
        decoder.feed(self.wire(self.init, self.step(kind="checkpoint", usage={"input_tokens": 999}), result))
        self.assertTrue(all(value is None for value in json.loads(decoder.finish(exit_code=0).reported_usage_json).values()))

    def test_malformed_wire_failure_is_sticky_and_does_not_expose_native_content(self):
        for raw in (b'{"event":"init","event":"result"}\n', b'[]\n', b'\xff\n',
                    b'{"event":"unknown","secret":"private-canary"}\n', b'{}\n',
                    b'{"event":"init","conversation_id":"\\ud800","init":{}}\n'):
            decoder = self.decoder()
            with self.assertRaises(TaskAlongError) as first:
                decoder.feed(raw)
            with self.assertRaises(TaskAlongError) as second:
                decoder.feed(self.wire(self.init, self.result))
            self.assertIs(first.exception, second.exception)
            with self.assertRaises(TaskAlongError) as third:
                decoder.finish(exit_code=0)
            self.assertIs(first.exception, third.exception)
            self.assertNotIn("private-canary", str(first.exception))
        self.failure(self.init, {"event": "future-event"}, self.result, code="agy_native_event_unsupported")

    def test_output_line_frame_and_depth_limits_cannot_turn_truncation_into_success(self):
        raw = self.wire(self.init, self.result)
        for options in ({"max_output_bytes": len(raw) - 1}, {"max_line_bytes": 20}, {"max_frames": 1}):
            decoder = self.decoder(**options)
            with self.assertRaises(TaskAlongError):
                decoder.feed(raw)
                decoder.finish(exit_code=0)
        decoder = self.decoder()
        decoder.feed(raw[:-1])
        with self.assertRaises(TaskAlongError) as failure:
            decoder.finish(exit_code=0)
        self.assertEqual(failure.exception.code, "agy_native_truncated_frame")
        decoder = self.decoder(max_output_bytes=len(raw))
        decoder.feed(raw)
        with self.assertRaises(TaskAlongError):
            decoder.finish(exit_code=0, stderr=b"x")
        deep = value = {}
        for _ in range(34):
            value["nested"] = {}
            value = value["nested"]
        self.failure(deep, code="agy_native_frame_invalid")
        self.failure(self.init, self.result, self.result, code="agy_native_event_after_terminal")

    def test_unresolved_local_schema_references_are_a_safe_failure(self):
        schema = {"$ref": "#/$defs/missing"}
        decoder = self.decoder(result_schema=schema)
        init = copy.deepcopy(self.init)
        init["init"]["json_schema"] = schema
        result = copy.deepcopy(self.result)
        result["result"]["json_schema"] = schema
        with self.assertRaises(TaskAlongError) as failure:
            decoder.feed(self.wire(init, result))
        self.assertEqual(failure.exception.code, "agy_native_structured_output_invalid")

    def test_decoder_configuration_and_eof_state_are_explicit(self):
        for options in ({"max_output_bytes": True}, {"max_line_bytes": 0}, {"max_frames": 0},
                        {"expected_model": None}, {"expected_cwd": ""}):
            with self.assertRaises(TaskAlongError) as failure:
                self.decoder(**options)
            self.assertEqual(failure.exception.effect_outcome, "not_sent")
        self.failure(self.init, code="agy_native_stream_incomplete")
        decoder = self.decoder()
        decoder.feed(self.wire(self.init, self.result))
        decoder.finish(exit_code=0)
        with self.assertRaises(TaskAlongError) as failure:
            decoder.finish(exit_code=1)
        self.assertEqual(failure.exception.code, "agy_native_finish_conflict")
        decoder = self.decoder()
        decoder.feed(self.wire(self.init, self.result))
        decoder.finish(exit_code=0)
        with self.assertRaises(TaskAlongError) as failure:
            decoder.feed(b"\n")
        self.assertEqual(failure.exception.code, "agy_native_decoder_closed")


if __name__ == "__main__":
    unittest.main()
