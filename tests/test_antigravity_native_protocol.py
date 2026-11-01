"""Original offline examples of native event envelopes, not runtime proof."""
import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
import unittest

from taskalong.errors import TaskAlongError
from taskalong.executors.antigravity_native_protocol import NativeAntigravityDecoder


class NativeAntigravityProtocolTests(unittest.TestCase):
    def finish_steps(self):
        """Original minimal examples of the observed native 1.4.12 transition."""
        init = self.init | {"init": self.init["init"] | {"tools": ["write_to_file", "finish"]}}
        active = self.step(index=7, state="ACTIVE", tool_name="finish", tool_info={
            "name": "finish", "parameters": {"answer": 42}})
        done = self.step(index=7, kind="finish", duration_seconds=0.01)
        return init, active, done

    def test_native_finish_completion_requires_the_separate_structured_result(self):
        init, active, done = self.finish_steps()
        for extended in (False, True):
            with self.subTest(extended_wire=extended):
                decoder = self.decoder(extended_wire=extended)
                raw = self.wire(init, active, done, self.result)
                for offset in range(0, len(raw), 13):
                    decoder.feed(raw[offset:offset + 13])
                turn = decoder.finish(exit_code=0)
                self.assertTrue(turn.successful)
                self.assertEqual(json.loads(turn.structured_output_json), {"answer": 42})
                self.assertEqual(json.loads(turn.reported_usage_json)["input_tokens"], 100)
                self.assertEqual(turn.stdout_sha256, hashlib.sha256(raw).hexdigest())
                self.assertIsNone(turn.observation()["effective_effort"])
                self.assertFalse(turn.observation()["production_dispatch_allowed"])

    def test_native_finish_completion_cannot_close_an_unrelated_or_unobserved_step(self):
        init, active, done = self.finish_steps()
        no_parameters = copy.deepcopy(active)
        no_parameters["step_update"].pop("tool_info")
        for events in ([done], [self.step(index=7, state="ACTIVE"), done],
                       [self.step(index=7, kind="checkpoint"), done], [no_parameters, done],
                       [active, self.step(index=8, kind="finish")],
                       [active, self.step(index=7, kind="finish", state="ACTIVE")],
                       [active, self.step(index=7, kind="finish", tool_name="finish")],
                       [active, self.step(index=7, kind="finish", tool_info={})],
                       [active, self.step(index=7, kind="finish", conversation_id="different")]):
            with self.subTest(events=events):
                self.failure(init, *events, self.result)

    def test_native_finish_duplicate_and_conflicting_completions_fail_stickily(self):
        init, active, done = self.finish_steps()
        other_result = self.result | {"result": self.result["result"] | {"status": "ERROR", "response": ""}}
        for events, code in (([active, done, done], "agy_native_step_transition_invalid"),
                             ([active, done, active], "agy_native_step_transition_invalid"),
                             ([active, done, self.result, self.result], "agy_native_event_after_terminal"),
                             ([active, done, self.result, other_result], "agy_native_event_after_terminal"),
                             ([active, done, self.result, done], "agy_native_event_after_terminal")):
            with self.subTest(code=code, events=events):
                decoder = self.decoder()
                with self.assertRaises(TaskAlongError) as first:
                    decoder.feed(self.wire(init, *events))
                self.assertEqual(first.exception.code, code)
                with self.assertRaises(TaskAlongError) as second:
                    decoder.finish(exit_code=0)
                self.assertIs(first.exception, second.exception)
                self.assertEqual(first.exception.effect_outcome, "uncertain")

    def test_native_finish_incomplete_or_invalid_endings_never_supply_a_result(self):
        init, active, done = self.finish_steps()
        for events in ([init, active], [init, active, done]):
            with self.subTest(events=events):
                self.failure(*events, code="agy_native_stream_incomplete")
        self.failure(init, active, self.result, code="agy_native_step_pending")
        missing = copy.deepcopy(self.result)
        missing["result"].pop("structured_output")
        self.failure(init, active, done, missing, code="agy_native_result_inconsistent")
        invalid = self.result | {"result": self.result["result"] | {"structured_output": {"answer": "wrong"}}}
        self.failure(init, active, done, invalid, code="agy_native_structured_output_invalid")
        decoder = self.decoder()
        decoder.feed(self.wire(init, active, done, self.result)[:-1])
        with self.assertRaises(TaskAlongError) as caught:
            decoder.finish(exit_code=0)
        self.assertEqual(caught.exception.code, "agy_native_truncated_frame")

    def test_native_finish_cannot_erase_denials_exit_failure_or_diagnostics(self):
        init, active, done = self.finish_steps()
        for change in ({"permission_denied": True}, {"error": {"type": "denied", "message": "private"}}):
            denied = copy.deepcopy(active)
            denied["step_update"]["tool_info"].update(change)
            decoder = self.decoder()
            decoder.feed(self.wire(init, denied, done, self.result))
            turn = decoder.finish(exit_code=0)
            self.assertFalse(turn.successful)
            self.assertEqual(turn.error_code, "agy_native_tool_failed")
        for options, code in (({"exit_code": 1}, "agy_native_exit_failed"),
                              ({"exit_code": 0, "stderr": b"unclassified"}, "agy_native_diagnostics_unqualified")):
            decoder = self.decoder()
            decoder.feed(self.wire(init, active, done, self.result))
            turn = decoder.finish(**options)
            self.assertFalse(turn.successful)
            self.assertEqual(turn.error_code, code)

    def test_native_finish_completion_preserves_extended_parameter_accounting(self):
        init, active, done = self.finish_steps()
        active["step_update"]["tool_info"]["parameters"] = {
            "p": "x" * (1048576 - len(json.dumps({"p": ""}, separators=(",", ":")).encode()))}
        decoder = self.decoder(extended_wire=True)
        decoder.feed(self.wire(init, active, done))
        with self.assertRaises(TaskAlongError) as caught:
            decoder.feed(self.wire(self.step(index=8, state="ACTIVE")))
        self.assertEqual(caught.exception.code, "agy_native_metadata_limit")

    def test_extended_frames_have_total_node_container_depth_and_unicode_bounds(self):
        values = ([[0] * 4096 for _ in range(17)], [0] * 4097, {str(i): 0 for i in range(4097)}, "\ud800")
        nested = 0
        for _ in range(40):
            nested = [nested]
        for value in (*values, nested):
            d = self.decoder(extended_wire=True)
            event = copy.deepcopy(self.init)
            event["init"]["oversized_unknown"] = value
            raw = (json.dumps(event, ensure_ascii=True) + "\n").encode()
            with self.subTest(value_type=type(value)), self.assertRaises(TaskAlongError) as caught:
                d.feed(raw)
            self.assertEqual(caught.exception.code, "agy_native_frame_invalid")

    def test_extended_steps_and_retained_parameters_are_bounded_without_delta_accumulation(self):
        d = self.decoder(extended_wire=True)
        d.feed(self.wire(self.init))
        event = self.step(index=0, kind="agent_response", state="ACTIVE", text_delta="discarded")
        for _ in range(1000):
            d.feed(self.wire(event))
        self.assertEqual((len(d._steps), d._parameter_bytes), (1, 0))
        for index in range(1, 256):
            d.feed(self.wire(self.step(index=index, kind="checkpoint")))
        with self.assertRaises(TaskAlongError) as caught:
            d.feed(self.wire(self.step(index=256, kind="checkpoint")))
        self.assertEqual(caught.exception.code, "agy_native_step_limit")
        legacy = self.decoder()
        legacy.feed(self.wire(self.init))
        for index in range(257):
            legacy.feed(self.wire(self.step(index=index, kind="checkpoint")))
        legacy.feed(self.wire(self.result))
        self.assertTrue(legacy.finish(exit_code=0).successful)
        d = self.decoder(extended_wire=True)
        d.feed(self.wire(self.init))
        parameters = {"p": "x" * (1048576 - len(json.dumps({"p": ""}, separators=(",", ":")).encode()))}
        event = self.step(index=0, state="ACTIVE", tool_info={"name": "write_to_file", "parameters": parameters})
        for _ in range(2):
            d.feed(self.wire(event))
        self.assertEqual(d._parameter_bytes, 1048576)
        with self.assertRaises(TaskAlongError) as caught:
            d.feed(self.wire(self.step(index=1, state="ACTIVE", tool_info={"name": "write_to_file", "parameters": {}})))
        self.assertEqual(caught.exception.code, "agy_native_metadata_limit")

    def test_extended_stderr_metadata_preserves_legacy_signature_failure_and_combined_bound(self):
        stderr = b"synthetic diagnostic\n"
        metadata = {"bytes": len(stderr), "sha256": hashlib.sha256(stderr).hexdigest()}
        old = self.decoder()
        old.feed(self.wire(self.init, self.result))
        expected = old.finish(exit_code=0, stderr=stderr)
        new = self.decoder(extended_wire=True)
        new.feed(self.wire(self.init, self.result))
        self.assertEqual(new.finish(exit_code=0, stderr_metadata=metadata), expected)
        self.assertEqual(new.finish(exit_code=0, stderr=stderr), expected)
        with self.assertRaises(TaskAlongError):
            new.finish(exit_code=0, stderr_metadata=metadata | {"sha256": "0" * 64})
        raw = self.wire(self.init, self.result)
        bounded = self.decoder(extended_wire=True, max_output_bytes=len(raw))
        bounded.feed(raw)
        with self.assertRaises(TaskAlongError) as caught:
            bounded.finish(exit_code=0, stderr_metadata=metadata)
        self.assertEqual(caught.exception.code, "agy_native_output_limit")
        for bad in ({"bytes": True, "sha256": "a" * 64}, {"bytes": 0, "sha256": "a" * 64},
                    {"bytes": 1, "sha256": "bad"}, metadata | {"extra": 1}):
            d = self.decoder(extended_wire=True)
            with self.assertRaises(TaskAlongError):
                d.finish(exit_code=0, stderr_metadata=bad)

    def test_result_limit_is_explicit_and_does_not_change_legacy_native_default(self):
        schema = {"type": "object"}
        init = self.init | {"init": self.init["init"] | {"json_schema": schema}}
        result = self.result | {"result": self.result["result"] | {
            "structured_output": {"text": "x" * 70000}, "json_schema": schema}}
        legacy = self.decoder(result_schema=schema)
        legacy.feed(self.wire(init, result))
        self.assertTrue(legacy.finish(exit_code=0).successful)
        extended = self.decoder(result_schema=schema, max_result_bytes=65536)
        with self.assertRaises(TaskAlongError) as caught:
            extended.feed(self.wire(init, result))
        self.assertEqual(caught.exception.code, "agy_native_result_limit")
        for bound in (True, 0, 1048577):
            with self.assertRaises(TaskAlongError):
                self.decoder(max_result_bytes=bound)

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
