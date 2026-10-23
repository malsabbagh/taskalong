"""Original synthetic frames, not captured or qualified CLI transcripts."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
import uuid

from taskalong.executors.claude_protocol import ClaudeStreamDecoder
from taskalong.errors import TaskAlongError
from taskalong.validation import loads
from test_codex_cli import fixture_packet, fixture_profile


class ClaudeProtocolTests(unittest.TestCase):
    def setUp(self):
        self.packet = fixture_packet(fixture_profile(Path("/usr/bin/true")))
        self.session = str(uuid.uuid4())
        self.model = "synthetic-exact-model"
        self.worker = {"kind": "worker_result", "schema_version": "1.0", "extensions": {},
            "result_id": str(uuid.uuid4()), "packet_id": self.packet["packet_id"],
            "packet_digest": self.packet["digest"], "run_id": self.packet["run_id"],
            "attempt_id": self.packet["attempt_id"], "spec_digest": self.packet["spec_digest"],
            "status": "completed", "changed_files": [], "command_claims": [],
            "summary": "Synthetic protocol result; independent acceptance is still required.",
            "blockers": [], "deviations": [], "residual_risks": [], "qualification": "synthetic"}
        self.init = {"type": "system", "subtype": "init", "session_id": self.session,
                     "model": self.model, "tools": ["Read", "Edit"]}
        self.result = {"type": "result", "subtype": "success", "is_error": False,
                       "session_id": self.session, "permission_denials": [],
                       "structured_output": self.worker}

    def decoder(self, **kwargs):
        return ClaudeStreamDecoder(self.packet, expected_session_id=self.session,
                                   expected_model=self.model, **kwargs)

    def wire(self, *events):
        return b"".join((json.dumps(e, ensure_ascii=False)+"\n").encode() for e in events)

    def test_chunked_result_is_immutable_packet_bound_data_not_acceptance(self):
        decoder = self.decoder()
        raw = self.wire(self.init, self.result)
        self.packet["digest"] = "f"*64  # constructor must retain immutable inputs
        for offset in range(0, len(raw), 7):decoder.feed(raw[offset:offset+7])
        result = decoder.finish(exit_code=0)
        self.assertEqual(loads(result.worker_result_json), self.worker)
        self.assertEqual(result.wire_sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual((result.session_id, result.reported_model, result.reported_tools),
                         (self.session, self.model, ("Read", "Edit")))
        self.assertFalse(hasattr(result, "acceptance"))
        self.assertFalse(hasattr(result, "termination_confirmed"))
        self.assertFalse(hasattr(result, "qualified"))

    def test_wire_decimal_cost_is_rounded_up_and_only_terminal_usage_is_reported(self):
        self.result.update(total_cost_usd=0.0000001, usage={"input_tokens": 11,
            "output_tokens": 7, "cache_creation_input_tokens": 3, "cache_read_input_tokens": 5})
        progress = {"type": "assistant", "session_id": self.session,
                    "message": {"model": self.model, "content": [], "usage": {"input_tokens": 9999}}}
        decoder = self.decoder()
        decoder.feed(self.wire(self.init, progress, self.result))
        self.assertEqual(loads(decoder.finish(exit_code=0).reported_usage_json), {
            "counter_scope": "terminal_reported_scope_unknown", "input_tokens": 11,
            "output_tokens": 7, "cache_creation_input_tokens": 3,
            "cache_read_input_tokens": 5, "cost_micro_usd": 1})

    def test_missing_denial_metadata_is_unknown_not_an_observed_denial(self):
        del self.result["permission_denials"]
        decoder = self.decoder()
        with self.assertRaises(TaskAlongError) as error:
            decoder.feed(self.wire(self.init, self.result))
        self.assertEqual(error.exception.code, "claude_permission_status_unknown")
        self.assertEqual(error.exception.effect_outcome, "uncertain")

    def test_nonboolean_tool_status_cannot_be_ignored(self):
        event = {"type": "user", "session_id": self.session,
                 "message": {"content": [{"type": "tool_result", "is_error": 1}]}}
        decoder = self.decoder()
        with self.assertRaises(TaskAlongError) as error:
            decoder.feed(self.wire(self.init, event, self.result))
        self.assertEqual(error.exception.code, "claude_tool_status_invalid")

    def expect_wire_error(self, events, code, *, exit_code=0, **limits):
        decoder = self.decoder(**limits)
        with self.assertRaises(TaskAlongError) as caught:
            decoder.feed(self.wire(*events))
            decoder.finish(exit_code=exit_code)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(caught.exception.effect_outcome, "uncertain")
        return decoder

    def test_worker_schema_and_every_packet_identity_are_independently_checked(self):
        for key in ("packet_id", "run_id", "attempt_id", "spec_digest", "packet_digest", "qualification"):
            result = copy.deepcopy(self.result)
            result["structured_output"][key] = (str(uuid.uuid4()) if key.endswith("_id")
                else "production" if key == "qualification" else "e"*64)
            with self.subTest(key=key):
                self.expect_wire_error([self.init, result], "claude_result_binding_mismatch")
        for worker in (None, "{\"status\":\"completed\"}", self.worker | {"acceptance": {"decision": "accepted"}}):
            with self.subTest(worker_type=type(worker).__name__):
                self.expect_wire_error([self.init, self.result | {"structured_output": worker}], "claude_result_invalid")
        for extra in ({"status": "blocked"}, {"blockers": ["still blocked"]}, {"deviations": ["changed scope"]}):
            # Values not admitted by the schema are also invalid, never repaired.
            decoder = self.decoder()
            with self.subTest(extra=extra), self.assertRaises(TaskAlongError):
                decoder.feed(self.wire(self.init, self.result | {"structured_output": self.worker | extra}))

    def test_session_and_reported_model_never_silently_change(self):
        self.expect_wire_error([self.init, self.result | {"session_id": str(uuid.uuid4())}], "claude_session_mismatch")
        self.expect_wire_error([self.init | {"model": "different-model"}, self.result], "claude_model_mismatch")
        for event in (
            {"type": "assistant", "session_id": self.session, "message": {"model": "fallback", "content": []}},
            {"type": "stream_event", "session_id": self.session, "event": {"type": "message_start", "message": {"model": "fallback"}}},
            self.result | {"modelUsage": {self.model: {}, "auxiliary-model": {}}},
        ):
            self.expect_wire_error([self.init, event], "claude_model_mismatch")
        self.expect_wire_error([self.init, self.result | {"parent_tool_use_id": "child"}], "claude_child_session_unsupported")
        self.expect_wire_error([self.init, self.result | {"origin": {"kind": "peer"}}], "claude_unsolicited_turn")

    def test_exit_zero_cannot_hide_error_denial_or_incomplete_terminal(self):
        for change, code in (
            ({"is_error": True}, "claude_result_failed"),
            ({"is_error": 0}, "claude_result_failed"),
            ({"subtype": "error_max_turns"}, "claude_result_failed"),
            ({"terminal_reason": "aborted_tools"}, "claude_result_failed"),
            ({"errors": ["synthetic failure"]}, "claude_result_failed"),
            ({"api_error_status": 429}, "claude_provider_error"),
            ({"deferred_tool_use": {"id": "pending"}}, "claude_result_failed"),
            ({"permission_denials": [{"tool_name": "Edit"}]}, "claude_permission_denied"),
        ):
            with self.subTest(change=change):
                self.expect_wire_error([self.init, self.result | change], code)
        self.expect_wire_error([self.init, {"type": "system", "subtype": "permission_denied", "session_id": self.session}], "claude_permission_denied")
        self.expect_wire_error([self.init, self.result], "claude_exit_failed", exit_code=1)
        self.expect_wire_error([self.init, self.result], "claude_exit_failed", exit_code=False)

    def test_unknown_or_duplicate_terminal_and_session_reset_are_not_progress(self):
        self.expect_wire_error([self.result], "claude_init_missing")
        self.expect_wire_error([self.init], "claude_terminal_missing")
        self.expect_wire_error([self.init, self.result, self.result], "claude_event_after_terminal")
        self.expect_wire_error([self.init, self.init], "claude_event_unsupported")
        for kind in ("conversation_reset", "future_terminal", "control_request"):
            self.expect_wire_error([self.init, {"type": kind, "session_id": self.session}], "claude_event_unsupported")
        decoder = self.decoder()
        decoder.feed(self.wire(self.init, self.result).rstrip(b"\n"))
        with self.assertRaises(TaskAlongError) as error:decoder.finish(exit_code=0)
        self.assertEqual(error.exception.code, "claude_stream_truncated")

    def test_json_encoding_duplicate_keys_and_nesting_are_bounded(self):
        for raw in (b"[]\n", b'{"type":"system","type":"result"}\n', b'{"n":NaN}\n',
                    b'{"n":Infinity}\n', b'{"n":1e9999999}\n', b'{"n":9007199254740992}\n',
                    b'{"bad":"\xff"}\n', b'{"x":"\\ud800"}\n',
                    b'{"x":'+b'['*40+b'0'+b']'*40+b'}\n'):
            with self.subTest(raw_hash=hashlib.sha256(raw).hexdigest()):
                decoder = self.decoder()
                with self.assertRaises(TaskAlongError) as error:decoder.feed(raw)
                self.assertEqual(error.exception.code, "claude_frame_invalid")

    def test_line_total_and_frame_limits_fail_before_unbounded_retention(self):
        decoder = self.decoder(max_line_bytes=16)
        with self.assertRaises(TaskAlongError) as error:decoder.feed(b"x"*17)
        self.assertEqual(error.exception.code, "claude_line_limit")
        raw = self.wire(self.init, self.result)
        decoder = self.decoder(max_output_bytes=len(raw)-1)
        with self.assertRaises(TaskAlongError) as error:decoder.feed(raw)
        self.assertEqual(error.exception.code, "claude_output_limit")
        self.expect_wire_error([self.init, self.result], "claude_frame_limit", max_frames=1)

    def test_usage_missing_stays_unknown_and_invalid_values_are_not_zero(self):
        decoder = self.decoder();decoder.feed(self.wire(self.init, self.result))
        usage = loads(decoder.finish(exit_code=0).reported_usage_json)
        self.assertTrue(all(usage[k] is None for k in usage if k != "counter_scope"))
        for value in (True, -1, 1.5):
            self.expect_wire_error([self.init, self.result | {"usage": {"input_tokens": value}}], "claude_usage_invalid")
        for cost in (-0.01, True, 9007199255):
            self.expect_wire_error([self.init, self.result | {"total_cost_usd": cost}], "claude_usage_invalid")
        result = copy.deepcopy(self.result)
        result["structured_output"]["extensions"] = {"test:fraction": 0.1}
        self.expect_wire_error([self.init, result], "claude_result_invalid")

    def test_parser_failure_is_sticky_and_does_not_echo_vendor_text(self):
        decoder = self.decoder()
        canary = b"SYNTHETIC_PRIVATE_PAYLOAD"
        with self.assertRaises(TaskAlongError) as first:decoder.feed(b"{"+canary+b"\n")
        self.assertNotIn(canary.decode(), str(first.exception))
        with self.assertRaises(TaskAlongError) as later:decoder.feed(self.wire(self.init, self.result))
        self.assertIs(first.exception, later.exception)
        with self.assertRaises(TaskAlongError) as finish:decoder.finish(exit_code=0)
        self.assertIs(first.exception, finish.exception)

    def test_sealed_result_is_idempotent_but_more_input_is_refused(self):
        decoder = self.decoder();decoder.feed(self.wire(self.init, self.result))
        first = decoder.finish(exit_code=0)
        self.assertIs(first, decoder.finish(exit_code=0))
        with self.assertRaises(TaskAlongError):decoder.feed(b"new input\n")
        with self.assertRaises(TaskAlongError):decoder.finish(exit_code=0)

    def test_limits_and_binding_errors_are_predecode_not_sent(self):
        for kwargs in ({"max_frames": True}, {"max_output_bytes": -1}, {"max_line_bytes": 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(TaskAlongError) as error:self.decoder(**kwargs)
            self.assertEqual(error.exception.effect_outcome, "not_sent")
        with self.assertRaises(TaskAlongError):
            ClaudeStreamDecoder(self.packet, expected_session_id="latest", expected_model=self.model)

    def test_module_installation_does_not_register_a_claude_launcher(self):
        from taskalong.executors.registry import executor_for
        with self.assertRaises(TaskAlongError) as error:executor_for({"adapter": "claude-code"})
        self.assertEqual(error.exception.code, "adapter_unavailable")

    def test_cost_normalization_is_independent_of_ambient_decimal_context(self):
        from decimal import localcontext, ROUND_DOWN
        self.result["total_cost_usd"] = 0.1234561
        with localcontext() as context:
            context.prec = 1
            context.rounding = ROUND_DOWN
            decoder = self.decoder()
            decoder.feed(self.wire(self.init, self.result))
            cost = loads(decoder.finish(exit_code=0).reported_usage_json)["cost_micro_usd"]
        self.assertEqual(cost, 123457)

    def test_initial_provider_failure_is_not_ignored(self):
        for change in ({"error": "synthetic provider failure"}, {"api_error_status": 401}):
            with self.subTest(change=change), self.assertRaises(TaskAlongError):
                decoder = self.decoder()
                decoder.feed(self.wire(self.init | change, self.result))

    def test_initial_unsolicited_origin_is_not_ignored(self):
        decoder = self.decoder()
        with self.assertRaises(TaskAlongError):
            decoder.feed(self.wire(self.init | {"origin": {"kind": "peer"}}, self.result))
