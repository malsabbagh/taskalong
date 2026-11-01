"""Original native-shape synthetic JSONL; no real backend qualification."""
import copy
from decimal import localcontext, ROUND_DOWN
import hashlib
import json
from pathlib import Path
import unittest

from jsonschema import validate

from taskalong.errors import TaskAlongError
from taskalong.executors.claude_local import new_decoder
from taskalong.executors.claude_local_protocol import ClaudeLocalDecoder, response_schema
from test_claude_local_config import binding, config


LIMITS = {"max_protocol_records": 32, "max_record_bytes": 16384, "max_proposal_bytes": 4096}


class ClaudeLocalProtocolTests(unittest.TestCase):
    def test_extended_frames_have_total_node_depth_and_unicode_bounds(self):
        limits = LIMITS | {"max_record_bytes": 16777216}
        nested = 0
        for _ in range(40):
            nested = [nested]
        for value in ([[0] * 4096 for _ in range(17)], [0] * 4097,
                      {str(i): 0 for i in range(4097)}, nested, "\ud800"):
            d = ClaudeLocalDecoder(self.binding, limits, extended_wire=True)
            with self.assertRaises(TaskAlongError) as caught:
                d.feed("stdout", (json.dumps(self.init | {"unknown": value}, ensure_ascii=True) + "\n").encode())
            self.assertEqual(caught.exception.code, "claude_local_frame_invalid")
        legacy = new_decoder(self.binding, LIMITS | {"max_record_bytes": 8388608})
        legacy.feed("stdout", self.wire(self.init | {"unknown": [[0] * 4096 for _ in range(17)]}, self.result))
        self.assertEqual(legacy.finish()["structured_response"], self.proposal)

    def test_large_file_content_is_an_explicit_opt_in_with_unchanged_native_default(self):
        limits = LIMITS | {"max_record_bytes": 4194304, "max_proposal_bytes": 1048576}
        proposal = self.proposal | {"changes": {"src/app.py": "x" * 70000 + "\n"}}
        raw = self.wire(self.init, self.result | {"structured_output": proposal})
        legacy = new_decoder(self.binding, limits)
        with self.assertRaises(TaskAlongError) as caught:
            legacy.feed("stdout", raw)
        self.assertEqual(caught.exception.code, "claude_local_proposal_text_invalid")
        extended = ClaudeLocalDecoder(self.binding, limits, max_content_bytes=1048576)
        extended.feed("stdout", raw)
        self.assertEqual(extended.finish()["structured_response"], proposal)
        for bound in (True, 0, 1048577):
            with self.assertRaises(TaskAlongError):
                ClaudeLocalDecoder(self.binding, limits, max_content_bytes=bound)

    def setUp(self):
        self.binding = binding()
        self.init = self.event("system", subtype="init", model="synthetic-model", tools=[])
        self.proposal = {"bundle_digest": self.binding["bundle_digest"], "changes": {"src/app.py": "pass\n"}}
        self.result = self.event("result", subtype="success", is_error=False, permission_denials=[],
                                 structured_output=self.proposal)

    def event(self, kind, **values):
        return {"type": kind, "session_id": self.binding["attempt_id"], "parent_tool_use_id": None, **values}

    def wire(self, *events):
        return b"".join((json.dumps(x, ensure_ascii=False) + "\n").encode() for x in events)

    def fail(self, events, code, **limits):
        decoder = new_decoder(self.binding, LIMITS | limits)
        with self.assertRaises(TaskAlongError) as caught:
            decoder.feed("stdout", self.wire(*events))
            decoder.finish()
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(caught.exception.effect_outcome, "uncertain")
        self.assertFalse(caught.exception.retryable)

    def test_both_backends_share_one_chunked_bound_protocol_without_lifecycle_claims(self):
        for backend in ("anthropic", "ollama"):
            cfg = config(backend)
            b = binding(cfg)
            decoder = new_decoder(b, LIMITS)
            b["bundle_digest"] = "d" * 64
            b["writable_outputs"].append("outside.txt")
            raw = self.wire(self.init, self.result)
            for offset in range(0, len(raw), 7):
                decoder.feed("stdout", raw[offset:offset + 7])
            decoder.feed("stderr", b"synthetic warning\n")
            result = decoder.finish()
            self.assertEqual(result["structured_response"], self.proposal)
            self.assertEqual(result["backend"], backend)
            self.assertEqual(result["capture"]["stdout"], {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
            self.assertEqual(result["capture"]["stderr"]["bytes"], 18)
            self.assertIsNone(result["native_turn_id"])
            for key in ("termination_confirmed", "acceptance", "settled_usage", "production_dispatch_allowed"):
                self.assertNotIn(key, result)
            self.assertIsNone(result["backend_route_observation"])
            self.assertEqual(result["qualification"], "native_unqualified")
            result["structured_response"]["changes"]["src/app.py"] = "changed\n"
            self.assertEqual(decoder.finish()["structured_response"], self.proposal)

    def test_schema_restricts_declared_outputs_and_bundle(self):
        schema = response_schema(self.binding)
        validate(self.proposal, schema)
        from jsonschema.exceptions import ValidationError
        for proposal in (self.proposal | {"bundle_digest": "d" * 64},
                         self.proposal | {"changes": {"undeclared.py": "x\n"}}, self.proposal | {"acceptance": True}):
            with self.assertRaises(ValidationError):
                validate(proposal, schema)

    def test_original_public_fixture_is_a_protocol_example_only(self):
        decoder = new_decoder(self.binding, LIMITS)
        raw = (Path(__file__).parent / "fixtures/claude_local/proposal.jsonl").read_bytes()
        decoder.feed("stdout", raw)
        result = decoder.finish(exit_code=0)
        self.assertEqual(result["structured_response"], self.proposal)
        self.assertEqual(result["qualification"], "native_unqualified")

    def test_binding_and_limits_are_validated_without_dispatch(self):
        for change in ({"run_id": []}, {"attempt_id": "bad"}, {"bundle_digest": "X" * 64},
                       {"writable_outputs": ["../x"]}, {"writable_outputs": [".git/config"]},
                       {"writable_outputs": [".GIT/config"]},
                       {"writable_outputs": ["a", "A"]}, {"writable_outputs": ["a", "a/b"]},
                       {"writable_outputs": []}, {"context": "exclude"}):
            with self.subTest(change=change), self.assertRaises(TaskAlongError) as caught:
                new_decoder(self.binding | change, LIMITS)
            self.assertEqual(caught.exception.effect_outcome, "not_sent")
        for change in ({"max_protocol_records": 0}, {"max_record_bytes": True},
                       {"max_proposal_bytes": 4 * 1024 * 1024 + 1}):
            with self.assertRaises(TaskAlongError):
                new_decoder(self.binding, LIMITS | change)

    def test_session_model_and_reported_auxiliary_model_cannot_change(self):
        self.fail([self.init, self.result | {"session_id": "33333333-3333-4333-8333-333333333333"}], "claude_local_session_mismatch")
        self.fail([self.init | {"model": "fallback"}, self.result], "claude_local_model_mismatch")
        for event in (self.event("assistant", message={"model": "fallback", "content": []}),
                      self.event("stream_event", event={"type": "message_start", "message": {"model": "fallback", "content": []}}),
                      self.result | {"modelUsage": {"fallback": {}}}, self.result | {"model": "fallback"}):
            self.fail([self.init, event], "claude_local_model_mismatch")
        self.fail([self.init, self.result | {"parent_tool_use_id": "subagent"}], "claude_local_child_session_unsupported")

    def test_denial_unknown_permission_auth_error_or_pending_work_never_succeed(self):
        for change, code in (({"is_error": True}, "claude_local_result_failed"),
                             ({"is_error": 0}, "claude_local_result_failed"),
                             ({"subtype": "error_max_turns"}, "claude_local_result_failed"),
                             ({"permission_denials": [{"tool_name": "Bash"}]}, "claude_local_permission_denied"),
                             ({"errors": ["failed"]}, "claude_local_result_failed"),
                             ({"deferred_tool_use": {}}, "claude_local_result_failed"),
                             ({"api_error_status": 429}, "claude_local_provider_error")):
            self.fail([self.init, self.result | change], code)
        event = copy.deepcopy(self.result); del event["permission_denials"]
        self.fail([self.init, event], "claude_local_permission_status_unknown")
        self.fail([self.result | {"subtype": "error_during_execution", "is_error": True}], "claude_local_result_failed")
        self.fail([self.init, self.event("system", subtype="permission_denied")], "claude_local_permission_denied")

    def test_reported_tools_and_tool_blocks_are_contradictions(self):
        self.fail([self.init | {"tools": ["Bash"]}, self.result], "claude_local_tools_mismatch")
        for kind in ("tool_use", "server_tool_use", "tool_result"):
            block = {"type": kind, "name": "Bash", "input": {}}
            for event in (self.event("assistant", message={"model": "synthetic-model", "content": [block]}),
                          self.event("user", message={"content": [block]}),
                          self.event("stream_event", event={"type": "content_block_start", "content_block": block})):
                self.fail([self.init, event], "claude_local_tool_observed")
        self.fail([self.init, self.event("assistant", message={"model": "synthetic-model", "content": [],
            "stop_reason": "tool_use"})], "claude_local_tool_observed")
        self.fail([self.init, self.event("stream_event", event={"type": "message_delta",
            "delta": {"stop_reason": "tool_use"}})], "claude_local_tool_observed")
        self.fail([self.init, self.event("stream_event", event={"type": "content_block_delta",
            "delta": {"type": "input_json_delta", "partial_json": "{}"}})], "claude_local_event_unsupported")

    def test_unsolicited_origins_and_contradictory_partial_context_fail(self):
        self.fail([self.init, self.result | {"origin": {"kind": "peer"}}], "claude_local_unsolicited_turn")
        decoder = new_decoder(self.binding | {"context": "native-only"}, LIMITS)
        with self.assertRaises(TaskAlongError) as error:
            decoder.feed("stdout", self.wire(self.init | {"mcp_servers": [{"name": "unexpected"}]}))
        self.assertEqual(error.exception.code, "claude_local_context_mismatch")

    def test_proposals_are_structured_bound_and_scoped_without_text_repair(self):
        for value, code in ((None, "claude_local_proposal_binding_mismatch"),
                            ("```json\n{}\n```", "claude_local_proposal_binding_mismatch"),
                            (self.proposal | {"bundle_digest": "d" * 64}, "claude_local_proposal_binding_mismatch"),
                            (self.proposal | {"extra": True}, "claude_local_proposal_binding_mismatch"),
                            (self.proposal | {"changes": {}}, "claude_local_proposal_scope_invalid"),
                            (self.proposal | {"changes": {"undeclared": "x\n"}}, "claude_local_proposal_scope_invalid")):
            self.fail([self.init, self.result | {"structured_output": value}], code)
        for content in (1, True, {}, "not LF terminated", "crlf\r\n", "NUL\x00\n", "x" * 65536 + "\n"):
            proposal = self.proposal | {"changes": {"src/app.py": content}}
            self.fail([self.init, self.result | {"structured_output": proposal}],
                      "claude_local_proposal_text_invalid", max_record_bytes=100000)
        for content in (None, "", "valid\n"):
            decoder = new_decoder(self.binding, LIMITS)
            decoder.feed("stdout", self.wire(self.init, self.result | {"structured_output": self.proposal | {"changes": {"new.txt": content}}}))
            self.assertEqual(decoder.finish()["structured_response"]["changes"]["new.txt"], content)

    def test_only_terminal_usage_is_retained_and_missing_is_not_zero(self):
        decoder = new_decoder(self.binding, LIMITS)
        progress = self.event("assistant", message={"model": "synthetic-model", "content": [], "usage": {"input_tokens": 999}})
        decoder.feed("stdout", self.wire(self.init, progress, self.result))
        usage = decoder.finish()["reported_usage"]
        self.assertTrue(all(usage[k] is None for k in usage if k != "counter_scope"))
        for value in (True, -1, 1.5):
            self.fail([self.init, self.result | {"usage": {"input_tokens": value}}], "claude_local_usage_invalid")
        for value in (-1, True, 9007199255):
            self.fail([self.init, self.result | {"total_cost_usd": value}], "claude_local_usage_invalid")

    def test_decimal_cost_is_rounded_up_independent_of_decimal_context(self):
        for precision in (2, 28):
            with localcontext() as context:
                context.prec = precision; context.rounding = ROUND_DOWN
                decoder = new_decoder(self.binding, LIMITS)
                decoder.feed("stdout", self.wire(self.init, self.result | {"total_cost_usd": 0.0000001,
                    "usage": {"input_tokens": 11, "output_tokens": 3}}))
                usage = decoder.finish()["reported_usage"]
            self.assertEqual(usage["cost_micro_usd"], 1)
            self.assertEqual(usage["input_tokens"], 11)
            self.assertIsNone(usage["financial_settlement"])

    def test_requested_and_reported_effort_are_distinct_from_effective_effort(self):
        decoder = new_decoder(self.binding | {"requested_effort": "high"}, LIMITS)
        decoder.feed("stdout", self.wire(self.init, self.result))
        result = decoder.finish()
        self.assertEqual(result["requested_effort"], "high")
        self.assertIsNone(result["reported_effort"])
        self.assertIsNone(result["effective_effort"])
        self.fail([self.init | {"effort": "high"}, self.result | {"effort": "low"}], "claude_local_effort_mismatch")

    def test_duplicate_missing_unknown_or_partial_terminal_is_never_recovered(self):
        self.fail([self.init, self.result, self.result], "claude_local_event_after_terminal")
        self.fail([self.init], "claude_local_terminal_missing")
        self.fail([self.result], "claude_local_init_missing")
        self.fail([self.init, self.init], "claude_local_event_unsupported")
        self.fail([self.init, self.event("future_terminal")], "claude_local_event_unsupported")
        duplicate = self.event("system", subtype="status", uuid="same-id")
        self.fail([self.init, duplicate, duplicate, self.result], "claude_local_duplicate_event")
        decoder = new_decoder(self.binding, LIMITS)
        decoder.feed("stdout", self.wire(self.init, self.result).rstrip(b"\n"))
        with self.assertRaises(TaskAlongError) as caught:
            decoder.finish()
        self.assertEqual(caught.exception.code, "claude_local_stream_truncated")

    def test_stdout_record_and_proposal_limits_are_separate(self):
        self.fail([self.init, self.result], "claude_local_record_count_limit", max_protocol_records=1)
        self.fail([self.init, self.result], "claude_local_proposal_limit", max_proposal_bytes=16)
        decoder = new_decoder(self.binding, LIMITS | {"max_record_bytes": 8})
        with self.assertRaises(TaskAlongError) as caught:
            decoder.feed("stdout", b"x" * 9)
        self.assertEqual(caught.exception.code, "claude_local_record_limit")

    def test_malformed_json_unicode_nesting_and_numbers_fail_without_echoing_content(self):
        for raw in (b"[]\n", b'{"type":"system","type":"result"}\n', b'{"n":NaN}\n',
                    b'{"n":Infinity}\n', b'{"n":1e999999}\n', b'{"n":9007199254740992}\n',
                    b'{"x":"\xff"}\n', b'{"x":"\\ud800"}\n',
                    b'{"x":' + b'[' * 40 + b'0' + b']' * 40 + b'}\n', b'{PRIVATE_CANARY\n'):
            decoder = new_decoder(self.binding, LIMITS)
            with self.subTest(raw=hashlib.sha256(raw).hexdigest()), self.assertRaises(TaskAlongError) as caught:
                decoder.feed("stdout", raw)
            self.assertEqual(caught.exception.code, "claude_local_frame_invalid")
            self.assertNotIn("PRIVATE_CANARY", str(caught.exception))
            with self.assertRaises(TaskAlongError) as later:
                decoder.finish()
            self.assertIs(later.exception, caught.exception)

    def test_stderr_cannot_supply_a_result_and_owner_exit_is_not_ignored(self):
        decoder = new_decoder(self.binding, LIMITS)
        decoder.feed("stderr", self.wire(self.init, self.result))
        with self.assertRaises(TaskAlongError) as caught:
            decoder.finish()
        self.assertEqual(caught.exception.code, "claude_local_terminal_missing")
        for exit_code in (1, -15, True, False, "0"):
            decoder = new_decoder(self.binding, LIMITS)
            decoder.feed("stdout", self.wire(self.init, self.result))
            with self.assertRaises(TaskAlongError) as caught:
                decoder.finish(exit_code=exit_code)
            self.assertEqual(caught.exception.code, "claude_local_exit_failed")

    def test_closed_decoder_and_invalid_stream_inputs_refuse(self):
        decoder = new_decoder(self.binding, LIMITS)
        decoder.feed("stdout", self.wire(self.init, self.result)); decoder.finish()
        with self.assertRaises(TaskAlongError) as caught:
            decoder.feed("stderr", b"late")
        self.assertEqual(caught.exception.code, "claude_local_decoder_closed")
        for stream, chunk in (("result", b"x"), ([], b"x"), ("stdout", "text")):
            with self.assertRaises(TaskAlongError):
                new_decoder(self.binding, LIMITS).feed(stream, chunk)


if __name__ == "__main__":
    unittest.main()
