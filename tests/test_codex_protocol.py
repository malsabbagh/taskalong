"""Codex observations stay bounded, exact-thread and separate from identity proof."""
import json
import unittest

from taskalong.errors import TaskAlongError
from taskalong.executors.codex_protocol import CodexEventDecoder, MAX_USAGE_TOKENS


def record(**value):
    return json.dumps(value).encode()


class CodexProtocolTests(unittest.TestCase):
    def test_one_turn_observes_only_thread_and_reported_usage(self):
        decoder = CodexEventDecoder()
        decoder.consume(record(type="thread.started", thread_id="exact-thread", model="untrusted-model"))
        decoder.consume(record(type="turn.started"))
        decoder.consume(record(type="item.completed", item={"text": "private provider text"}))
        decoder.consume(record(type="turn.completed", usage={"input_tokens": 12, "output_tokens": 3,
                                                            "cost_usd": "0", "model": "untrusted-model"}))
        self.assertEqual((decoder.thread_id, decoder.terminal, decoder.error_code),
                         ("exact-thread", "turn.completed", None))
        self.assertEqual(decoder.usage, {"input_tokens": 12, "output_tokens": 3, "cost_usd": None})
        observed = decoder.usage
        observed["cost_usd"] = "invented"
        self.assertIsNone(decoder.usage["cost_usd"])
        self.assertEqual(decoder.diagnostics, {})

    def test_usage_unknowns_and_safe_integer_limit_are_preserved(self):
        for usage, expected in (({}, None), ({"input_tokens": 0}, 0),
                                ({"input_tokens": MAX_USAGE_TOKENS}, MAX_USAGE_TOKENS)):
            with self.subTest(usage=usage):
                decoder = CodexEventDecoder()
                decoder.consume(record(type="turn.completed", usage=usage))
                self.assertIsNone(decoder.error_code)
                self.assertEqual(decoder.usage["input_tokens"], expected)
                self.assertIsNone(decoder.usage["output_tokens"])
                self.assertIsNone(decoder.usage["cost_usd"])

    def test_invalid_usage_is_atomic_and_does_not_erase_unknowns(self):
        for invalid in (True, -1, 1.5, "12", MAX_USAGE_TOKENS + 1, [], {}):
            with self.subTest(invalid=invalid):
                decoder = CodexEventDecoder()
                decoder.consume(record(type="turn.completed", usage={"input_tokens": 12, "output_tokens": invalid}))
                self.assertEqual(decoder.error_code, "runtime_protocol_invalid")
                self.assertIsNone(decoder.terminal)
                self.assertEqual(decoder.usage, {"input_tokens": None, "output_tokens": None, "cost_usd": None})

    def test_native_resume_cannot_adopt_a_foreign_thread(self):
        decoder = CodexEventDecoder(mode="native_resume", thread_id="authorized-thread")
        decoder.consume(record(type="thread.started", thread_id="foreign-thread"))
        decoder.consume(record(type="thread.started", thread_id="authorized-thread"))
        decoder.consume(record(type="turn.completed", usage={"input_tokens": 1}))
        self.assertEqual(decoder.error_code, "native_resume_thread_mismatch")
        self.assertIsNone(decoder.thread_id)
        self.assertIsNone(decoder.terminal)

    def test_no_event_can_follow_a_terminal(self):
        for terminal in ("turn.completed", "turn.failed", "error"):
            for following in ("turn.completed", "thread.started", "item.completed", "future.event"):
                with self.subTest(terminal=terminal, following=following):
                    decoder = CodexEventDecoder()
                    decoder.consume(record(type="thread.started", thread_id="exact-thread"))
                    decoder.consume(record(type=terminal))
                    decoder.consume(record(type=following, thread_id="exact-thread"))
                    self.assertEqual(decoder.error_code, "runtime_protocol_invalid")

    def test_record_limit_stops_even_tiny_unknown_events(self):
        decoder = CodexEventDecoder(max_records=2)
        decoder.consume(record(type="future.event", private="do not expose"))
        decoder.consume(record(type="future.event"))
        decoder.consume(record(type="turn.completed"))
        self.assertEqual(decoder.error_code, "runtime_protocol_record_limit")
        self.assertEqual(decoder.diagnostics, {"unknown_event_count": 2})
        self.assertIsNone(decoder.terminal)

    def test_malformed_or_excessively_nested_records_have_only_safe_errors(self):
        nested = {"type": "future.event"}
        for _ in range(40):
            nested = {"type": "future.event", "nested": nested}
        for raw in (b'[]', b'null', b'\xff', b'{"type":"error","type":"turn.completed"}',
                    b'{"type":[]}', record(type=""), json.dumps(nested).encode(),
                    b'{"type":"future.event","nested":' + b'[' * 1500 + b'0' + b']' * 1500 + b'}'):
            with self.subTest(raw=raw[:50]):
                decoder = CodexEventDecoder()
                decoder.consume(raw)
                self.assertEqual(decoder.error_code, "runtime_protocol_invalid")
                self.assertEqual(decoder.diagnostics, {})

    def test_line_bound_and_failure_are_sticky(self):
        decoder = CodexEventDecoder(max_line_bytes=32)
        decoder.consume(record(type="future.event", private="x" * 100))
        decoder.consume(record(type="turn.completed"))
        self.assertEqual(decoder.error_code, "runtime_protocol_invalid")
        self.assertIsNone(decoder.terminal)

    def test_invalid_modes_bindings_and_limits_refuse_before_records(self):
        for arguments in ({"mode": "last"}, {"mode": []}, {"mode": "native_resume"},
                          {"mode": "native_resume", "thread_id": "--last"},
                          {"thread_id": "unrequested"}, {"max_records": True},
                          {"max_records": 65537}, {"max_line_bytes": 0}):
            with self.subTest(arguments=arguments), self.assertRaises(TaskAlongError) as raised:
                CodexEventDecoder(**arguments)
            self.assertEqual(raised.exception.effect_outcome, "not_sent")

    def test_reported_thread_cannot_smuggle_resume_flags(self):
        for thread in ("--last", "--all", "-m", "-thread"):
            with self.subTest(thread=thread):
                decoder = CodexEventDecoder()
                decoder.consume(record(type="thread.started", thread_id=thread))
                self.assertEqual(decoder.error_code, "runtime_protocol_invalid")
                self.assertIsNone(decoder.thread_id)


if __name__ == "__main__":
    unittest.main()
