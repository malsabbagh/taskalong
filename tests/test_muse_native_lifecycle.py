"""Synthetic native wrappers only: no provider, process, State or filesystem I/O."""
import copy
import json
import unittest
from unittest.mock import patch

from taskalong import muse_native_lifecycle as lifecycle
from taskalong.muse_native_lifecycle import NativeModelTaskGuard
from taskalong.validation import canonical_bytes

SESSION = "11111111-1111-4111-8111-111111111111"
RUN = "22222222-2222-4222-8222-222222222222"
TASK = "33333333-3333-4333-8333-333333333333"
SECOND = "44444444-4444-4444-8444-444444444444"
OTHER = "55555555-5555-4555-8555-555555555555"
MODEL = "model.meta.response"


def row(sequence, kind="proposed", task=TASK, *, task_kind=MODEL):
    event = {"kind": kind, "task_id": task}
    if kind == "proposed":
        event["task_kind"] = task_kind
    elif kind == "side_effect_intent":
        event["operation"] = task_kind
    return {"schema_version": 1, "payload_schema_version": 1,
            "stream": {"kind": "session", "id": SESSION}, "sequence": sequence,
            "payload_type": "task.lifecycle." + kind,
            "payload": {"kind": "task_lifecycle", "command_id": RUN,
                        "run_stream": {"kind": "run", "id": RUN},
                        "task_id": task, "task_stream": {"kind": "task", "id": task}, "event": event}}


def raw(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def start_rows():
    return [row(1), row(2, "side_effect_intent"), row(3, "started")]


class NativeModelTaskGuardTests(unittest.TestCase):
    def feed(self, guard, values):
        for value in values:
            self.assertIsNone(guard.observe(raw(value)))
        return guard.summary()

    def test_completed_one_model_does_not_stop(self):
        guard = NativeModelTaskGuard(SESSION)
        values = start_rows() + [row(4, "status"), row(5, "completed")]
        values[3]["payload"]["event"].update(message="synthetic status", details={"elapsed": 1.5})
        summary = self.feed(guard, values)
        self.assertFalse(guard.stop_requested)
        self.assertEqual(summary["model_tasks_observed"], 1)
        self.assertEqual(summary["model_tasks_proposed"], 1)
        self.assertEqual(summary["model_tasks_side_effect_intent"], 1)
        self.assertEqual(summary["model_tasks_started"], 1)

    def test_timeout_then_queued_second_task_in_one_chunk_sticky_first_cause(self):
        guard = NativeModelTaskGuard(SESSION)
        values = start_rows() + [row(4, "timed_out"), row(5, task=SECOND),
                               row(6, "side_effect_intent", SECOND), row(7, "started", SECOND)]
        chunk = b"\n".join(raw(value) for value in values) + b"\n"
        for line in chunk.splitlines():
            guard.observe(line)
        summary = guard.summary()
        self.assertTrue(guard.stop_requested)
        self.assertEqual(summary["first_stop_cause"], "model_task_timed_out")
        self.assertEqual(summary["first_stop_sequence"], 4)
        self.assertEqual(summary["model_tasks_observed"], 2)
        self.assertEqual(summary["model_tasks_started"], 2)
        self.assertEqual(summary["model_tasks_timed_out"], 1)
        self.assertTrue(summary["protocol_valid"])

    def test_later_malformed_row_invalidates_protocol_without_losing_first_stop(self):
        guard = NativeModelTaskGuard(SESSION)
        self.feed(guard, start_rows() + [row(4, "timed_out")])
        guard.observe(b"malformed synthetic row")
        summary = guard.summary()
        self.assertFalse(summary["protocol_valid"])
        self.assertEqual(summary["first_protocol_failure"], "malformed_native_lifecycle")
        self.assertEqual(summary["first_stop_cause"], "model_task_timed_out")

    def test_second_proposal_stops_before_its_intent(self):
        guard = NativeModelTaskGuard(SESSION)
        summary = self.feed(guard, start_rows() + [row(4, "completed"), row(5, task=SECOND)])
        self.assertEqual(summary["first_stop_cause"], "second_model_task_observed")
        self.assertEqual(summary["model_tasks_started"], 1)

    def test_second_intent_without_proposal_stops_and_records_model_marker(self):
        guard = NativeModelTaskGuard(SESSION)
        summary = self.feed(guard, start_rows() + [row(4, "side_effect_intent", SECOND)])
        self.assertTrue(guard.stop_requested)
        self.assertEqual(summary["model_tasks_observed"], 2)

    def test_unknown_started_task_stops_without_inventing_model_count(self):
        guard = NativeModelTaskGuard(SESSION)
        summary = self.feed(guard, start_rows() + [row(4, "started", SECOND)])
        self.assertTrue(guard.stop_requested)
        self.assertEqual(summary["model_tasks_observed"], 1)

    def test_no_double_count_proposed_intent_start_same_task(self):
        guard = NativeModelTaskGuard(SESSION)
        summary = self.feed(guard, start_rows())
        self.assertEqual(summary["model_tasks_observed"], 1)
        self.assertFalse(guard.stop_requested)

    def test_model_failures_request_stop(self):
        for kind in ("timed_out", "failed", "cancelled"):
            with self.subTest(kind=kind):
                guard = NativeModelTaskGuard(SESSION)
                summary = self.feed(guard, start_rows() + [row(4, kind)])
                self.assertEqual(summary["first_stop_cause"], "model_task_" + kind)

    def test_nonmodel_session_name_task_not_counted(self):
        guard = NativeModelTaskGuard(SESSION)
        summary = self.feed(guard, [row(1, task=OTHER, task_kind="session_name.allocate"),
                                    row(2, "started", OTHER), row(3, "completed", OTHER),
                                    row(4), row(5, "side_effect_intent"), row(6, "started"), row(7, "completed")])
        self.assertFalse(guard.stop_requested)
        self.assertEqual(summary["model_tasks_observed"], 1)
        self.assertEqual(summary["tracked_tasks"], 2)

    def test_nonmodel_failure_not_mistaken_for_meta_failure(self):
        guard = NativeModelTaskGuard(SESSION)
        self.feed(guard, [row(1, task=OTHER, task_kind="session_name.allocate"), row(2, "failed", OTHER)])
        self.assertFalse(guard.stop_requested)

    def test_foreign_session_run_command_and_task_bindings_stop(self):
        mutations = [lambda v: v["stream"].update(id=OTHER),
                     lambda v: v["payload"]["run_stream"].update(id=OTHER),
                     lambda v: v["payload"].update(command_id=OTHER),
                     lambda v: v["payload"]["task_stream"].update(id=OTHER),
                     lambda v: v["payload"]["event"].update(task_id=OTHER),
                     lambda v: v["payload"]["run_stream"].update(kind="session"),
                     lambda v: v["payload"]["task_stream"].update(kind="run")]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                guard = NativeModelTaskGuard(SESSION)
                value = row(1)
                mutation(value)
                self.feed(guard, [value])
                self.assertTrue(guard.stop_requested)

    def test_run_change_after_initial_binding_stops(self):
        guard = NativeModelTaskGuard(SESSION)
        self.feed(guard, [row(1)])
        value = row(2, "side_effect_intent")
        value["payload"]["command_id"] = OTHER
        value["payload"]["run_stream"]["id"] = OTHER
        self.feed(guard, [value])
        self.assertTrue(guard.stop_requested)

    def test_known_reference_before_lifecycle_cannot_switch_run(self):
        guard = NativeModelTaskGuard(SESSION)
        value = row(1)
        value["payload_type"] = "session.run.linked"
        value["payload"] = {"kind": "session_run_linked", "run_stream": {"kind": "run", "id": OTHER}}
        self.feed(guard, [value, row(2)])
        self.assertTrue(guard.stop_requested)

    def test_optional_scalar_bindings_at_all_known_locations(self):
        for location in ("row", "payload", "event", "nested"):
            for field, expected in (("run_id", RUN), ("session_id", SESSION), ("task_id", TASK)):
                for value in (expected, OTHER, True, 3, 1.5, None, {}, [], "é" * 129):
                    with self.subTest(location=location, field=field, value=value):
                        item = row(1)
                        target = item if location == "row" else item["payload"] if location == "payload" else item["payload"]["event"]
                        if location == "nested":
                            target["details"] = {"binding": {field: value}}
                        else:
                            target[field] = value
                        guard = NativeModelTaskGuard(SESSION)
                        self.feed(guard, [item])
                        self.assertEqual(guard.summary()["protocol_valid"], value == expected)

    def test_earlier_scalar_run_binding_pins_pending_identity(self):
        for field in ("command_id", "run_id"):
            for nested in (False, True):
                with self.subTest(field=field, nested=nested):
                    first = row(1)
                    first["payload_type"] = "session.metadata"
                    first["payload"] = {"kind": "metadata"}
                    if nested:
                        first["payload"]["details"] = {field: OTHER}
                    else:
                        first["payload"][field] = OTHER
                    guard = NativeModelTaskGuard(SESSION)
                    self.feed(guard, [first, row(2)])
                    self.assertTrue(guard.stop_requested)
                    self.assertFalse(guard.summary()["protocol_valid"])

    def test_consistent_earlier_scalar_run_binding_is_allowed(self):
        first = row(1)
        first["payload_type"] = "session.metadata"
        first["payload"] = {"kind": "metadata", "command_id": RUN, "run_id": RUN, "session_id": SESSION}
        guard = NativeModelTaskGuard(SESSION)
        self.feed(guard, [first, row(2)])
        self.assertFalse(guard.stop_requested)

    def test_sequence_gaps_reorder_duplicates_and_bool_are_invalid(self):
        for sequence in (0, 2, -1, True, 1.0, "1"):
            with self.subTest(sequence=sequence):
                guard = NativeModelTaskGuard(SESSION)
                value = row(sequence)
                self.feed(guard, [value])
                self.assertTrue(guard.stop_requested)
        guard = NativeModelTaskGuard(SESSION)
        self.feed(guard, [row(1), row(1)])
        self.assertTrue(guard.stop_requested)

    def test_known_field_types_do_not_accept_decimal_coercion_or_bool(self):
        for field in ("schema_version", "payload_schema_version"):
            for value in (True, 1.0, "1"):
                with self.subTest(field=field, value=value):
                    guard = NativeModelTaskGuard(SESSION)
                    item = row(1)
                    item[field] = value
                    self.feed(guard, [item])
                    self.assertTrue(guard.stop_requested)
        for value in (1.5, True, [], {}, None):
            with self.subTest(identifier=value):
                guard = NativeModelTaskGuard(SESSION)
                item = row(1)
                item["payload"]["task_id"] = value
                self.feed(guard, [item])
                self.assertTrue(guard.stop_requested)

    def test_phase_reorder_duplicate_and_activity_after_terminal_stop(self):
        for values in ([row(1, "started")], [row(1, "side_effect_intent")],
                       [row(1), row(2)], [row(1), row(2, "side_effect_intent"), row(3, "side_effect_intent")],
                       start_rows() + [row(4, "started")],
                       start_rows() + [row(4, "completed"), row(5, "status")]):
            with self.subTest(values=values):
                guard = NativeModelTaskGuard(SESSION)
                self.feed(guard, values)
                self.assertTrue(guard.stop_requested)

    def test_unknown_lifecycle_and_model_kind_stop(self):
        for value in (row(1, "new_status"), row(1, task_kind="model.unrecognized.response")):
            guard = NativeModelTaskGuard(SESSION)
            self.feed(guard, [value])
            self.assertTrue(guard.stop_requested)

    def test_hidden_known_markers_are_not_ignored(self):
        for hidden in ({"kind": "task_lifecycle"}, {"payload_type": "task.lifecycle.started"},
                       {"task_kind": MODEL}, {"operation": MODEL},
                       {"kind": "started", "task_id": SECOND},
                       {"run_stream": {"kind": "run", "id": OTHER}},
                       {"command_id": OTHER}, {"session_stream": {"kind": "session", "id": OTHER}}):
            with self.subTest(hidden=hidden):
                guard = NativeModelTaskGuard(SESSION)
                value = row(1)
                value["payload"]["event"]["details"] = {"nested": [hidden]}
                self.feed(guard, [value])
                self.assertTrue(guard.stop_requested)

    def test_hidden_foreign_task_stream_stops(self):
        guard = NativeModelTaskGuard(SESSION)
        value = row(1)
        value["payload"]["event"]["details"] = {"task_stream": {"kind": "task", "id": SECOND}}
        self.feed(guard, [value])
        self.assertTrue(guard.stop_requested)

    def test_ordinary_metadata_and_completed_session_wrapper_are_allowed(self):
        guard = NativeModelTaskGuard(SESSION)
        values = start_rows() + [row(4, "completed")]
        metadata = row(5)
        metadata["payload_type"] = "session.metadata"
        metadata["payload"] = {"kind": "metadata", "record": {"elapsed": 0.5}}
        terminal = row(6)
        terminal["payload_type"] = "run.terminal.completed"
        terminal["payload"] = {"kind": "run_terminal", "command_id": RUN,
                               "run_stream": {"kind": "run", "id": RUN},
                               "terminal": "completed", "text": "synthetic completed answer"}
        self.feed(guard, values + [metadata, terminal])
        self.assertFalse(guard.stop_requested)

    def test_hidden_model_event_under_nonlifecycle_header_stops(self):
        guard = NativeModelTaskGuard(SESSION)
        value = row(1)
        value["payload_type"] = "session.metadata"
        value["payload"]["kind"] = "metadata"
        self.feed(guard, [value])
        self.assertTrue(guard.stop_requested)

    def test_literal_messages_not_interpreted_or_retained(self):
        guard = NativeModelTaskGuard(SESSION)
        values = start_rows() + [row(4, "status")]
        private = 'synthetic private message {"task_kind":"model.meta.response"}'
        values[-1]["payload"]["event"].update(message=private, details={"note": private})
        summary = self.feed(guard, values)
        self.assertFalse(guard.stop_requested)
        self.assertNotIn(private, json.dumps(summary))
        self.assertNotIn(TASK, json.dumps(summary))

    def test_summary_is_small_detached_and_honest(self):
        guard = NativeModelTaskGuard(SESSION)
        self.feed(guard, start_rows())
        value = guard.summary()
        self.assertLess(len(canonical_bytes(value)), 4096)
        self.assertFalse(value["hard_native_attempt_limit_enforced"])
        self.assertFalse(value["native_activity_exhaustive"])
        self.assertFalse(value["new_dispatch_authorized"])
        self.assertEqual(value["paid_call_count"], "unknown")
        self.assertEqual(value["remote_usage"], "unknown")
        value["model_tasks_started"] = 900
        self.assertEqual(guard.summary()["model_tasks_started"], 1)

    def test_malformed_json_duplicate_keys_utf8_and_nonfinite_stop_without_throw(self):
        samples = (b"{", raw(row(1))[:-1] + b',"sequence":1}', b"\xff", b"{}\n{}", b"",
                   b'{"x":NaN}', b'{"x":"\\ud800"}', b"[]", "not bytes", None)
        for sample in samples:
            with self.subTest(sample=sample):
                guard = NativeModelTaskGuard(SESSION)
                self.assertIsNone(guard.observe(sample))
                self.assertTrue(guard.stop_requested)

    def test_valid_utf8_identifier_and_byte_bound(self):
        guard = NativeModelTaskGuard(SESSION)
        identifier = "é" * 128
        self.feed(guard, [row(1, task=identifier)])
        self.assertFalse(guard.stop_requested)
        guard = NativeModelTaskGuard(SESSION)
        self.feed(guard, [row(1, task=identifier + "é")])
        self.assertTrue(guard.stop_requested)

    def test_record_cap_sticky_and_flood_counters_saturate(self):
        guard = NativeModelTaskGuard(SESSION, max_records=1)
        self.feed(guard, [row(1), row(2, "side_effect_intent")])
        for _ in range(1000):
            guard.observe(raw(row(3, "started")))
        summary = guard.summary()
        self.assertTrue(summary["record_limited"])
        self.assertEqual(summary["records_observed"], 2)
        self.assertEqual(summary["first_stop_cause"], "record_limit")

    def test_frame_exact_bound_and_overflow(self):
        frame = raw(row(1))
        guard = NativeModelTaskGuard(SESSION, max_frame_bytes=len(frame))
        guard.observe(frame)
        self.assertFalse(guard.stop_requested)
        guard = NativeModelTaskGuard(SESSION, max_frame_bytes=len(frame) - 1)
        guard.observe(frame)
        self.assertTrue(guard.stop_requested)

    def test_task_metadata_flood_bounded(self):
        guard = NativeModelTaskGuard(SESSION)
        for i in range(1, 300):
            guard.observe(raw(row(i, task="synthetic-task-" + str(i), task_kind="session_name.allocate")))
        summary = guard.summary()
        self.assertTrue(summary["task_metadata_limited"])
        self.assertEqual(summary["tracked_tasks"], 256)
        self.assertEqual(summary["model_tasks_observed"], 0)

    def test_parser_depth_and_node_bounds(self):
        for extra in ([[]] * 4097, [[0] * 4096] * 17):
            guard = NativeModelTaskGuard(SESSION)
            value = row(1)
            value["payload"]["event"]["details"] = extra
            guard.observe(raw(value))
            self.assertTrue(guard.stop_requested)
        extra = {}
        for _ in range(65):
            extra = {"nested": extra}
        guard = NativeModelTaskGuard(SESSION)
        value = row(1)
        value["payload"]["event"]["details"] = extra
        guard.observe(raw(value))
        self.assertTrue(guard.stop_requested)

    def test_callback_exception_never_escapes(self):
        guard = NativeModelTaskGuard(SESSION)
        with patch.object(lifecycle, "_parse", side_effect=RuntimeError("synthetic private parser failure")):
            self.assertIsNone(guard.observe(raw(row(1))))
        self.assertTrue(guard.stop_requested)
        self.assertNotIn("private", json.dumps(guard.summary()))

    def test_invalid_constructor_parameters(self):
        for kwargs in ({"max_records": True}, {"max_records": 0}, {"max_records": 131073},
                       {"max_frame_bytes": False}, {"max_frame_bytes": 0}, {"max_frame_bytes": 16777217}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                NativeModelTaskGuard(SESSION, **kwargs)
        for session in (None, True, "", "\n", "é" * 129):
            with self.subTest(session=session), self.assertRaises(ValueError):
                NativeModelTaskGuard(session)


if __name__ == "__main__":
    unittest.main()
