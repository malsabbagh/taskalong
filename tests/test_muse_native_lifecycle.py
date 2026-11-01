"""Synthetic native wrappers only: no provider, process, account or operator State."""
import copy
import json
import os
from pathlib import Path
import tempfile
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


def status_details(phase):
    """Public protocol shapes with wholly invented diagnostic values."""
    if phase == "retrying":
        return {"phase": phase, "facets": [{"kind": "external_attempt", "system": "turn",
            "operation": "retry", "attempt": 1, "next_attempt": 2, "max_attempts": 10,
            "retry_delay_ms": 1, "error_kind": "model_stream_idle_timeout"}]}
    attempt = {"kind": "external_attempt", "system": "meta", "operation": "model.response",
               "attempt": 1, "max_attempts": 10}
    producer = {"kind": "provider", "provider": "meta"}
    if phase in {"stream_cancelled", "stream_succeeded"}:
        attempt["error_kind"] = phase
        producer.update(request_id="synthetic-request", response_id="synthetic-response", model="synthetic-model",
            stream={"bytes_read": 1, "wire_events_seen": 1, "last_wire_event_type": "keepalive",
                    "eof": False, "eof_buffer_len": 0, "time_to_first_event_ms": 1, "bytes_before_first_event": 0})
    return {"phase": phase, "facets": [attempt, {"kind": "producer", "detail": producer}]}


def complete_native_rows():
    """All 22 observed record shapes, without retained source text or identities."""
    def metadata(sequence, kind, payload):
        value = row(sequence)
        value.update(payload_type=kind, payload=payload)
        return value
    binding = {"command_id": RUN, "run_stream": {"kind": "run", "id": RUN}}
    values = [metadata(1, "runtime.command.accepted", {"kind": "command_accepted", "command_id": RUN,
                   "client_id": None, "command_kind": "run"}),
              metadata(2, "session.run.linked", {"kind": "session_run_linked", **binding}),
              metadata(3, "run.model.configured", {"kind": "run_model_configured", **binding,
                  "provider_id": "meta", "profile_id": "synthetic", "model_id": "synthetic-model",
                  "display_label": "Synthetic model", "source": "synthetic"}),
              metadata(4, "turn.input.user", {"kind": "turn_input_user", **binding, "prompt": "Synthetic input.\n"}),
              metadata(5, "run.lifecycle.started", {"kind": "run_started", **binding, "prompt": "Synthetic input.\n"})]
    for task in (TASK, SECOND):
        values.append(metadata(len(values) + 1, "task.stream.linked", {"kind": "task_stream_linked", **binding,
            "task_id": task, "task_stream": {"kind": "task", "id": task}}))
        for kind in ("proposed", "accepted", "scheduled", "side_effect_intent", "started"):
            value = row(len(values) + 1, kind, task)
            if kind in {"scheduled", "side_effect_intent"}:
                value["payload"]["event"]["idempotency_key"] = "synthetic-key"
            if kind == "side_effect_intent":
                value["payload"]["event"].update(policy_decision="synthetic-policy", cancellation_handle=None, parent_task_id=None)
            values.append(value)
        for phase in (("opening_stream", "stream_cancelled", "retrying") if task == TASK else ("opening_stream",)):
            value = row(len(values) + 1, "status", task)
            value["payload"]["event"].update(message="Synthetic status.", details=status_details(phase))
            values.append(value)
        if task == TASK:
            values.append(row(len(values) + 1, "timed_out", task))
    for value in values:
        sequence = value["sequence"]
        value.update(id=OTHER, recorded_at=sequence, causation_id=OTHER,
            record_type="reconciliation" if sequence == 1 else "status" if sequence == 4 else "event",
            durability="ephemeral" if sequence == 4 else "durable")
    return values


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

    def test_complete_native_grammar_preserves_timeout_and_queued_second_start(self):
        values = complete_native_rows()
        self.assertEqual(len(values), 22)
        guard = NativeModelTaskGuard(SESSION)
        summary = self.feed(guard, values)
        self.assertTrue(summary["protocol_valid"])
        self.assertEqual(summary["records_observed"], 22)
        self.assertEqual(summary["first_stop_cause"], "model_task_timed_out")
        self.assertEqual(summary["first_stop_sequence"], 15)
        self.assertEqual(summary["model_tasks_observed"], 2)
        self.assertEqual(summary["model_tasks_started"], 2)
        self.assertEqual(summary["paid_call_count"], "unknown")
        self.assertFalse(summary["hard_native_attempt_limit_enforced"])

    def test_status_retry_descriptor_does_not_replace_actual_second_task_stop(self):
        values = complete_native_rows()
        values[14]["payload_type"] = "task.lifecycle.completed"
        values[14]["payload"]["event"]["kind"] = "completed"
        guard = NativeModelTaskGuard(SESSION)
        summary = self.feed(guard, values)
        self.assertTrue(summary["protocol_valid"])
        self.assertEqual(summary["first_stop_cause"], "second_model_task_observed")
        self.assertEqual(summary["first_stop_sequence"], 17)
        self.assertEqual(summary["model_tasks_started"], 2)

    def test_bounded_model_status_descriptors_do_not_invent_task_starts(self):
        for phase in ("opening_stream", "stream_cancelled", "stream_succeeded"):
            for attempt, maximum in ((1, 1), (1, 10), (2, 10), (10, 10)):
                item = row(4, "status")
                item["payload"]["event"]["details"] = status_details(phase)
                item["payload"]["event"]["details"]["facets"][0].update(attempt=attempt, max_attempts=maximum)
                guard = NativeModelTaskGuard(SESSION)
                with self.subTest(phase=phase, attempt=attempt, maximum=maximum):
                    summary = self.feed(guard, start_rows() + [item])
                    self.assertTrue(summary["protocol_valid"])
                    self.assertFalse(guard.stop_requested)
                    self.assertEqual(summary["model_tasks_started"], 1)

    def test_status_descriptor_exemption_is_closed_typed_and_path_specific(self):
        mutations = [lambda d: d.update(phase="unknown"), lambda d: d.update(response={}),
            lambda d: d["facets"][0].update(system="other"),
            lambda d: d["facets"][0].update(operation="model.meta.response"),
            lambda d: d["facets"][0].update(operation="model.other"),
            lambda d: d["facets"][0].update(operation=False), lambda d: d["facets"][0].update(operation=None),
            lambda d: d["facets"][0].update(operation="retry"), lambda d: d["facets"][0].pop("operation"),
            lambda d: d["facets"][0].update(attempt=False), lambda d: d["facets"][0].update(attempt=0),
            lambda d: d["facets"][0].update(attempt=11), lambda d: d["facets"][0].update(max_attempts=11),
            lambda d: d["facets"][0].update(attempt=2, max_attempts=1),
            lambda d: d["facets"][0].update(max_attempts=0), lambda d: d["facets"][0].update(max_attempts=1.5),
            lambda d: d["facets"].reverse(), lambda d: d["facets"].append({}),
            lambda d: d.update(nested=d.pop("facets")),
            lambda d: d["facets"][1]["detail"].update(provider="other"),
            lambda d: d["facets"][1]["detail"].update(response={})]
        for mutate in mutations:
            details = status_details("opening_stream"); mutate(details)
            item = row(4, "status"); item["payload"]["event"]["details"] = details
            guard = NativeModelTaskGuard(SESSION)
            with self.subTest(details=details):
                self.assertFalse(self.feed(guard, start_rows() + [item])["protocol_valid"])

    def test_status_descriptors_do_not_hide_activity_results_or_foreign_references(self):
        for phase in ("opening_stream", "stream_cancelled", "stream_succeeded"):
            for location in ("details", "facet", "producer", "stream"):
                if location == "stream" and phase == "opening_stream":
                    continue
                for extra in ({"kind": "task_lifecycle", "task_id": SECOND},
                              {"kind": "run_terminal", "terminal": "completed"}, {"response": {}},
                              {"run_id": OTHER}, {"session_id": OTHER}, {"command_id": OTHER},
                              {"task_id": SECOND}, {"operation": "model.meta.response"}):
                    details = status_details(phase)
                    target = details if location == "details" else details["facets"][0] if location == "facet" else details["facets"][1]["detail"]
                    if location == "stream": target = target["stream"]
                    target["hidden"] = extra
                    item = row(4, "status"); item["payload"]["event"]["details"] = details
                    guard = NativeModelTaskGuard(SESSION)
                    with self.subTest(phase=phase, location=location, extra=extra):
                        self.assertFalse(self.feed(guard, start_rows() + [item])["protocol_valid"])

    def test_stream_status_metadata_has_finite_strict_scalar_types(self):
        for key in ("bytes_read", "wire_events_seen", "eof_buffer_len", "time_to_first_event_ms", "bytes_before_first_event"):
            for invalid in (False, -1, 1.5, None, "1", 2**53):
                details = status_details("stream_cancelled")
                details["facets"][1]["detail"]["stream"][key] = invalid
                item = row(4, "status"); item["payload"]["event"]["details"] = details
                with self.subTest(key=key, value=invalid):
                    self.assertFalse(self.feed(NativeModelTaskGuard(SESSION), start_rows() + [item])["protocol_valid"])
        for key, values in (("request_id", (None, False, "", "x" * 257)),
                            ("response_id", ({}, [], "\ud800")), ("model", (0, "x\n"))):
            for invalid in values:
                details = status_details("stream_cancelled"); details["facets"][1]["detail"][key] = invalid
                item = row(4, "status"); item["payload"]["event"]["details"] = details
                # ASCII escaping keeps a malformed surrogate a parser input.
                guard = NativeModelTaskGuard(SESSION)
                for value in start_rows(): guard.observe(raw(value))
                guard.observe(json.dumps(item, ensure_ascii=True).encode())
                with self.subTest(key=key, value=repr(invalid)):
                    self.assertFalse(guard.summary()["protocol_valid"])
        for key, invalid in (("eof", 0), ("last_wire_event_type", None), ("last_wire_event_type", "x" * 257)):
            details = status_details("stream_cancelled"); details["facets"][1]["detail"]["stream"][key] = invalid
            item = row(4, "status"); item["payload"]["event"]["details"] = details
            self.assertFalse(self.feed(NativeModelTaskGuard(SESSION), start_rows() + [item])["protocol_valid"])

    def test_model_status_descriptor_requires_started_bound_model_task(self):
        for prefix in ([row(1)], [row(1), row(2, "accepted")], start_rows() + [row(4, "completed")],
                       [row(1, task_kind="session_name.allocate"), row(2, "started", task_kind="session_name.allocate")]):
            item = row(len(prefix) + 1, "status")
            item["payload"]["event"]["details"] = status_details("opening_stream")
            with self.subTest(prefix=prefix):
                self.assertFalse(self.feed(NativeModelTaskGuard(SESSION), prefix + [item])["protocol_valid"])

    @unittest.skipUnless(os.name == "posix", "Private descriptor capture requires POSIX")
    def test_complete_synthetic_grammar_passes_all_interrupted_capture_gates(self):
        from taskalong.local_provider_capture import PrivateCapture
        from taskalong.muse_interrupted_recovery import _capture
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); root.chmod(0o700)
            capture = PrivateCapture(root / "capture", schema_version="2.0", max_output_bytes=64 * 1048576, max_records=8192)
            try:
                capture.write("stdout", b"".join(raw(value) + b"\n" for value in complete_native_rows()))
            finally:
                capture.close()
            native_run, summary = _capture(root, {"max_output_bytes": 64 * 1048576}, SESSION)
        self.assertEqual(native_run, RUN)
        self.assertEqual(summary["records_observed"], 22)
        self.assertEqual(summary["status"], "incomplete")
        self.assertFalse(summary["byte_closure"])
        self.assertFalse(summary["observed_counts_complete"])
        self.assertTrue(summary["native_lifecycle"]["protocol_valid"])
        self.assertEqual(summary["native_lifecycle"]["first_stop_sequence"], 15)
        self.assertEqual(summary["native_lifecycle"]["model_tasks_started"], 2)

    def test_native_accepted_scheduled_metadata_prefix_before_model_intent(self):
        # Corpus-free reproduction of the demonstrated native wrapper/order.
        accepted_command = row(1)
        accepted_command["payload_type"] = "runtime.command.accepted"
        accepted_command["payload"] = {"kind": "command_accepted", "command_id": RUN}
        linked = row(2)
        linked["payload_type"] = "session.run.linked"
        linked["payload"] = {"kind": "session_run_linked", "command_id": RUN,
                             "run_stream": {"kind": "run", "id": RUN}}
        guard = NativeModelTaskGuard(SESSION)
        summary = self.feed(guard, [accepted_command, linked, row(3), row(4, "accepted"),
                                    row(5, "scheduled"), row(6, "side_effect_intent"), row(7, "started")])
        self.assertTrue(summary["protocol_valid"])
        self.assertFalse(guard.stop_requested)
        self.assertEqual(summary["model_tasks_observed"], 1)
        self.assertEqual(summary["model_tasks_proposed"], 1)
        self.assertEqual(summary["model_tasks_side_effect_intent"], 1)
        self.assertEqual(summary["model_tasks_started"], 1)

    def test_accepted_scheduled_status_and_completion_preserve_single_model(self):
        for kinds in (("proposed", "accepted", "side_effect_intent", "started", "completed"),
                      ("proposed", "accepted", "status", "scheduled", "status", "side_effect_intent", "started", "completed")):
            with self.subTest(kinds=kinds):
                guard = NativeModelTaskGuard(SESSION)
                summary = self.feed(guard, [row(i, kind) for i, kind in enumerate(kinds, 1)])
                self.assertTrue(summary["protocol_valid"])
                self.assertFalse(guard.stop_requested)
                self.assertEqual(summary["model_tasks_observed"], 1)
                self.assertEqual(summary["model_tasks_started"], 1)

    def test_nonmodel_accepted_scheduled_does_not_count_as_model_task(self):
        guard = NativeModelTaskGuard(SESSION)
        summary = self.feed(guard, [row(i, kind, OTHER, task_kind="session_name.allocate")
                                    for i, kind in enumerate(("proposed", "accepted", "scheduled", "started", "completed"), 1)])
        self.assertTrue(summary["protocol_valid"])
        self.assertFalse(guard.stop_requested)
        self.assertEqual(summary["model_tasks_observed"], 0)

    def test_accepted_scheduled_duplicates_reordering_and_missing_intent_refuse(self):
        invalid = [("accepted",), ("scheduled",), ("proposed", "scheduled"),
                   ("proposed", "accepted", "accepted"),
                   ("proposed", "accepted", "scheduled", "accepted"),
                   ("proposed", "accepted", "scheduled", "scheduled"),
                   ("proposed", "side_effect_intent", "accepted"),
                   ("proposed", "side_effect_intent", "started", "scheduled"),
                   ("proposed", "accepted", "scheduled", "started"),
                   ("proposed", "accepted", "scheduled", "side_effect_intent", "started", "completed", "accepted")]
        for kinds in invalid:
            with self.subTest(kinds=kinds):
                guard = NativeModelTaskGuard(SESSION)
                summary = self.feed(guard, [row(i, kind) for i, kind in enumerate(kinds, 1)])
                self.assertFalse(summary["protocol_valid"])
                self.assertTrue(guard.stop_requested)

    def test_accepted_scheduled_foreign_aliases_and_hidden_markers_refuse(self):
        for kind in ("accepted", "scheduled"):
            prefix = [row(1)] + ([row(2, "accepted")] if kind == "scheduled" else [])
            for location in ("row", "payload", "event", "nested"):
                for field, value in (("run_id", OTHER), ("session_id", OTHER), ("task_id", SECOND),
                                     ("run_id", True), ("session_id", None), ("task_id", 1.5)):
                    with self.subTest(kind=kind, location=location, field=field, value=value):
                        item = row(len(prefix) + 1, kind)
                        target = item if location == "row" else item["payload"] if location == "payload" else item["payload"]["event"]
                        if location == "nested":
                            target["details"] = {field: value}
                        else:
                            target[field] = value
                        guard = NativeModelTaskGuard(SESSION)
                        summary = self.feed(guard, prefix + [item])
                        self.assertFalse(summary["protocol_valid"])
            guard = NativeModelTaskGuard(SESSION)
            item = row(len(prefix) + 1, kind)
            item["payload"]["event"]["details"] = {"kind": kind, "task_id": TASK}
            self.feed(guard, prefix + [item])
            self.assertFalse(guard.summary()["protocol_valid"])

    def test_accepted_scheduled_then_timeout_and_queued_second_keep_first_stop(self):
        kinds = ("proposed", "accepted", "scheduled", "side_effect_intent", "started", "timed_out")
        values = [row(i, kind) for i, kind in enumerate(kinds, 1)]
        values += [row(i, kind, SECOND) for i, kind in enumerate(kinds[:-1], 7)]
        guard = NativeModelTaskGuard(SESSION)
        summary = self.feed(guard, values)
        self.assertEqual(summary["first_stop_cause"], "model_task_timed_out")
        self.assertEqual(summary["first_stop_sequence"], 6)
        self.assertTrue(summary["protocol_valid"])
        self.assertEqual(summary["model_tasks_observed"], 2)
        self.assertEqual(summary["model_tasks_started"], 2)

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
