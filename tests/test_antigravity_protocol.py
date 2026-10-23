"""Original Antigravity fixture contracts; installed vendor behavior is unqualified."""
from dataclasses import FrozenInstanceError
import hashlib
from importlib import resources
import json
from pathlib import Path
import unittest
import uuid

from jsonschema import Draft202012Validator

from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes, loads, schema, schema_names, seal_versioned


def example_agy_config():
    return {
        "driver_id": "antigravity-cli", "driver_version": "agy-headless-fixture-1",
        "projection": "antigravity-headless-fixture/1", "wire_version": "2.6",
        "installation_digest": "a" * 64, "provider_profile_digest": "b" * 64,
        "qualification": "synthetic", "registration": "operator_registered_fixture",
        "executable": {"path": "/opt/taskalong/fixture-agy", "sha256": "c" * 64},
        "credential_ref": "fixture-google-account", "expected_reported_model": "fixture-agy-model",
        "policy_digests": {"instructions": "d" * 64, "tools": "e" * 64,
                           "worker_sandbox": "f" * 64, "check_binding": "1" * 64},
        "launch": {"mode": "headless", "input_format": "stream-json", "output_format": "stream-json",
                   "session_policy": "fresh", "input_framing": "agy-user-ndjson/1", "print_timeout_seconds": 30},
    }


def agy_packet():
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
        "projection": "antigravity-headless-fixture/1", "session_policy": "fresh", "allowed_tools": ["write_file"],
    }, version="2.6")


def agy_worker(packet):
    return {"kind": "worker_result", "schema_version": "2.5", "extensions": {},
        "result_id": str(uuid.uuid4()), "packet_id": packet["packet_id"], "packet_digest": packet["digest"],
        "run_id": packet["run_id"], "attempt_id": packet["attempt_id"], "spec_digest": packet["spec_digest"],
        "driver_config_digest": packet["bindings"]["driver_config_digest"],
        "provider_profile_digest": packet["bindings"]["provider_profile_digest"],
        "status": "completed", "changed_files": [], "command_claims": [], "summary": "Synthetic Antigravity result.",
        "blockers": [], "deviations": [], "residual_risks": [], "qualification": "synthetic"}


class AntigravityContractTests(unittest.TestCase):
    def test_explicit_family_reuses_neutral_result_without_changing_shipped_resources(self):
        self.assertEqual(schema_names(version="2.6"),
                         ("driver-config", "task-spec", "worker-packet", "packet-projection"))
        for name in schema_names(version="2.6"):
            value = schema(name, version="2.6")
            self.assertEqual(value["$id"], "urn:taskalong:schema:v2.6:" + name)
            Draft202012Validator.check_schema(value)
        with self.assertRaises(TaskAlongError) as result_family:
            schema("worker-result", version="2.6")
        self.assertEqual(result_family.exception.code, "unknown_schema")
        self.assertEqual(agy_packet()["result_schema_id"], "urn:taskalong:schema:v2.5:worker-result")
        prior = json.loads((Path(__file__).parent / "fixtures/m7-contract-hashes.json").read_text())
        self.assertEqual(len(prior), 48)
        for path, expected in prior.items():
            actual = resources.files("taskalong.resources").joinpath(path.removeprefix("src/taskalong/resources/")).read_bytes()
            self.assertEqual(hashlib.sha256(actual).hexdigest(), expected, path)

    def test_reader_is_immutable_and_refuses_foreign_or_unbounded_launch_options(self):
        from taskalong.execution import read_task_spec, AntigravityTaskSpec
        from taskalong.executors.config import AntigravityDriverConfig, CursorDriverConfig, read_driver_config
        from test_contracts import example_spec
        value = seal_versioned("driver-config", example_agy_config(), version="2.6")
        config = read_driver_config(value)
        self.assertIsInstance(config, AntigravityDriverConfig)
        before = config.to_bytes()
        value["launch"]["session_policy"] = "continue"
        self.assertEqual(config.to_bytes(), before)
        with self.assertRaises(FrozenInstanceError):
            config._canonical = b"{}"
        with self.assertRaises(TaskAlongError):
            CursorDriverConfig.from_dict(config.to_dict())
        task = seal_versioned("task-spec", example_spec() | {"schema_version": "2.6", "execution": {
            "binding_digest": "a" * 64, "driver_config_digest": config.digest}}, version="2.6")
        self.assertIsInstance(read_task_spec(task), AntigravityTaskSpec)
        for change in ({"session_policy": "continue"}, {"extra_args": ["--dangerously-skip-permissions"]},
                       {"print_timeout_seconds": 0}, {"print_timeout_seconds": True},
                       {"input_framing": "text"}, {"print_timeout_seconds": 301}):
            with self.subTest(change=change), self.assertRaises(TaskAlongError):
                seal_versioned("driver-config", example_agy_config() | {
                    "launch": example_agy_config()["launch"] | change}, version="2.6")


class AntigravityProtocolTests(unittest.TestCase):
    def setUp(self):
        self.packet = agy_packet()
        self.worker = agy_worker(self.packet)
        self.conversation = str(uuid.uuid4())
        self.model, self.cwd = "fixture-agy-model", "/synthetic-workspace"
        self.init = {"type": "init", "conversation_id": self.conversation, "model": self.model,
                     "tools": ["write_file"], "permission_mode": "request-review", "cwd": self.cwd,
                     "json_schema": schema("worker-result", version="2.5"), "agent": "fixture-agent"}
        self.terminal = {"type": "result", "conversation_id": self.conversation,
                         "status": "SUCCESS", "num_turns": 1, "structured_output": self.worker}

    def wire(self, *events):
        return b"".join((json.dumps(value, ensure_ascii=False) + "\n").encode() for value in events)

    def decoder(self, **limits):
        from taskalong.executors.antigravity_protocol import AntigravityStreamDecoder
        return AntigravityStreamDecoder(self.packet, expected_model=self.model, expected_cwd=self.cwd, **limits)

    def step(self, index=7, status="DONE", **changes):
        return {"type": "step_update", "conversation_id": self.conversation, "step": {
            "index": index, "kind": "tool", "status": status, "tool": "write_file", "tool_info": {
                "name": "write_file", "parameters": {"path": "arithmetic.py"}, "error": None,
                "permission_denied": False}, **changes}}

    def expect_failure(self, events, code=None, *, exit_code=0, **limits):
        decoder = self.decoder(**limits)
        with self.assertRaises(TaskAlongError) as failure:
            decoder.feed(self.wire(*events))
            decoder.finish(exit_code=exit_code)
        if code:
            self.assertEqual(failure.exception.code, code)
        self.assertEqual(failure.exception.effect_outcome, "uncertain")

    def test_fresh_conversation_and_whole_neutral_result_are_observed_without_injection(self):
        raw = self.wire(self.init, self.step(), self.terminal)
        decoder = self.decoder()
        for offset in range(0, len(raw), 7):
            decoder.feed(raw[offset:offset + 7])
        turn = decoder.finish(exit_code=0)
        self.assertEqual(turn.session_id, self.conversation)
        self.assertNotEqual(turn.session_id, self.packet["attempt_id"])
        self.assertEqual(loads(turn.worker_result_json), self.worker)
        self.assertNotIn("session_id", self.worker)
        self.assertEqual((turn.wire_sha256, turn.wire_bytes, turn.frames), (hashlib.sha256(raw).hexdigest(), len(raw), 3))
        self.assertEqual(turn.observation()["native_session_kind"], "conversation")
        self.assertEqual(turn.observation()["observed_session_id"], self.conversation)
        self.assertIsNone(loads(turn.reported_usage_json)["input_tokens"])

    def test_init_identity_and_every_result_binding_are_required(self):
        for field, value in {"model": "other", "tools": [], "permission_mode": "auto",
                             "cwd": "/other", "json_schema": {}, "agent": "default"}.items():
            with self.subTest(field=field):
                self.expect_failure([self.init | {field: value}, self.terminal], "agy_init_mismatch")
        self.expect_failure([self.init, self.init, self.terminal], "agy_duplicate_init")
        self.expect_failure([self.terminal], "agy_init_required")
        self.expect_failure([self.init | {"conversation_id": "bad"}], "agy_conversation_invalid")
        for field in ("packet_id", "run_id", "attempt_id"):
            self.expect_failure([self.init | {"conversation_id": self.packet[field]}], "agy_conversation_conflict")
        self.expect_failure([self.init, self.terminal | {"conversation_id": str(uuid.uuid4())}], "agy_conversation_mismatch")
        for field in ("packet_id", "run_id", "attempt_id", "spec_digest", "packet_digest",
                      "driver_config_digest", "provider_profile_digest", "qualification"):
            value = str(uuid.uuid4()) if field.endswith("_id") else "f" * 64
            if field == "qualification":
                value = "production"
            with self.subTest(binding=field):
                self.expect_failure([self.init, self.terminal | {"structured_output": self.worker | {field: value}}])

    def test_step_indices_allow_gaps_and_done_without_active_but_never_change_identity(self):
        decoder = self.decoder()
        decoder.feed(self.wire(self.init, self.step(index=17), self.step(index=2, status="ACTIVE"),
                               self.step(index=2), self.terminal))
        self.assertEqual(decoder.finish(exit_code=0).frames, 5)
        for events in ([self.step(), self.step()], [self.step(), self.step(status="ACTIVE")],
                       [self.step(status="ACTIVE")],
                       [self.step(status="ACTIVE"), self.step(kind="text", content="different")]):
            with self.subTest(events=events):
                self.expect_failure([self.init, *events, self.terminal])
        for value in (-1, True, 65536, [], None):
            self.expect_failure([self.init, self.step(index=value), self.terminal], "agy_step_invalid")
        for value in ([], {}, "UNKNOWN"):
            self.expect_failure([self.init, self.step(kind=value), self.terminal], "agy_step_invalid")

    def test_denial_and_unknown_tool_shapes_are_sticky_even_before_success(self):
        for change in ({"error": "denied"}, {"permission_denied": True}, {"permission_denied": 0},
                       {"name": "shell"}, {"parameters": {"path": "outside.py"}}, {"remote_job": "job"}):
            event = self.step(tool_info=self.step()["step"]["tool_info"] | change)
            with self.subTest(change=change):
                decoder = self.decoder()
                with self.assertRaises(TaskAlongError) as first:
                    decoder.feed(self.wire(self.init, event, self.terminal))
                with self.assertRaises(TaskAlongError) as later:
                    decoder.feed(self.wire(self.terminal))
                self.assertIs(first.exception, later.exception)
                with self.assertRaises(TaskAlongError):
                    decoder.finish(exit_code=0)
        self.expect_failure([self.init, self.step(tool="shell"), self.terminal], "agy_tool_invalid")

    def test_only_the_exact_one_supplied_input_turn_is_admitted(self):
        def turn(index, content):
            return {"type": "step_update", "conversation_id": self.conversation, "step": {
                "index": index, "kind": "user_input", "status": "DONE", "content": content}}
        content = canonical_bytes(self.packet).decode()
        decoder = self.decoder()
        decoder.feed(self.wire(self.init, turn(3, content), self.terminal))
        decoder.finish(exit_code=0)
        self.expect_failure([self.init, turn(3, content), turn(4, content), self.terminal], "agy_extra_turn")
        self.expect_failure([self.init, turn(3, "continue"), self.terminal], "agy_extra_turn")
        self.expect_failure([self.init, {"type": "subagent", "conversation_id": self.conversation}, self.terminal],
                            "agy_event_unsupported")

    def test_result_never_falls_back_to_response_and_requires_successful_single_turn(self):
        for value in (None, [], json.dumps(self.worker), {}, "```json\n" + json.dumps(self.worker) + "\n```"):
            with self.subTest(output=value):
                self.expect_failure([self.init, self.terminal | {"structured_output": value,
                    "response": json.dumps(self.worker)}], "agy_result_invalid")
        for changes in ({"status": "CANCELED"}, {"status": "INTERRUPTED"}, {"status": "FAILURE"},
                        {"num_turns": True}, {"num_turns": 2}, {"error": "denied"}):
            self.expect_failure([self.init, self.terminal | changes], "agy_result_failed")
        for changes in ({"json_schema": {}}, {"response": {}}, {"extra": True},
                        {"structured_output": self.worker | {"session_id": self.conversation}}):
            self.expect_failure([self.init, self.terminal | changes], "agy_result_invalid")
        for field in self.worker:
            self.expect_failure([self.init, self.terminal | {"structured_output": {
                key: value for key, value in self.worker.items() if key != field}}], "agy_result_invalid")

    def test_usage_is_one_terminal_reported_snapshot_never_summed_or_inferred(self):
        decoder = self.decoder()
        decoder.feed(self.wire(self.init, self.step(usage={"input_tokens": 100, "output_tokens": 20}),
            self.terminal | {"usage": {"input_tokens": 110, "output_tokens": 25, "total_tokens": 135}}))
        usage = loads(decoder.finish(exit_code=0).reported_usage_json)
        self.assertEqual(usage, {"input_tokens": 110, "output_tokens": 25, "total_tokens": 135})
        decoder = self.decoder()
        decoder.feed(self.wire(self.init, self.step(usage={"input_tokens": 100}), self.terminal))
        self.assertEqual(loads(decoder.finish(exit_code=0).reported_usage_json),
                         {"input_tokens": None, "output_tokens": None, "total_tokens": None})
        for value in (-1, True, "1", None):
            for frame in (self.terminal | {"usage": {"input_tokens": value}},
                          self.step(usage={"input_tokens": value})):
                self.expect_failure([self.init, frame], "agy_usage_invalid")
        for value in ([], {"cost": 1}):
            self.expect_failure([self.init, self.terminal | {"usage": value}], "agy_usage_invalid")
        self.expect_failure([self.init, self.terminal | {"usage": {"input_tokens": 2**53}}], "agy_frame_invalid")

    def test_wire_is_bounded_strict_utf8_ndjson_with_no_trailing_or_duplicate_frames(self):
        self.expect_failure([self.init, self.terminal], "agy_exit_failed", exit_code=1)
        self.expect_failure([self.init], "agy_stream_incomplete")
        self.expect_failure([self.init, self.terminal, self.terminal], "agy_event_after_terminal")
        for raw in (b'{"type":"init","type":"init"}\n', b'\xff\n', b'[]\n', b'\n', b'{"type":NaN}\n'):
            with self.subTest(raw=raw), self.assertRaises(TaskAlongError):
                self.decoder().feed(raw)
        raw = self.wire(self.init, self.terminal)
        decoder = self.decoder()
        decoder.feed(raw[:-1])
        with self.assertRaises(TaskAlongError) as truncated:
            decoder.finish(exit_code=0)
        self.assertEqual(truncated.exception.code, "agy_truncated_frame")
        for limits, code in (({"max_output_bytes": 10}, "agy_output_limit"),
                             ({"max_line_bytes": 10}, "agy_line_limit"),
                             ({"max_frames": 1}, "agy_frame_limit")):
            with self.subTest(limits=limits), self.assertRaises(TaskAlongError) as failure:
                self.decoder(**limits).feed(raw)
            self.assertEqual(failure.exception.code, code)

    def test_schema_comparison_preserves_json_types_and_stream_depth_is_at_most_32(self):
        wrong_schema = loads(canonical_bytes(self.init["json_schema"]))
        self.assertIs(wrong_schema["additionalProperties"], False)
        wrong_schema["additionalProperties"] = 0
        self.expect_failure([self.init | {"json_schema": wrong_schema}, self.terminal], "agy_init_mismatch")
        deep = None
        for _ in range(33):
            deep = [deep]
        self.expect_failure([self.init, self.terminal | {"structured_output": self.worker | {
            "extensions": {"fixture:deep": deep}}}], "agy_frame_invalid")
