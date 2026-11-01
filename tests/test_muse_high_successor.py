"""Linked High corrections using disposable State and a synthetic existing owner."""
import copy
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from taskalong.api import RunService
from taskalong import muse_experimental as muse, muse_successor as successor
from taskalong import supervised_pilot as pilot
from taskalong.muse_effort_amendment import derive
from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes, digest
import test_muse_interrupted_recovery as interrupted_fixtures


def interrupted_fixture(effort="max"):
    # Keep this fixture class local: unittest must not rediscover its inherited
    # legacy test methods in addition to the focused journeys below.
    class OriginalEffortFixture(interrupted_fixtures.InterruptedSuccessorTests):
        def configure(self, **changes):
            self.c.request["reasoning_effort"] = effort
            return super().configure(**{"reasoning_effort": effort, **changes})
    fixture = OriginalEffortFixture()
    fixture.setUp()
    return fixture


@unittest.skipUnless(os.name == "posix", "Private local evidence requires POSIX")
class MuseHighSuccessorTests(unittest.TestCase):
    def setUp(self):
        self.fixture = interrupted_fixture()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.service, self.original = self.fixture.root, self.fixture.service, self.fixture.original
        self.store = self.service._store
        self.original_config = self.store.setting("provider:muse")
        self.original_manifest = json.loads((Path(self.original["bundle"]) / "bundle.json").read_bytes())
        self.high_config, self.high_manifest, self.amendment = derive(self.original_config, self.original_manifest, "high")
        self.assertEqual(self.original_config["reasoning_effort"], "max")
        self.assertEqual(self.original_manifest["request"]["reasoning_effort"], "max")
        old_invocation = json.loads((Path(self.original["output"]) / "invocation.json").read_bytes())
        self.assertEqual(old_invocation["argv"][old_invocation["argv"].index("--reasoning-effort") + 1], "max")

    def plan(self, service=None):
        return (service or self.service).provider_successor_plan(predecessor=self.original["run_id"], reason="interrupted-high")

    def execute(self, proof, *, key="high-replacement", service=None, reason="interrupted-high"):
        return (service or self.service).provider_successor(predecessor=self.original["run_id"], reason=reason,
            key=key, plan_digest=proof["digest"], output=str(self.root / key))

    def assert_original(self):
        self.fixture.c.assert_original()
        self.assertEqual(self.store.setting("provider:muse"), self.original_config)
        self.assertEqual(self.store.setting("provider-config:" + self.original_config["digest"]), self.original_config)

    def test_guard_rejects_malformed_requests_before_history_lookup(self):
        invalid = [None, False, [], "request", {"provider": "muse", "reasoning_effort": "high"}]
        for model in (None, False, [], {}, ""):
            invalid.append({**self.high_manifest["request"], "model": model})
        for request in invalid:
            with self.subTest(request=request), patch.object(self.store, "setting", side_effect=AssertionError("no history lookup")), self.assertRaises(TaskAlongError) as caught:
                successor.guard_effort_replay(self.store, request)
            self.assertEqual(caught.exception.code, "pilot_request_invalid")
            self.assertEqual(caught.exception.effect_outcome, "not_sent")
        self.assert_original()

    def test_public_malformed_high_requests_refuse_before_guard_preflight_or_output(self):
        self.fixture.configure(reasoning_effort="high")
        requests = []
        missing = copy.deepcopy(self.high_manifest["request"]); missing.pop("model"); requests.append(missing)
        requests.extend({**self.high_manifest["request"], "model": value} for value in (None, False, [], {}))
        for index, request in enumerate(requests):
            output = self.root / f"invalid-high-{index}"
            with self.subTest(index=index), patch.object(successor, "guard_effort_replay", side_effect=AssertionError("validated requests only")), \
                    patch.object(muse, "_preflight", side_effect=AssertionError("no preflight")), \
                    patch.object(muse, "run_foreground_experiment", side_effect=AssertionError("no provider")), self.assertRaises(TaskAlongError) as caught:
                self.service.run_provider(request=request, output=str(output))
            self.assertEqual(caught.exception.code, "pilot_request_invalid")
            self.assertFalse(output.exists())
        self.fixture.configure()
        self.assert_original()

    def test_plan_binds_only_explicit_high_amendment_without_storing_or_dispatching(self):
        with patch.object(muse, "run_foreground_experiment", side_effect=AssertionError("model-free plan")):
            proof = self.plan()
        self.assertEqual(proof["format"], "manual-muse-successor-plan/5")
        self.assertEqual(proof["enrollment"]["format"], "manual-muse-ladder/5")
        self.assertEqual(proof["reason"], "interrupted-high")
        self.assertEqual(proof["amendment"], self.amendment)
        self.assertEqual(proof["ordinal"], 1)
        self.assertEqual(proof["remaining_controller_slots_including_this"], 1)
        self.assertEqual(proof["attempt_seconds"], self.original_config["attempt_seconds"])
        self.assertFalse(proof["plan_authorizes_dispatch"])
        self.assertFalse(proof["remote_usage_settled"])
        self.assertFalse(proof["hard_native_attempt_limit_enforced"])
        self.assertIsNone(self.store.setting("provider-config:" + self.high_config["digest"]))
        self.assertIsNone(self.store.setting("provider-successor:muse:" + self.original["run_id"]))
        self.assertFalse(successor._anchor(self.original).exists())
        self.assert_original()

    def test_one_high_execution_keeps_global_max_and_old_evidence_and_never_replays(self):
        proof = self.plan()
        def owner(argv, **options):
            self.assertEqual(argv[argv.index("--reasoning-effort") + 1], "high")
            self.assertEqual(argv[argv.index("--model") + 1], self.original_config["model"])
            new_root = Path(argv[argv.index("--workspace") + 1]).parent
            self.assertEqual(json.loads((new_root / "bundle/bundle.json").read_bytes()), self.high_manifest)
            self.assertEqual(self.store.setting("provider:muse"), self.original_config)
            return self.fixture.child(argv, **options)
        with patch.object(muse, "run_foreground_experiment", side_effect=owner) as calls:
            result = self.execute(proof)
        self.assertEqual(calls.call_count, 1)
        self.assertEqual(result["state"], "proposal_ready")
        self.assertEqual(result["configuration_digest"], self.high_config["digest"])
        self.assertEqual(result["bundle_digest"], self.high_manifest["digest"])
        self.assertEqual(result["manual_successor"]["format"], "manual-muse-successor/5")
        self.assertEqual(result["manual_successor"]["effort_amendment"], self.amendment)
        self.assertEqual(result["manual_successor"]["ordinal"], 1)
        self.assertEqual(result["manual_successor"]["root_run_id"], self.original["run_id"])
        self.assertEqual(result["manual_successor"]["predecessor_run_id"], self.original["run_id"])
        self.assertEqual(result["manual_successor"]["native_lifecycle_policy"], interrupted_fixtures.recovery.POLICY)
        self.assertTrue(result["process"]["native_lifecycle"]["protocol_valid"])
        self.assertEqual(result["process"]["native_lifecycle"]["model_tasks_started"], 1)
        self.assertFalse(result["process"]["native_lifecycle"]["stop_requested"])
        self.assertEqual(result["process"]["native_lifecycle"]["paid_call_count"], "unknown")
        self.assertFalse(result["process"]["native_lifecycle"]["hard_native_attempt_limit_enforced"])
        self.assertEqual(result["execution"]["requested_effort"], "high")
        self.assertIsNone(result["execution"]["reported_effort"])
        self.assertEqual(result["remote_usage"], "unknown")
        self.assertFalse(result["acceptance_allowed"])
        self.assertEqual(self.store.setting("provider-config:" + self.high_config["digest"]), self.high_config)
        self.assert_original()
        with patch.object(muse, "_preflight", side_effect=AssertionError("no preflight replay")), \
                patch.object(muse, "run_foreground_experiment", side_effect=AssertionError("no provider replay")):
            self.assertEqual(self.execute(proof), result)
            with self.assertRaises(TaskAlongError): self.execute(proof, key="another-key")
            with self.assertRaises(TaskAlongError): self.execute(proof, key="wrong-reason", reason="interrupted")
            with self.assertRaises(TaskAlongError):
                self.service.provider_successor_plan(predecessor=result["run_id"], reason="interrupted-high")
        self.assert_original()

    def test_preflight_failure_consumes_shared_original_slot_and_retains_high_config(self):
        proof = self.plan()
        with patch.object(muse, "_preflight", side_effect=TaskAlongError("synthetic_preflight", "Unavailable.")) as preflight, \
                patch.object(muse, "run_foreground_experiment", side_effect=AssertionError("no provider")):
            with self.assertRaises(TaskAlongError): self.execute(proof)
        self.assertEqual(preflight.call_count, 1)
        reservation = self.store.setting("provider-successor:muse:" + self.original["run_id"])
        self.assertEqual(reservation["format"], "manual-muse-successor/5")
        self.assertEqual(reservation["effort_amendment"], self.amendment)
        self.assertEqual(reservation["ordinal"], 1)
        self.assertTrue((successor._anchor(self.original) / "slot-1.json").is_file())
        self.assertEqual(self.store.setting("provider-config:" + self.high_config["digest"]), self.high_config)
        with patch.object(muse, "_preflight", side_effect=AssertionError("consumed slot")):
            observed = self.execute(proof)
            self.assertEqual(observed["state"], "blocked")
            self.assertEqual(observed["run_id"], reservation["run_id"])
            with self.assertRaises(TaskAlongError): self.execute(proof, key="fresh-key")
        self.assert_original()

    def test_wrong_reason_and_changed_scope_refuse_before_reservation(self):
        proof = self.plan()
        with self.assertRaises(TaskAlongError): self.execute(proof, reason="interrupted")
        for changes in ({"context": "native-only"}, {"attempt_seconds": 720}, {"reasoning_effort": "high"}, {"model": "other-model"}):
            self.fixture.configure(**changes)
            with self.subTest(changes=changes), self.assertRaises(TaskAlongError): self.execute(proof)
            self.assertIsNone(self.store.setting("provider-successor:muse:" + self.original["run_id"]))
            self.assertFalse(successor._anchor(self.original).exists())
            self.fixture.configure()
        self.assert_original()

    def test_copied_and_restored_state_cannot_reopen_high_slot(self):
        proof = self.plan()
        with RunService(self.root / "copied-state") as copied:
            self.store.db.backup(copied._store.db)
            with patch.object(muse, "_preflight", side_effect=TaskAlongError("synthetic_preflight", "Unavailable.")):
                with self.assertRaises(TaskAlongError): self.execute(proof)
            with self.assertRaises(TaskAlongError): self.plan(copied)
            copied._store.db.backup(self.store.db)
            with patch.object(muse, "_preflight", side_effect=AssertionError("no restored replay")):
                with self.assertRaises(TaskAlongError): self.execute(proof)
        self.assert_original()

    def test_reserved_high_run_alias_blocks_ordinary_high_after_explicit_reconfigure(self):
        proof = self.plan()
        with patch.object(muse, "run_foreground_experiment", side_effect=self.fixture.child):
            result = self.execute(proof)
        alias = self.store.setting("provider-claim:muse:" + self.high_manifest["digest"])
        self.assertEqual(alias, {"run_id": result["run_id"], "bundle_digest": self.high_manifest["digest"],
                                 "output": result["output"]})
        self.fixture.configure(reasoning_effort="high")
        self.assertEqual(self.store.setting("provider:muse"), self.high_config)
        output = self.root / "ordinary-high-replay"
        with patch.object(muse, "_preflight") as preflight, patch.object(muse, "run_foreground_experiment") as owner, \
                self.assertRaises(TaskAlongError):
            self.service.run_provider(request=copy.deepcopy(self.high_manifest["request"]), output=str(output))
        preflight.assert_not_called(); owner.assert_not_called()
        self.assertFalse(output.exists())
        self.assertEqual(self.store.setting("provider-claim:muse:" + self.high_manifest["digest"]), alias)
        self.assertEqual(self.service.result(result["run_id"]), result)
        self.fixture.c.assert_original()
        self.assertEqual(self.store.setting("provider-config:" + self.original_config["digest"]), self.original_config)

    def test_restored_pre_high_state_and_model_aliases_cannot_bypass_retained_anchor(self):
        proof = self.plan()
        with RunService(self.root / "before-high-state") as backup:
            self.store.db.backup(backup._store.db)
            with patch.object(muse, "_preflight", side_effect=TaskAlongError("synthetic_preflight", "Unavailable.")):
                with self.assertRaises(TaskAlongError): self.execute(proof)
            self.assertTrue(successor._anchor(self.original).is_dir())
            backup._store.db.backup(self.store.db)
        self.assertIsNone(self.store.setting("provider-claim:muse:" + self.high_manifest["digest"]))
        self.assertIsNone(self.store.setting("provider-successor:muse:" + self.original["run_id"]))
        self.fixture.configure(reasoning_effort="high")
        for index, model in enumerate(("muse-wonder-full-1.0", "wonder-full")):
            request = copy.deepcopy(self.high_manifest["request"]); request["model"] = model
            output = self.root / f"restored-high-replay-{index}"
            with self.subTest(model=model), patch.object(muse, "_preflight") as preflight, \
                    patch.object(muse, "run_foreground_experiment") as owner, self.assertRaises(TaskAlongError):
                self.service.run_provider(request=request, output=str(output))
            preflight.assert_not_called(); owner.assert_not_called()
            self.assertFalse(output.exists())
            self.assertIsNone(self.store.setting("provider-successor:muse:" + self.original["run_id"]))
        self.fixture.c.assert_original()
        self.assertEqual(self.store.setting("provider-config:" + self.original_config["digest"]), self.original_config)

    def test_unlinked_high_is_refused_before_anchor_for_both_model_spellings(self):
        self.fixture.configure(reasoning_effort="high")
        for index, model in enumerate(("muse-wonder-full-1.0", "wonder-full")):
            request = copy.deepcopy(self.high_manifest["request"]); request["model"] = model
            manifest, _ = pilot._manifest(request)
            output = self.root / f"unlinked-high-{index}"
            with self.subTest(model=model), patch.object(muse, "_preflight") as preflight, \
                    patch.object(muse, "run_foreground_experiment") as owner, self.assertRaises(TaskAlongError) as caught:
                self.service.run_provider(request=request, output=str(output))
            self.assertEqual(caught.exception.code, "provider_successor_link_required")
            preflight.assert_not_called(); owner.assert_not_called()
            self.assertFalse(output.exists())
            self.assertIsNone(self.store.setting("provider-claim:muse:" + manifest["digest"]))
        self.assertFalse(successor._anchor(self.original).exists())
        self.fixture.configure()
        self.assertEqual(self.plan()["reason"], "interrupted-high")
        self.assert_original()

    def test_preexisting_ordinary_high_claim_blocks_amendment_before_slot(self):
        proof = self.plan()
        self.fixture.configure(reasoning_effort="high")
        # Simulate a claim retained from before the ordinary-run lineage fence;
        # current public admission must never create this historical condition.
        with patch.object(successor, "guard_effort_replay"), \
                patch.object(muse, "run_foreground_experiment", side_effect=self.fixture.child):
            existing = self.service.run_provider(request=copy.deepcopy(self.high_manifest["request"]),
                output=str(self.root / "previous-ordinary-high"))
        self.assertEqual(existing["state"], "proposal_ready")
        alias = self.store.setting("provider-claim:muse:" + self.high_manifest["digest"])
        self.assertEqual(alias["run_id"], existing["run_id"])
        self.fixture.configure()
        with patch.object(muse, "_preflight") as preflight, patch.object(muse, "run_foreground_experiment") as owner:
            with self.assertRaises(TaskAlongError): self.plan()
            with self.assertRaises(TaskAlongError): self.execute(proof)
        preflight.assert_not_called(); owner.assert_not_called()
        self.assertFalse(successor._anchor(self.original).exists())
        self.assertIsNone(self.store.setting("provider-successor:muse:" + self.original["run_id"]))
        self.assertEqual(self.store.setting("provider-claim:muse:" + self.high_manifest["digest"]), alias)
        self.assertEqual(self.service.result(existing["run_id"]), existing)
        self.assert_original()

    def test_preexisting_alternate_model_high_claim_blocks_plan_and_old_proof(self):
        proof = self.plan()
        self.fixture.configure(reasoning_effort="high")
        request = copy.deepcopy(self.high_manifest["request"]); request["model"] = "wonder-full"
        alternate, _ = pilot._manifest(request)
        self.assertNotEqual(alternate["digest"], self.high_manifest["digest"])
        # Simulate a claim retained from before the ordinary-run lineage fence;
        # current public admission must never create this historical condition.
        with patch.object(successor, "guard_effort_replay"), \
                patch.object(muse, "run_foreground_experiment", side_effect=self.fixture.child):
            existing = self.service.run_provider(request=request, output=str(self.root / "previous-alias-high"))
        self.assertEqual(existing["state"], "proposal_ready")
        claim = self.store.setting("provider-claim:muse:" + alternate["digest"])
        self.assertEqual(claim["run_id"], existing["run_id"])
        self.assertIsNone(self.store.setting("provider-claim:muse:" + self.high_manifest["digest"]))
        self.fixture.configure()
        with patch.object(muse, "_preflight") as preflight, patch.object(muse, "run_foreground_experiment") as owner:
            for action in (self.plan, lambda: self.execute(proof)):
                with self.assertRaises(TaskAlongError) as caught: action()
                self.assertEqual(caught.exception.code, "provider_successor_effort_already_submitted")
        preflight.assert_not_called(); owner.assert_not_called()
        self.assertFalse(successor._anchor(self.original).exists())
        self.assertIsNone(self.store.setting("provider-successor:muse:" + self.original["run_id"]))
        self.assertEqual(self.store.setting("provider-claim:muse:" + alternate["digest"]), claim)
        self.assertEqual(self.service.result(existing["run_id"]), existing)
        self.assert_original()

    def test_alternate_high_claim_racing_material_is_refenced_before_any_slot_write(self):
        proof = self.plan()
        request = copy.deepcopy(self.high_manifest["request"]); request["model"] = "wonder-full"
        alternate, _ = pilot._manifest(request)
        claim = {"run_id": "77777777-7777-4777-8777-777777777777", "bundle_digest": alternate["digest"],
                 "output": str(self.root / "concurrent-alias-high")}
        real = successor._dispatch_configuration
        def raced(*args, **kwargs):
            config = real(*args, **kwargs)
            self.assertIsNone(self.store.setting("provider-config:" + self.high_config["digest"]))
            self.store.set_setting("provider-claim:muse:" + alternate["digest"], claim)
            return config
        with patch.object(successor, "_dispatch_configuration", side_effect=raced) as dispatch, \
                patch.object(muse, "_preflight") as preflight, patch.object(muse, "run_foreground_experiment") as owner, \
                self.assertRaises(TaskAlongError) as caught:
            self.execute(proof)
        self.assertEqual(caught.exception.code, "provider_successor_effort_already_submitted")
        self.assertEqual(dispatch.call_count, 1)
        preflight.assert_not_called(); owner.assert_not_called()
        self.assertFalse(successor._anchor(self.original).exists())
        self.assertIsNone(self.store.setting("provider-successor:muse:" + self.original["run_id"]))
        self.assertIsNone(self.store.setting("provider-config:" + self.high_config["digest"]))
        self.assertIsNone(self.store.setting("provider-claim:muse:" + self.high_manifest["digest"]))
        self.assertEqual(self.store.setting("provider-claim:muse:" + alternate["digest"]), claim)
        self.assert_original()

    def test_original_high_run_is_not_a_max_to_high_amendment(self):
        fixture = interrupted_fixture("high"); self.addCleanup(fixture.doCleanups)
        with patch.object(muse, "run_foreground_experiment", side_effect=AssertionError("no provider")), self.assertRaises(TaskAlongError):
            fixture.service.provider_successor_plan(predecessor=fixture.original["run_id"], reason="interrupted-high")
        self.assertFalse(successor._anchor(fixture.original).exists())
        self.assertEqual(fixture.plan()["format"], "manual-muse-successor-plan/4")
        fixture.c.assert_original()

    def test_rehashed_forged_plan_or_amendment_cannot_reserve(self):
        proof = self.plan()
        for field, value in (("to_effort", "max"), ("configuration_digest", "0" * 64), ("bundle_digest", "0" * 64)):
            forged = copy.deepcopy(proof); forged["amendment"][field] = value
            forged["amendment"]["digest"] = digest(forged["amendment"]); forged["digest"] = digest(forged)
            with self.subTest(field=field), patch.object(muse, "run_foreground_experiment") as owner, self.assertRaises(TaskAlongError):
                self.execute(forged)
            owner.assert_not_called()
            self.assertFalse(successor._anchor(self.original).exists())
        self.assert_original()

    def test_active_pointer_changed_after_reservation_refuses_before_preflight(self):
        proof = self.plan(); real = muse.run
        def reconfigured(*args, **kwargs):
            self.assertEqual(self.store.setting("provider-successor:muse:" + self.original["run_id"]), kwargs["_successor"])
            self.fixture.configure(reasoning_effort="high")
            return real(*args, **kwargs)
        with patch.object(muse, "run", side_effect=reconfigured), patch.object(muse, "_preflight") as preflight, \
                patch.object(muse, "run_foreground_experiment") as owner, self.assertRaises(TaskAlongError) as caught:
            self.execute(proof)
        self.assertEqual(caught.exception.code, "provider_successor_plan_changed")
        preflight.assert_not_called(); owner.assert_not_called()
        reservation = self.store.setting("provider-successor:muse:" + self.original["run_id"])
        self.assertEqual(reservation["ordinal"], 1)
        with patch.object(muse, "run", side_effect=AssertionError("same key cannot resume")):
            observed = self.execute(proof)
        self.assertEqual(observed["state"], "reserved_incomplete")
        self.assertEqual(observed["run_id"], reservation["run_id"])
        self.fixture.configure()
        self.assert_original()

    def test_rehashed_reservation_cannot_select_a_configuration_image_under_the_wrong_digest_key(self):
        proof = self.plan(); real = muse.run
        def aliased(*args, **kwargs):
            reservation = copy.deepcopy(kwargs["_successor"])
            alias = "0" * 64
            self.store.set_setting("provider-config:" + alias, self.high_config)
            reservation["configuration_digest"] = alias
            reservation["digest"] = digest(reservation)
            for key in ("provider-successor:muse:" + self.original["run_id"],
                        "provider-successor-run:muse:" + reservation["run_id"],
                        "provider-successor-key:muse:" + reservation["key_digest"]):
                self.store.set_setting(key, reservation)
            path = successor._anchor(self.original) / "slot-1.json"
            path.chmod(0o600); path.write_bytes(canonical_bytes(reservation)); path.chmod(0o400)
            kwargs["_successor"] = reservation
            return real(*args, **kwargs)
        with patch.object(muse, "run", side_effect=aliased), \
                patch.object(muse, "run_foreground_experiment", side_effect=self.fixture.child) as owner, self.assertRaises(TaskAlongError) as caught:
            self.execute(proof)
        self.assertEqual(caught.exception.code, "provider_successor_history_changed")
        owner.assert_not_called()
        self.assert_original()

    def test_changed_derived_high_config_is_not_loaded_before_owner(self):
        proof = self.plan(); real = muse.run
        def changed(*args, **kwargs):
            value = self.store.setting("provider-config:" + self.high_config["digest"])
            self.assertEqual(value, self.high_config)
            value["context"] = "native-only"; value["digest"] = digest(value)
            self.store.set_setting("provider-config:" + self.high_config["digest"], value)
            return real(*args, **kwargs)
        with patch.object(muse, "run", side_effect=changed), patch.object(muse, "run_foreground_experiment") as owner, self.assertRaises(TaskAlongError):
            self.execute(proof)
        owner.assert_not_called()
        self.assertIsNotNone(self.store.setting("provider-successor:muse:" + self.original["run_id"]))
        self.assert_original()

    def test_consistently_rehashed_reservation_amendment_cannot_change_effort(self):
        proof = self.plan(); real = muse.run
        def changed(*args, **kwargs):
            reservation = copy.deepcopy(kwargs["_successor"])
            reservation["effort_amendment"]["to_effort"] = "max"
            reservation["effort_amendment"]["digest"] = digest(reservation["effort_amendment"])
            reservation["digest"] = digest(reservation)
            for key in ("provider-successor:muse:" + self.original["run_id"],
                        "provider-successor-run:muse:" + reservation["run_id"],
                        "provider-successor-key:muse:" + reservation["key_digest"]):
                self.store.set_setting(key, reservation)
            path = successor._anchor(self.original) / "slot-1.json"
            path.chmod(0o600); path.write_bytes(canonical_bytes(reservation)); path.chmod(0o400)
            kwargs["_successor"] = reservation
            return real(*args, **kwargs)
        with patch.object(muse, "run", side_effect=changed), patch.object(muse, "run_foreground_experiment") as owner, self.assertRaises(TaskAlongError):
            self.execute(proof)
        owner.assert_not_called()
        self.assert_original()


if __name__ == "__main__":
    unittest.main()
