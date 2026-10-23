"""Ollama fixture routes preserve exact identities without a server request."""
import dataclasses
import hashlib
import json
import os
import unittest
from importlib import resources
from pathlib import Path
from unittest.mock import patch

from taskalong.bindings import ProviderProfile
from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes, loads, schema, schema_names, seal_versioned
from test_bindings import provider


def local_profile(**changes):
    return ProviderProfile.from_dict(seal_versioned(
        "provider-profile", provider() | changes, version="2.0"))


def route_observation(profile, **changes):
    value = profile.to_dict()
    return {
        "kind": "ollama_fixture_route_observation", "schema_version": "1.0",
        "provider_profile_digest": profile.digest, "endpoint": value["endpoint"],
        "requested_model": value["model"]["requested"],
        "resolved_model_digest": value["model"]["resolved_digest"],
        "model_origin": "local", "server_available": True, "model_available": True,
        "tool_protocol": "fixture-edit/1",
        "result_schema_id": "urn:taskalong:schema:v2.3:worker-result",
        "external_effect": "none", "managed_route_conflict": False,
        "qualification": "synthetic",
        "auth": {**value["auth"], "token_present": True, "token_matched": True},
        **changes,
    }


def captured_route_inputs(*, lookup_capture=None, start_capture=None, extra_lookup_capture=None):
    """Original fixture captures feed the real offline evaluator, not a mock."""
    from taskalong.runtime_profiles import FixtureRouteObservation
    from test_qualification import inputs, measured, policy_for, reference
    binding, installation, profile, context = inputs()
    leaf = FixtureRouteObservation.from_dict(route_observation(profile))
    leaf_bytes = leaf.to_bytes()
    receipts, blobs = [], {leaf.digest: leaf_bytes}
    def measurement(capability, facts, capture, *, mode):
        receipt, entries = measured(capability, facts, binding=binding, context=context, mode=mode)
        old = receipt["results"][0]["evidence_refs"][0]
        observation = loads(entries.pop(old["sha256"]))
        if capture is not None:
            capture_ref = reference(capture) | {"classification": "private"}
            entries[capture_ref["sha256"]] = capture
            observation["capture_refs"] = [capture_ref]
        raw = canonical_bytes(observation)
        ref = reference(raw)
        entries[ref["sha256"]] = raw
        receipt = seal_versioned("qualification-receipt", receipt | {
            "results": [{"capability": capability, "outcome": "supported", "evidence_refs": [ref]}]}, version="2.1")
        receipts.append(receipt)
        blobs.update(entries)
    measurement("start", {"dispatch_observed": True, "subject_matched": True}, start_capture, mode="start")
    measurement("start", {"dispatch_observed": True, "subject_matched": True}, None, mode="provider_lookup")
    measurement("provider_lookup", {"destination_matched": True, "model_digest_matched": True, "auth_matched": True},
                leaf_bytes if lookup_capture is None else lookup_capture, mode="provider_lookup")
    if extra_lookup_capture is not None:
        measurement("provider_lookup", {"destination_matched": True, "model_digest_matched": True, "auth_matched": True}, extra_lookup_capture, mode="provider_lookup")
    policy = policy_for(receipts[0])
    for receipt in receipts[1:]:
        policy["approvals"] += policy_for(receipt)["approvals"]
    return dict(binding=binding, installation=installation, provider=profile, context=context,
                receipts=receipts, policy=policy, blobs=blobs, leaf=leaf)


def evaluate_route_inputs(case, *, when=None):
    from taskalong.qualification import EvidenceStore, TrustPolicy, evaluate
    from test_qualification import NOW
    evidence = EvidenceStore.from_blobs(case["blobs"])
    arguments = dict(installation=case["installation"], provider=case["provider"], context=case["context"],
        receipts=case["receipts"], trust=TrustPolicy.from_dict(case["policy"]), evidence=evidence,
        now=NOW if when is None else when, minimum_level="offline_fixture")
    return (evaluate(case["binding"], mode="start", **arguments),
            evaluate(case["binding"], mode="provider_lookup", **arguments), evidence)


class OllamaRouteTests(unittest.TestCase):
    def test_local_route_preserves_identity_and_never_claims_server_cancellation(self):
        from taskalong.runtime_profiles import FixtureRouteObservation, resolve_ollama_route, fixture_environment
        profile = local_profile()
        original = route_observation(profile)
        observed = FixtureRouteObservation.from_dict(original)
        plan = resolve_ollama_route(profile, observed)
        view = plan.to_dict()
        self.assertEqual(view["provider_profile_digest"], profile.digest)
        self.assertEqual(view["observation_digest"], observed.digest)
        self.assertEqual(view["endpoint"], "http://127.0.0.1:11434")
        self.assertEqual(view["model"], {"requested": "synthetic-model", "resolved_digest": "3" * 64})
        self.assertEqual(view["qualification"], "synthetic")
        self.assertEqual(view["external_request"], "not_sent")
        self.assertEqual(view["remote_cancellation"], "unsupported")
        self.assertEqual(view["cost_accounting"], "unknown")
        self.assertFalse(view["native_resume"])
        self.assertEqual(fixture_environment(plan), {
            "ANTHROPIC_BASE_URL": "http://127.0.0.1:11434",
            "ANTHROPIC_AUTH_TOKEN": "ollama", "ANTHROPIC_API_KEY": "",
        })
        before = plan.to_bytes()
        original["model_origin"] = "cloud"
        view["model"]["requested"] = "changed"
        self.assertEqual(plan.to_bytes(), before)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            plan._canonical = b"{}"

    def test_cloud_route_requires_exact_explicit_fixture_reference(self):
        from taskalong.runtime_profiles import FixtureRouteObservation, resolve_ollama_route, fixture_environment
        profile = local_profile(provider="ollama-cloud", endpoint="https://ollama.com",
            allowed_disclosure="provider-only", auth={"mode": "credential-ref", "credential_ref": "fixture-ollama-cloud"})
        observed = FixtureRouteObservation.from_dict(route_observation(profile, model_origin="cloud"))
        plan = resolve_ollama_route(profile, observed)
        self.assertEqual(plan.to_dict()["provider"], "ollama-cloud")
        self.assertEqual(plan.to_dict()["auth"]["credential_ref"], "fixture-ollama-cloud")
        self.assertEqual(plan.to_dict()["remote_cancellation"], "unsupported")
        with self.assertRaises(TaskAlongError) as missing:
            fixture_environment(plan)
        self.assertEqual(missing.exception.code, "fixture_credential_unresolved")
        with self.assertRaises(TaskAlongError):
            fixture_environment(plan, credential_refs={"fixture-ollama-cloud": "unregistered-value"})
        actual = fixture_environment(plan, credential_refs={"fixture-ollama-cloud": "taskalong-fixture-ollama-cloud-1"})
        self.assertEqual(actual, {"ANTHROPIC_BASE_URL": "https://ollama.com",
            "ANTHROPIC_AUTH_TOKEN": "taskalong-fixture-ollama-cloud-1", "ANTHROPIC_API_KEY": ""})
        self.assertNotIn("taskalong-fixture-ollama-cloud-1", plan.to_bytes().decode())

    def test_missing_or_conflicting_observations_cannot_become_route_proof(self):
        from taskalong.runtime_profiles import FixtureRouteObservation, resolve_ollama_route
        profile = local_profile()
        base = route_observation(profile)
        changes = [
            {"server_available": False}, {"server_available": None},
            {"model_available": False}, {"model_available": None},
            {"model_origin": "cloud"}, {"model_origin": "forwarded"}, {"model_origin": "unknown"},
            {"external_effect": "active"}, {"external_effect": "unknown"}, {"external_effect": "reported-complete"},
            {"managed_route_conflict": True}, {"provider_profile_digest": "4" * 64},
            {"endpoint": "http://127.0.0.1:11435"}, {"requested_model": "another-model"},
            {"resolved_model_digest": "4" * 64},
            {"auth": base["auth"] | {"token_present": False}},
            {"auth": base["auth"] | {"token_matched": None}},
            {"auth": base["auth"] | {"credential_ref": "unrelated"}},
        ]
        for fields in changes:
            with self.subTest(fields=fields):
                observed = FixtureRouteObservation.from_dict(base | fields)
                with self.assertRaises(TaskAlongError) as failure:
                    resolve_ollama_route(profile, observed)
                self.assertEqual(failure.exception.code, "provider_route_unqualified")

    def test_capture_shape_is_closed_and_unknown_values_remain_typed(self):
        from taskalong.runtime_profiles import FixtureRouteObservation
        base = route_observation(local_profile())
        changes = [{"approved": True}, {"schema_version": []}, {"provider_profile_digest": {}},
            {"model_origin": []}, {"server_available": 1}, {"managed_route_conflict": "false"},
            {"external_effect": {}}, {"auth": []}, {"auth": base["auth"] | {"token_matched": 1}},
            {"qualification": "production"}, {"tool_protocol": "arbitrary-tools"},
            {"result_schema_id": "urn:taskalong:schema:v1:worker-result"}]
        for fields in changes:
            with self.subTest(fields=fields), self.assertRaises(TaskAlongError):
                FixtureRouteObservation.from_dict(base | fields)

    def test_narrow_endpoints_effort_and_model_origin_never_fall_back(self):
        from taskalong.runtime_profiles import FixtureRouteObservation, resolve_ollama_route
        changes = [{"endpoint": endpoint} for endpoint in (
            "http://127.0.0.1", "https://127.0.0.1:11434", "http://127.0.0.1:11434/",
            "http://127.0.0.1:011434", "http://[0:0:0:0:0:0:0:1]:11434")]
        changes += [{"effort": "high"}, {"service_tier": "priority"},
            {"model": {"requested": "innocent:cloud", "resolved_digest": "3" * 64}},
            {"auxiliary_routes": [{"purpose": "subagent", "provider_profile_digest": "4" * 64}]}]
        for fields in changes:
            with self.subTest(fields=fields):
                profile = local_profile(**fields)
                observed = FixtureRouteObservation.from_dict(route_observation(profile))
                with self.assertRaises(TaskAlongError) as failure:
                    resolve_ollama_route(profile, observed)
                self.assertEqual(failure.exception.code, "provider_route_unsupported")
        for endpoint in ("https://ollama.com/", "https://ollama.com:443", "https://ollama.com/v1", "https://example.invalid"):
            with self.subTest(endpoint=endpoint):
                profile = local_profile(provider="ollama-cloud", endpoint=endpoint, allowed_disclosure="provider-only",
                    auth={"mode": "credential-ref", "credential_ref": "fixture-ollama-cloud"})
                observed = FixtureRouteObservation.from_dict(route_observation(profile, model_origin="cloud"))
                with self.assertRaises(TaskAlongError) as failure:
                    resolve_ollama_route(profile, observed)
                self.assertEqual(failure.exception.code, "provider_route_unsupported")

    def test_environment_and_route_view_cannot_inherit_credentials_or_claim_external_effects(self):
        from taskalong.runtime_profiles import FixtureRouteObservation, OllamaFixtureRoute, resolve_ollama_route, fixture_environment
        profile = local_profile()
        plan = resolve_ollama_route(profile, FixtureRouteObservation.from_dict(route_observation(profile)))
        inherited = {"ANTHROPIC_BASE_URL": "https://unselected.invalid", "ANTHROPIC_API_KEY": "inherited-fixture-value",
            "OLLAMA_API_KEY": "inherited-fixture-value", "OPENAI_API_KEY": "inherited-fixture-value",
            "HTTP_PROXY": "http://unselected.invalid", "ANTHROPIC_MODEL": "unselected-model"}
        with patch.dict(os.environ, inherited):
            self.assertEqual(fixture_environment(plan), {"ANTHROPIC_BASE_URL": "http://127.0.0.1:11434",
                "ANTHROPIC_AUTH_TOKEN": "ollama", "ANTHROPIC_API_KEY": ""})
        for fields in ({"external_request": "completed"}, {"remote_cancellation": "supported"},
                       {"cost_accounting": "zero"}, {"native_resume": True}, {"qualification": "production"}):
            with self.subTest(fields=fields), self.assertRaises(TaskAlongError):
                OllamaFixtureRoute.from_dict(plan.to_dict() | fields)


class OllamaCaptureBindingTests(unittest.TestCase):
    def assert_unqualified(self, case, *, when=None):
        from taskalong.runtime_profiles import require_route_capture
        start, lookup, evidence = evaluate_route_inputs(case, when=when)
        with self.assertRaises(TaskAlongError) as failure:
            require_route_capture(start, lookup, case["leaf"], evidence)
        self.assertEqual(failure.exception.code, "provider_route_evidence_unqualified")
        return start, lookup

    def test_route_capture_binds_only_to_current_contributing_lookup_evidence(self):
        case = captured_route_inputs()
        start, lookup, evidence = evaluate_route_inputs(case)
        self.assertTrue(start.decision.to_dict()["requirements_satisfied"])
        self.assertTrue(lookup.decision.to_dict()["requirements_satisfied"])
        self.assertNotIn("provider_lookup", case["binding"].to_dict()["required_capabilities"])
        from taskalong.runtime_profiles import require_route_capture
        actual = require_route_capture(start, lookup, case["leaf"], evidence)
        result = next(item for item in lookup.decision.to_dict()["capability_results"] if item["capability"] == "provider_lookup")
        self.assertEqual(actual, tuple(result["evidence_digests"]))
        self.assertFalse(start.decision.to_dict()["production_dispatch_allowed"])
        self.assertFalse(lookup.decision.to_dict()["production_dispatch_allowed"])

    def test_a_matching_blob_or_other_capability_cannot_substitute_for_lookup_capture(self):
        from taskalong.runtime_profiles import FixtureRouteObservation
        from test_qualification import inputs
        leaf = FixtureRouteObservation.from_dict(route_observation(inputs()[2])).to_bytes()
        for start_capture in (None, leaf):
            with self.subTest(attached_to_start=start_capture is not None):
                case = captured_route_inputs(lookup_capture=b"unrelated original fixture capture", start_capture=start_capture)
                self.assertIn(case["leaf"].digest, case["blobs"])
                start, lookup = self.assert_unqualified(case)
                self.assertTrue(start.decision.to_dict()["requirements_satisfied"])
                self.assertTrue(lookup.decision.to_dict()["requirements_satisfied"])

    def test_every_contributing_lookup_observation_must_match_the_route(self):
        case = captured_route_inputs(extra_lookup_capture=b"another original route capture")
        start, lookup = self.assert_unqualified(case)
        self.assertTrue(start.decision.to_dict()["requirements_satisfied"])
        self.assertTrue(lookup.decision.to_dict()["requirements_satisfied"])
        result = next(item for item in lookup.decision.to_dict()["capability_results"] if item["capability"] == "provider_lookup")
        self.assertEqual(len(result["evidence_digests"]), 2)

    def test_both_modes_require_the_entire_unchanged_original_binding(self):
        for removed in ("start-mode", "lookup-mode", "original-capability-in-lookup-mode"):
            with self.subTest(removed=removed):
                case = captured_route_inputs()
                original = case["binding"].to_bytes()
                def keep(receipt):
                    if removed == "start-mode":
                        return receipt["mode"] != "start"
                    if removed == "lookup-mode":
                        return receipt["mode"] != "provider_lookup"
                    return not (receipt["mode"] == "provider_lookup" and receipt["results"][0]["capability"] == "start")
                case["receipts"] = [r for r in case["receipts"] if keep(r)]
                start, lookup = self.assert_unqualified(case)
                self.assertEqual(case["binding"].to_bytes(), original)
                self.assertNotIn("provider_lookup", case["binding"].to_dict()["required_capabilities"])
                if removed == "original-capability-in-lookup-mode":
                    self.assertTrue(start.decision.to_dict()["requirements_satisfied"])
                    result = next(item for item in lookup.decision.to_dict()["capability_results"] if item["capability"] == "provider_lookup")
                    self.assertEqual(result["outcome"], "supported")
                    self.assertFalse(lookup.decision.to_dict()["requirements_satisfied"])

    def test_current_revocations_or_expiry_cannot_be_overridden_by_capture_presence(self):
        for target in ("capture", "observation", "receipt", "approval"):
            with self.subTest(target=target):
                case = captured_route_inputs()
                receipt = next(r for r in case["receipts"] if r["results"][0]["capability"] == "provider_lookup")
                if target == "capture":
                    case["policy"]["revoked_evidence_digests"] = [case["leaf"].digest]
                elif target == "observation":
                    case["policy"]["revoked_evidence_digests"] = [receipt["results"][0]["evidence_refs"][0]["sha256"]]
                elif target == "receipt":
                    case["policy"]["revoked_receipt_digests"] = [receipt["digest"]]
                else:
                    approval = next(a for a in case["policy"]["approvals"] if a["receipt_digest"] == receipt["digest"])
                    case["policy"]["revoked_approval_digests"] = [approval["digest"]]
                start, lookup = self.assert_unqualified(case)
                self.assertTrue(start.decision.to_dict()["requirements_satisfied"])
                self.assertFalse(lookup.decision.to_dict()["requirements_satisfied"])
        start, lookup = self.assert_unqualified(captured_route_inputs(), when="2028-01-01T00:00:00Z")
        self.assertFalse(start.decision.to_dict()["requirements_satisfied"])
        self.assertFalse(lookup.decision.to_dict()["requirements_satisfied"])

    def test_evaluations_cannot_mix_modes_times_or_trust_snapshots(self):
        from taskalong.runtime_profiles import require_route_capture
        case = captured_route_inputs()
        start, lookup, evidence = evaluate_route_inputs(case)
        _, later_lookup, _ = evaluate_route_inputs(case, when="2026-10-22T12:00:01Z")
        changed = captured_route_inputs()
        changed["policy"]["revoked_evidence_digests"] = ["e" * 64]
        _, other_trust, _ = evaluate_route_inputs(changed)
        for first, second in ((lookup, start), (start, later_lookup), (start, other_trust)):
            with self.subTest(modes=(first.decision.to_dict()["mode"], second.decision.to_dict()["mode"])):
                self.assertTrue(first.decision.to_dict()["requirements_satisfied"])
                self.assertTrue(second.decision.to_dict()["requirements_satisfied"])
                with self.assertRaises(TaskAlongError) as failure:
                    require_route_capture(first, second, case["leaf"], evidence)
                self.assertEqual(failure.exception.code, "provider_route_evidence_unqualified")

    def test_canonical_bytes_and_json_media_are_required_beyond_generic_capture_validity(self):
        from test_qualification import policy_for, reference
        case = captured_route_inputs()
        raw = case["leaf"].to_bytes() + b"\n"
        case = captured_route_inputs(lookup_capture=raw)
        start, lookup = self.assert_unqualified(case)
        self.assertTrue(start.decision.to_dict()["requirements_satisfied"])
        self.assertTrue(lookup.decision.to_dict()["requirements_satisfied"])
        case = captured_route_inputs()
        index = next(i for i,r in enumerate(case["receipts"]) if r["results"][0]["capability"] == "provider_lookup")
        receipt = case["receipts"][index]
        observed = loads(case["blobs"][receipt["results"][0]["evidence_refs"][0]["sha256"]])
        observed["capture_refs"][0]["media_type"] = "text/plain"
        raw = canonical_bytes(observed)
        ref = reference(raw)
        case["blobs"][ref["sha256"]] = raw
        receipt = seal_versioned("qualification-receipt", receipt | {"results": [receipt["results"][0] | {"evidence_refs": [ref]}]}, version="2.1")
        case["receipts"][index] = receipt
        case["policy"]["approvals"] += policy_for(receipt)["approvals"]
        start, lookup = self.assert_unqualified(case)
        self.assertTrue(start.decision.to_dict()["requirements_satisfied"])
        self.assertTrue(lookup.decision.to_dict()["requirements_satisfied"])


class OllamaSchemaTests(unittest.TestCase):
    def test_driver_reader_rejects_non_object_inputs_with_a_typed_error(self):
        from taskalong.executors.config import read_driver_config
        for value in (None, [], True, "2.4", 24):
            with self.subTest(value=value), self.assertRaises(TaskAlongError):
                read_driver_config(value)

    def test_explicit_readers_preserve_legacy_bytes_and_reject_cross_version_input(self):
        from taskalong.executors.config import DriverConfig, OllamaDriverConfig, read_driver_config
        from taskalong.execution import DriverTaskSpec, OllamaTaskSpec, read_task_spec
        from test_claude_driver import example_driver_config
        from test_contracts import example_spec
        profile = local_profile()
        old = DriverConfig.from_dict(seal_versioned("driver-config", example_driver_config(), version="2.3"))
        fields = example_driver_config() | {
            "driver_version": "claude-print-ollama-fixture-1", "projection": "claude-ollama-fixture/1",
            "wire_version": "2.4", "provider_profile_digest": profile.digest,
            "fixture_route_observation": route_observation(profile), "credential_ref": None,
        }
        current = seal_versioned("driver-config", fields, version="2.4")
        new = read_driver_config(current)
        self.assertIs(type(new), OllamaDriverConfig)
        self.assertEqual(read_driver_config(old.to_dict()).to_bytes(), old.to_bytes())
        self.assertEqual(new.to_dict()["fixture_route_observation"], route_observation(profile))
        current["fixture_route_observation"]["server_available"] = False
        self.assertTrue(new.to_dict()["fixture_route_observation"]["server_available"])
        with self.assertRaises(dataclasses.FrozenInstanceError):
            new._canonical = b"{}"
        task = seal_versioned("task-spec", example_spec() | {"schema_version": "2.4",
            "execution": {"binding_digest": "a" * 64, "driver_config_digest": new.digest}}, version="2.4")
        self.assertIs(type(read_task_spec(task)), OllamaTaskSpec)
        for reader, document in ((DriverConfig, new.to_dict()), (OllamaDriverConfig, old.to_dict()),
                                 (DriverTaskSpec, task)):
            with self.subTest(reader=reader.__name__), self.assertRaises(TaskAlongError):
                reader.from_dict(document)

    def test_additive_schema_inventory_preserves_every_m5_contract_resource(self):
        from jsonschema import Draft202012Validator
        expected = ("driver-config", "task-spec", "worker-packet", "packet-projection")
        self.assertEqual(schema_names(version="2.4"), expected)
        for name in expected:
            document = schema(name, version="2.4")
            Draft202012Validator.check_schema(document)
            self.assertEqual(document["$id"], "urn:taskalong:schema:v2.4:" + name)
        self.assertEqual(schema("worker-packet", version="2.4")["properties"]["result_schema_id"]["const"],
                         "urn:taskalong:schema:v2.3:worker-result")
        with self.assertRaises(TaskAlongError) as unknown:
            schema("worker-result", version="2.4")
        self.assertEqual(unknown.exception.code, "unknown_schema")
        old = json.loads((Path(__file__).parent / "fixtures/m5-contract-hashes.json").read_text())
        self.assertEqual(len(old), 37)
        root = resources.files("taskalong.resources")
        for path, expected_hash in old.items():
            with self.subTest(resource=path):
                self.assertEqual(hashlib.sha256(root.joinpath(path).read_bytes()).hexdigest(), expected_hash)


class OllamaDriverContractTests(unittest.TestCase):
    def test_preflight_requires_the_same_exact_config_and_provider_for_both_routes(self):
        import sys
        from taskalong.executors.registry import contract_for
        from test_claude_driver import example_driver_config
        profiles = [local_profile(), local_profile(provider="ollama-cloud", endpoint="https://ollama.com",
            allowed_disclosure="provider-only", auth={"mode":"credential-ref", "credential_ref":"fixture-ollama-cloud"})]
        executable = Path(sys.executable).resolve()
        for profile in profiles:
            fields = example_driver_config() | {
                "driver_version":"claude-print-ollama-fixture-1", "projection":"claude-ollama-fixture/1", "wire_version":"2.4",
                "provider_profile_digest":profile.digest, "credential_ref":profile.to_dict()["auth"]["credential_ref"],
                "executable":{"path":str(executable), "sha256":hashlib.sha256(executable.read_bytes()).hexdigest()},
                "fixture_route_observation":route_observation(profile,
                    model_origin="local" if profile.to_dict()["provider"] == "ollama-local" else "cloud")}
            good = seal_versioned("driver-config", fields, version="2.4")
            selected = contract_for(good, task_version="2.4", projection="claude-ollama-fixture/1")
            # Fingerprint only: this does not execute the selected interpreter.
            selected.factory(good, profile.to_dict()).preflight(qualification="synthetic", budget={})
            bad = seal_versioned("driver-config", fields | {"provider_profile_digest":"e" * 64}, version="2.4")
            with self.subTest(provider=profile.to_dict()["provider"]), self.assertRaises(TaskAlongError) as failure:
                selected.factory(bad, profile.to_dict()).preflight(qualification="synthetic", budget={})
            self.assertEqual(failure.exception.code, "execution_projection_unsupported")

    def test_closed_registry_reuses_claude_driver_with_explicit_packet_and_no_effort(self):
        from taskalong.executors.registry import contract_for
        from taskalong.executors.claude_code import ClaudeCode
        from test_claude_driver import driver_packet_inputs, driver_worker
        from test_ollama_store import ollama_config
        config = ollama_config().to_dict()
        contract = contract_for(config, task_version="2.4", projection="claude-ollama-fixture/1")
        fields, old = driver_packet_inputs()
        admission = old | {"schema_version": "2.4", "driver_config": config,
            "projection": old["projection"] | {"projection": "claude-ollama-fixture/1", "driver_config_digest": config["digest"]}}
        packet, wire, mapping = contract.compile_packet(fields, admission)
        self.assertEqual(packet["schema_version"], "2.4")
        self.assertEqual(packet["result_schema_id"], "urn:taskalong:schema:v2.3:worker-result")
        self.assertEqual(packet, wire)
        self.assertEqual(packet["session_id"], fields["attempt_id"])
        self.assertEqual(mapping["driver_config_digest"], config["digest"])
        driver = contract.factory(config, local_profile().to_dict())
        self.assertIs(type(driver), ClaudeCode)
        argv = driver.build_argv(packet)
        self.assertNotIn("--effort", argv)
        self.assertEqual(argv[argv.index("--model")+1], "synthetic-model")
        from taskalong.executors.claude_protocol import OllamaDriverStreamDecoder, ClaudeDriverStreamDecoder
        frames = [{"type": "system", "subtype": "init", "model": "synthetic-model", "tools": ["Edit"], "session_id": packet["session_id"]},
            {"type": "result", "subtype": "success", "is_error": False, "permission_denials": [],
             "session_id": packet["session_id"], "structured_output": driver_worker(packet)}]
        decoder = OllamaDriverStreamDecoder(packet, expected_session_id=packet["session_id"], expected_model="synthetic-model")
        decoder.feed(b"\n".join(canonical_bytes(frame) for frame in frames)+b"\n")
        self.assertEqual(loads(decoder.finish(exit_code=0).worker_result_json)["schema_version"], "2.3")
        with self.assertRaises(TaskAlongError):
            ClaudeDriverStreamDecoder(packet, expected_session_id=packet["session_id"], expected_model="synthetic-model")
        for version, projection in (("2.3", "claude-ollama-fixture/1"), ("2.4", "claude-print-fixture/1")):
            with self.subTest(version=version), self.assertRaises(TaskAlongError):
                contract_for(config, task_version=version, projection=projection)
