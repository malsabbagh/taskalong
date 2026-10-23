"""Semantic execution documents are offline data, never launch authority."""

import dataclasses
import hashlib
import json
import unittest
from importlib import resources
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator
from referencing.exceptions import Unresolvable

from taskalong.errors import TaskAlongError
from taskalong.validation import schema, schema_names, schema_registry


def installation():
    return {
        "installation_id": "fixture-cli", "revision": 1, "harness": "claude-code",
        "adapter_id": "not-registered", "driver_version": "1.0", "cli_version": "fixture-1",
        "platform": {"os": "linux", "architecture": "x86_64", "backend_id": "fixture-only"},
        "executable_digest": "1" * 64, "runtime_closure_digest": "2" * 64,
    }


def provider():
    return {
        "profile_id": "fixture-local", "revision": 1, "harness": "claude-code", "provider": "ollama-local",
        "model": {"requested": "synthetic-model", "resolved_digest": "3" * 64},
        "endpoint": "http://127.0.0.1:11434", "auth": {"mode": "local-no-secret", "credential_ref": None},
        "effort": None, "service_tier": None, "auxiliary_routes": [], "unlisted_auxiliary_routes": "deny",
        "allowed_disclosure": "local-only", "fallback": "forbidden",
    }


def binding():
    return {
        "installation_digest": "1" * 64, "provider_profile_digest": "2" * 64,
        "instruction_bundle_digest": "3" * 64, "tool_policy_digest": "4" * 64,
        "worker_sandbox_digest": "5" * 64, "check_binding_digest": "6" * 64,
        "required_capabilities": ["structured_result", "start"],
        "budget": {"wall_seconds": 120, "max_attempts": 1, "max_cost_micro_usd": None,
                   "max_tokens": None, "hard_cost_cap_required": False, "hard_token_cap_required": False},
        "native_resume": None,
    }


class SemanticDocumentTests(unittest.TestCase):
    def test_identity_patterns_refuse_trailing_controls_in_schema_and_reader(self):
        from taskalong.validation import seal_versioned
        cases = []
        for key in ("installation_id", "adapter_id", "driver_version", "cli_version"):
            cases.append(("harness-installation", installation() | {key: installation()[key] + "\n"}))
        for key in ("profile_id",):
            cases.append(("provider-profile", provider() | {key: provider()[key] + "\n"}))
        cases.extend([
            ("provider-profile", provider() | {"model": provider()["model"] | {"requested": "model\n"}}),
            ("provider-profile", provider() | {"provider": "anthropic-api", "endpoint": "https://example.invalid", "allowed_disclosure": "provider-only", "auth": {"mode": "credential-ref", "credential_ref": "account\n"}}),
        ])
        for name, data in cases:
            complete = {"kind": name.replace("-", "_"), "schema_version": "2.0", **data, "digest": "0" * 64}
            with self.subTest(name=name, data=data):
                self.assertFalse(Draft202012Validator(schema(name, version="2.0")).is_valid(complete))
                with self.assertRaises(TaskAlongError):
                    seal_versioned(name, data, version="2.0")
        resume = schema("execution-binding", version="2.0")["properties"]["native_resume"]["anyOf"][0]["properties"]["protocol_version"]
        self.assertFalse(Draft202012Validator(resume).is_valid("fixture-1\n"))

    def test_documents_are_frozen_nested_copies_with_stable_digests(self):
        from taskalong.bindings import ExecutionBinding, HarnessInstallation, ProviderProfile
        from taskalong.validation import seal_versioned, validate_versioned
        for name, cls, data in (("harness-installation", HarnessInstallation, installation()),
                                ("provider-profile", ProviderProfile, provider()),
                                ("execution-binding", ExecutionBinding, binding())):
            with self.subTest(name=name):
                sealed = seal_versioned(name, data, version="2.0")
                frozen = cls.from_dict(sealed)
                original = frozen.to_bytes()
                sealed.clear()
                exposed = frozen.to_dict()
                exposed["digest"] = "0" * 64
                self.assertEqual(frozen.to_bytes(), original)
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    frozen._canonical = b"{}"
                self.assertEqual(validate_versioned(name, frozen.to_dict(), expected_version="2.0"), frozen.to_dict())
        doc = ProviderProfile.from_dict(seal_versioned("provider-profile", provider(), version="2.0"))
        changed = doc.to_dict()
        changed["model"]["requested"] = "changed"
        self.assertEqual(doc.to_dict()["model"]["requested"], "synthetic-model")
        with self.assertRaises(TaskAlongError):
            ProviderProfile.from_dict(changed)
        first = seal_versioned("execution-binding", binding(), version="2.0")
        second = seal_versioned("execution-binding", binding() | {"required_capabilities": ["start", "structured_result"]}, version="2.0")
        self.assertEqual(first, second)
        for key in ("qualification_receipt_ids", "qualification_receipt_digest"):
            with self.assertRaises(TaskAlongError):
                seal_versioned("execution-binding", binding() | {key: []}, version="2.0")

    def test_closed_boundaries_reject_malformed_documents(self):
        from taskalong.validation import seal_versioned
        changes = [
            ("harness-installation", installation() | {"argv": ["untrusted"]}),
            ("harness-installation", installation() | {"revision": True}),
            ("harness-installation", installation() | {"runtime_closure_digest": "missing"}),
            ("provider-profile", provider() | {"schema_version": "1.0"}),
            ("provider-profile", provider() | {"model": {"requested": "alias-only"}}),
            ("provider-profile", provider() | {"extensions": {"claimed_qualified": True}}),
            ("provider-profile", provider() | {"effort": "automatic"}),
            ("provider-profile", provider() | {"fallback": "allowed"}),
            ("execution-binding", binding() | {"required_capabilities": ["start", "start"]}),
            ("execution-binding", binding() | {"required_capabilities": []}),
            ("execution-binding", binding() | {"budget": binding()["budget"] | {"wall_seconds": 1.5}}),
            ("execution-binding", binding() | {"budget": binding()["budget"] | {"max_cost_micro_usd": 2**53}}),
            ("execution-binding", binding() | {"worker_sandbox_digest": "https://unapproved.invalid/policy"}),
        ]
        for name, data in changes:
            with self.subTest(name=name, data=data), self.assertRaises(TaskAlongError):
                seal_versioned(name, data, version="2.0")

    def test_provider_discriminants_destinations_and_secrets(self):
        from taskalong.validation import seal_versioned
        for endpoint in ("https://unapproved.invalid", "http://localhost:11434", "file:///tmp/model", "http://127.0.0.1:11434?key=hidden", "http://127.0.0.1:0", "http://127.0.0.1:99999", "http://127.0.0.1/\nprivate"):
            with self.subTest(endpoint=endpoint), self.assertRaises(TaskAlongError):
                seal_versioned("provider-profile", provider() | {"endpoint": endpoint}, version="2.0")
        for extra in ({"harness": "cursor"}, {"provider": "ollama-cloud"}, {"auth": {"mode": "credential-ref", "credential_ref": "raw"}}, {"model": provider()["model"] | {"api_key": "synthetic credential"}}):
            with self.subTest(extra=extra), self.assertRaises(TaskAlongError):
                seal_versioned("provider-profile", provider() | extra, version="2.0")
        cloud = provider() | {"provider": "ollama-cloud", "endpoint": "https://example.invalid", "auth": {"mode": "credential-ref", "credential_ref": "fixture-account"}, "allowed_disclosure": "provider-only"}
        local = seal_versioned("provider-profile", provider(), version="2.0")
        self.assertNotEqual(seal_versioned("provider-profile", cloud, version="2.0")["digest"], local["digest"])
        for p, h, mode in (("openai-account", "codex", "account"), ("anthropic-account", "claude-code", "account"), ("anthropic-api", "claude-code", "credential-ref"), ("cursor-account", "cursor", "account"), ("google-account", "antigravity", "account")):
            self.assertEqual(seal_versioned("provider-profile", cloud | {"provider": p, "harness": h, "auth": {"mode": mode, "credential_ref": "fixture-account"}}, version="2.0")["provider"], p)
        secret = "sk-" + "x" * 30
        with self.assertRaises(TaskAlongError) as failure:
            seal_versioned("provider-profile", provider() | {"model": {"requested": secret, "resolved_digest": "3" * 64}}, version="2.0")
        self.assertEqual(failure.exception.code, "sensitive_input")
        self.assertNotIn(secret, str(failure.exception))

    def test_native_resume_and_hard_budget_identity(self):
        from taskalong.bindings import ExecutionBinding
        from taskalong.validation import seal_versioned
        data = binding() | {"kind": "execution_binding", "schema_version": "2.0", "required_capabilities": ["native_resume", "start"], "native_resume": {"protocol_version": "fixture-1", "session_scope": "exact_stored_session"}}
        # Independent canonical oracle: hash the fully specified compatibility
        # inputs before either digest is added. No implementation helper here.
        expected = hashlib.sha256(json.dumps(data,sort_keys=True,separators=(",", ":"),ensure_ascii=False).encode()).hexdigest()
        data["native_resume"]["compatibility_digest"] = expected
        doc = seal_versioned("execution-binding", data, version="2.0")
        self.assertEqual(ExecutionBinding.from_dict(doc).to_dict()["native_resume"]["compatibility_digest"], expected)
        from taskalong.bindings import native_resume_compatibility_digest
        unsorted = doc | {"required_capabilities": ["start", "native_resume"]}
        self.assertEqual(native_resume_compatibility_digest(unsorted), expected)
        for field in ("installation_digest", "provider_profile_digest", "instruction_bundle_digest", "tool_policy_digest", "worker_sandbox_digest", "check_binding_digest"):
            with self.subTest(field=field), self.assertRaises(TaskAlongError):
                seal_versioned("execution-binding", data | {field: "f" * 64}, version="2.0")
        for limit, capability, flag in (("max_cost_micro_usd", "hard_cost_cap", "hard_cost_cap_required"), ("max_tokens", "hard_token_cap", "hard_token_cap_required")):
            missing = binding() | {"budget": binding()["budget"] | {flag: True}}
            with self.assertRaises(TaskAlongError):
                seal_versioned("execution-binding", missing, version="2.0")
            explicit = missing | {"required_capabilities": ["start", capability], "budget": missing["budget"] | {limit: 0}}
            self.assertEqual(seal_versioned("execution-binding", explicit, version="2.0")["budget"][limit], 0)

    def test_readers_never_launch_resolve_or_admit_an_adapter(self):
        from taskalong.bindings import HarnessInstallation
        from taskalong.validation import seal_versioned, validate_versioned
        from taskalong.executors.registry import executor_for
        with patch("subprocess.Popen", side_effect=AssertionError("offline reader spawned")), patch("socket.socket", side_effect=AssertionError("offline reader connected")):
            doc = seal_versioned("harness-installation", installation(), version="2.0")
            self.assertEqual(HarnessInstallation.from_dict(doc).to_dict(), doc)
            with self.assertRaises(TaskAlongError):
                executor_for({"adapter": doc["adapter_id"]})
            for raw in ('{"kind":"provider_profile","kind":"provider_profile"}', '{"x":1.1}', '{"x":9007199254740992}'):
                with self.assertRaises(TaskAlongError):
                    HarnessInstallation(raw.encode())
            with self.assertRaises(TaskAlongError):
                validate_versioned("harness-installation", doc, expected_version="1.0")
            with self.assertRaises(Unresolvable):
                schema_registry(version="2.0").resolver().lookup("https://unapproved.invalid/schema")

    def test_v1_original_documents_and_schema_bytes_remain_unchanged(self):
        from taskalong.validation import canonical_bytes, validate, validate_versioned
        fixture_root = Path(__file__).parent / "fixtures"
        fixtures = json.loads((fixture_root / "v1-canonical.json").read_text())
        for name, document in fixtures.items():
            original = canonical_bytes(document)
            self.assertEqual(canonical_bytes(validate(name, document)), original)
            self.assertEqual(canonical_bytes(validate_versioned(name, document, expected_version="1.0")), original)
        for relative, expected in json.loads((fixture_root / "v1-schema-hashes.json").read_text()).items():
            self.assertEqual(hashlib.sha256(resources.files("taskalong.resources").joinpath(relative).read_bytes()).hexdigest(), expected)


class VersionedResourceTests(unittest.TestCase):
    def test_packaged_examples_are_complete_linked_semantic_data(self):
        from taskalong.bindings import ExecutionBinding, HarnessInstallation, ProviderProfile
        docs = {}
        for name, cls in (("harness-installation", HarnessInstallation), ("provider-profile", ProviderProfile), ("execution-binding", ExecutionBinding)):
            raw = resources.files("taskalong.resources").joinpath("examples", "v2", name + ".json").read_bytes()
            docs[name] = cls(raw).to_dict()
        self.assertEqual(docs["execution-binding"]["installation_digest"], docs["harness-installation"]["digest"])
        self.assertEqual(docs["execution-binding"]["provider_profile_digest"], docs["provider-profile"]["digest"])

    def test_explicit_version_keeps_v1_enumeration_separate(self):
        expected = {"harness-installation", "provider-profile", "execution-binding"}
        self.assertEqual(set(schema_names(version="2.0")), expected)
        self.assertEqual(len(schema_names()), 12)
        self.assertEqual(schema("task-spec"), schema("task-spec", version="1.0"))
        for name in expected:
            document = schema(name, version="2.0")
            Draft202012Validator.check_schema(document)
            self.assertEqual(document["$id"], "urn:taskalong:schema:v2:" + name)
            self.assertEqual(schema_registry(version="2.0").contents(document["$id"]), document)
        for version in ("2", "v2", "3.0", "../v1"):
            with self.subTest(version=version), self.assertRaises(TaskAlongError):
                schema_names(version=version)
        with self.assertRaises(TaskAlongError):
            schema("harness-installation")


if __name__ == "__main__":
    unittest.main()
