"""Trusted local resolution for one explicitly simulated protocol projection.

Portable histories supply identity, never current authority. The OS operator
registers exact fixture transport/policy content separately from task submission.
Mutable trust is re-evaluated before preparation and dispatch. No real provider
or production policy enforcement is admitted by this module.
"""
from __future__ import annotations

import hashlib
import platform
import sys

from .bindings import ExecutionBinding, HarnessInstallation, ProviderProfile
from .contracts import RuntimeProfile
from .errors import TaskAlongError
from .execution import CheckBinding, InstructionBundle, PolicyResolver, SandboxPolicy, ToolPolicy
from .qualification import EvidenceStore, QualificationReceipt, TrustPolicy, evaluate
from .store import encode, now
from .validation import canonical_bytes, digest, loads, screen_sensitive


PROJECTION = "codex-v1-fixture/1"
_POLICIES = {cls.schema_name.replace("-", "_"): cls for cls in
             (InstructionBundle, ToolPolicy, SandboxPolicy, CheckBinding)}


def _refuse(code="execution_projection_unsupported"):
    raise TaskAlongError(code, "The selected execution context is unresolved or outside the implemented fixture projection.", exit_code=3)


def _require(store):
    if store.format_version != 3:
        _refuse("store_upgrade_required")


def exact_document(store, content_digest, cls):
    """Resolve by content and type; never select the last revision or an ID alias."""
    _require(store)
    row = store.db.execute("SELECT kind,schema_version,document FROM document_history WHERE digest=?", (content_digest,)).fetchone()
    if row is None or row["kind"] != cls.schema_name.replace("-", "_"):
        _refuse("execution_document_unresolved")
    document = cls.from_dict(loads(row["document"]))
    if document.digest != content_digest or document.to_dict()["schema_version"] != row["schema_version"]:
        _refuse("store_integrity")
    return document


def configure_execution(store, *, binding, installation, provider, policies,
                        runtime_profile_digest, receipts, trust, evidence, context, projection):
    """Trusted OS control-plane registration, not a worker/task JSON command.

    Registration does not qualify dispatch. The immutable projection freezes
    route/policy identities; only explicit trust/receipt updates remain mutable.
    Evidence bytes are private content-addressed blobs, not arbitrary paths.
    """
    _require(store)
    if projection != PROJECTION:
        _refuse()
    b = ExecutionBinding.from_dict(binding)
    i = HarnessInstallation.from_dict(installation)
    p = ProviderProfile.from_dict(provider)
    if type(policies) not in (list, tuple) or len(policies) > 64:
        _refuse("policy_unresolved")
    try:
        resolver = PolicyResolver(tuple(_POLICIES[item["kind"]].from_dict(item) for item in policies))
    except (KeyError, TypeError):
        _refuse("policy_unresolved")
    trust = TrustPolicy.from_dict(trust)
    evidence = EvidenceStore.from_blobs(evidence)
    if type(receipts) not in (list, tuple) or len(receipts) > 64:
        _refuse("qualification_input_invalid")
    receipts = tuple(QualificationReceipt.from_dict(item) for item in receipts)
    context = loads(canonical_bytes(context))
    screen_sensitive(context)
    # Validate the exact M2 context and receipt subjects now, without treating
    # an unsatisfied decision as authority or as a registration error.
    evaluate(b, installation=i, provider=p, context=context, mode="start", receipts=receipts,
             trust=trust, evidence=evidence, now=now(), minimum_level="offline_fixture")
    profile = exact_document(store, runtime_profile_digest, RuntimeProfile)
    sandbox = store.setting("command_sandbox")
    if not sandbox or sandbox.get("qualification") != "synthetic":
        _refuse("check_binding_unresolved")
    registration = {"projection": projection, "binding_digest": b.digest,
                    "runtime_profile_digest": profile.digest, "context": context,
                    "policy_digests": sorted(doc.digest for doc in resolver.documents),
                    "check_launcher_digest": digest(sandbox), "transport": "operator_registered_fixture"}
    registration["digest"] = digest(registration)
    # Check identity links and representability before persisting this route.
    _projection(b, i, p, resolver, profile.to_dict(), registration)
    for document in (b, i, p, *resolver.documents):
        store.record_document(document, operation_key="execution-document:" + document.digest)
    refs = []
    for key, data in evidence._entries:
        ref = store.put_blob(data)
        refs.append(ref["sha256"])
    setting = {"receipts": [item.to_dict() for item in receipts], "trust": trust.to_dict(), "evidence": sorted(refs)}
    canonical_bytes(setting)
    with store.transaction() as db:
        row = db.execute("SELECT document FROM execution_projections WHERE binding_digest=?", (b.digest,)).fetchone()
        if row is not None and loads(row[0]) != registration:
            _refuse("execution_registration_conflict")
        db.execute("INSERT OR IGNORE INTO execution_projections VALUES(?,?)", (b.digest, encode(registration)))
        db.execute("INSERT INTO settings VALUES(?,?) ON CONFLICT(name) DO UPDATE SET document=excluded.document",
                   ("execution-trust:" + b.digest, encode(setting)))
    return {"binding_digest": b.digest, "projection_digest": registration["digest"],
            "trust_digest": trust.digest, "production_dispatch_allowed": False}


def registered_profile(store, binding_digest):
    _require(store)
    row = store.db.execute("SELECT document FROM execution_projections WHERE binding_digest=?", (binding_digest,)).fetchone()
    if row is None:
        _refuse("execution_binding_unregistered")
    registration = loads(row[0])
    if registration.get("binding_digest") != binding_digest or digest(registration) != registration.get("digest"):
        _refuse("store_integrity")
    return exact_document(store, registration["runtime_profile_digest"], RuntimeProfile).to_dict(), registration


def _projection(binding, installation, provider, policies, profile, registration):
    b, i, p = binding.to_dict(), installation.to_dict(), provider.to_dict()
    for field, document in (("installation_digest", installation), ("provider_profile_digest", provider)):
        if b[field] != document.digest:
            _refuse("execution_identity_mismatch")
    instructions = policies.resolve(b["instruction_bundle_digest"], InstructionBundle).to_dict()
    tools = policies.resolve(b["tool_policy_digest"], ToolPolicy).to_dict()
    worker = policies.resolve(b["worker_sandbox_digest"], SandboxPolicy).to_dict()
    check = policies.resolve(b["check_binding_digest"], CheckBinding).to_dict()
    verifier = policies.resolve(check["sandbox_digest"], SandboxPolicy).to_dict()
    architecture = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x86_64"
    if (registration["projection"] != PROJECTION or profile["qualification"] != "synthetic"
            or i["harness"] != "codex" or i["adapter_id"] != profile["adapter"] or i["adapter_id"] != "codex-cli"
            or i["driver_version"] != "codex-v1-fixture-1" or i["cli_version"] != profile["runtime_version"]
            or i["executable_digest"] != profile["executable_sha256"]
            or i["platform"] != {"os": sys.platform, "architecture": architecture, "backend_id": "synthetic-fixture"}
            or profile["permission_policy"] != {} or profile["toolchain_read_roots"]
            or instructions["texts"] or tools["allowed_tools"] != ["fixture.edit"]
            or instructions["protective_policy_digest"] != profile["permission_policy_digest"]
            or worker["role"] != "worker" or verifier["role"] != "independent_check"
            or worker["backend_id"] != "synthetic-fixture" or verifier["backend_id"] != "synthetic-fixture"
            or worker["permission_policy_digest"] != profile["permission_policy_digest"]
            or p["harness"] != "codex" or p["provider"] != "openai-account"
            or p["model"]["requested"] != profile["model"] or p["effort"] != profile["reasoning_effort"]
            or p["service_tier"] != profile["service_tier"] or p["auth"]["credential_ref"] != profile["credential_source_ref"]
            or p["auxiliary_routes"]):
        _refuse()
    # Even a non-hard non-null limit cannot be silently discarded by v1.
    if b["budget"]["max_cost_micro_usd"] is not None or b["budget"]["max_tokens"] is not None:
        _refuse("hard_budget_unsupported")
    return check, verifier


def resolve(store, spec, *, mode="start", authority_id=None):
    """Resolve current trusted facts; caller owns the transaction/fence boundary."""
    profile, registration = registered_profile(store, spec["execution"]["binding_digest"])
    b = exact_document(store, registration["binding_digest"], ExecutionBinding)
    bv = b.to_dict()
    installation = exact_document(store, bv["installation_digest"], HarnessInstallation)
    provider = exact_document(store, bv["provider_profile_digest"], ProviderProfile)
    docs = []
    for key in registration["policy_digests"]:
        row = store.db.execute("SELECT kind FROM document_history WHERE digest=?", (key,)).fetchone()
        if row is None or row[0] not in _POLICIES:
            _refuse("policy_unresolved")
        docs.append(exact_document(store, key, _POLICIES[row[0]]))
    policies = PolicyResolver(tuple(docs))
    check, sandbox = _projection(b, installation, provider, policies, profile, registration)
    check_profile = exact_document(store, check["runtime_profile_digest"], RuntimeProfile).to_dict()
    if (check_profile["qualification"] != "synthetic" or check_profile["adapter"] != "codex-cli"
            or check_profile["permission_policy"] != {} or check_profile["toolchain_read_roots"]
            or check_profile["digest"] == profile["digest"]
            or check_profile["permission_policy_digest"] != sandbox["permission_policy_digest"]
            or digest(store.setting("command_sandbox")) != registration["check_launcher_digest"]):
        _refuse("check_binding_mismatch")
    effective_context = digest([doc.to_dict() for doc in sorted(policies.documents, key=lambda item: item.digest)])
    if registration["context"]["effective_context_digest"] != effective_context:
        _refuse("execution_context_mismatch")
    if (spec["qualification"] != "synthetic" or spec["permissions"]["inference_destination_id"] != profile["inference_destination_id"]
            or digest(spec["checks"]) != check["checks_digest"] or spec["review"]["config_digest"] != check["review_config_digest"]):
        _refuse("execution_identity_mismatch")
    budget = spec["budget"]
    if budget["max_attempts"] > bv["budget"]["max_attempts"] or budget["total_active_seconds"] > bv["budget"]["wall_seconds"]:
        _refuse("binding_budget_exceeded")
    if mode not in {"start", "restart"}:
        _refuse("native_resume_unsupported")
    setting = store.setting("execution-trust:" + b.digest)
    if setting is None:
        _refuse("qualification_unresolved")
    trust = TrustPolicy.from_dict(setting["trust"])
    evidence = EvidenceStore.from_blobs({key:store.get_blob(key) for key in setting["evidence"]})
    decision = evaluate(b, installation=installation, provider=provider, context=registration["context"], mode="start",
                       receipts=setting["receipts"], trust=trust, evidence=evidence, now=now(), minimum_level="offline_fixture")
    if not decision.decision.to_dict()["requirements_satisfied"]:
        _refuse("qualification_unsatisfied")
    from .executors.registry import executor_for
    executor_for(profile).preflight(qualification=spec["qualification"], budget=budget)
    executor_for(check_profile).preflight(qualification=spec["qualification"], budget=budget)
    # The check executable is independent of worker selection; its actual bytes
    # are checked before any verifier effect, including fixture launches.
    launcher = store.setting("command_sandbox")
    from pathlib import Path
    try:
        if hashlib.sha256(Path(launcher["executable"]).read_bytes()).hexdigest() != launcher["sha256"]:
            _refuse("sandbox_changed")
    except OSError:
        _refuse("sandbox_changed")
    snapshot = {"kind": "admission_snapshot", "schema_version": "2.2", "spec_digest": spec["digest"],
                "binding": bv, "installation": installation.to_dict(), "provider": provider.to_dict(),
                "policies": [doc.to_dict() for doc in policies.documents], "projection": registration,
                "decision": decision.decision.to_dict(), "report": decision.report.to_dict(),
                "runtime_profile_digest": profile["digest"], "check_profile_digest": check_profile["digest"],
                "trust_digest": trust.digest, "authority_id": authority_id,
                "limitations": ["Synthetic protocol transport; no actual provider, instruction/tool isolation or containment proof."]}
    snapshot["digest"] = digest(snapshot)
    return snapshot, profile, check_profile
