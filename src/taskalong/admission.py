"""Trusted local resolution for explicitly simulated protocol projections.

Portable histories supply identity, never current authority. The OS operator
registers exact fixture transport/policy content separately from task submission.
Mutable trust is re-evaluated before preparation and dispatch. No real provider
or production policy enforcement is admitted by this module.
"""
from __future__ import annotations

import hashlib

from .bindings import ExecutionBinding, HarnessInstallation, ProviderProfile
from .contracts import RuntimeProfile
from .errors import TaskAlongError
from .execution import CheckBinding, InstructionBundle, PolicyResolver, SandboxPolicy, ToolPolicy
from .executors.config import AntigravityDriverConfig, CursorDriverConfig, DriverConfig, OllamaDriverConfig, read_driver_config
from .qualification import EvidenceStore, QualificationReceipt, TrustPolicy, evaluate
from .store import encode, now
from .validation import canonical_bytes, digest, loads, screen_sensitive


PROJECTION = "codex-v1-fixture/1"
_POLICIES = {cls.schema_name.replace("-", "_"): cls for cls in
             (InstructionBundle, ToolPolicy, SandboxPolicy, CheckBinding)}


def _refuse(code="execution_projection_unsupported"):
    raise TaskAlongError(code, "The selected execution context is unresolved or outside the implemented fixture projection.", exit_code=3)


def _require(store):
    if store.format_version not in (3, 4, 5, 6, 7, 8, 9, 10):
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
                        runtime_profile_digest=None, driver_config=None, receipts, trust, evidence, context, projection):
    """Trusted OS control-plane registration, not a worker/task JSON command.

    Registration does not qualify dispatch. The immutable projection freezes
    route/policy identities; only explicit trust/receipt updates remain mutable.
    Evidence bytes are private content-addressed blobs, not arbitrary paths.
    """
    _require(store)
    is_driver = driver_config is not None
    if is_driver and runtime_profile_digest is not None:
        _refuse("execution_registration_conflict")
    profile = read_driver_config(driver_config) if is_driver else exact_document(store, runtime_profile_digest, RuntimeProfile)
    version = profile.to_dict()["schema_version"] if is_driver else "2.2"
    if version == "2.8":
        _refuse("trial_runtime_unqualified")
    if is_driver and store.format_version < {"2.3": 4, "2.4": 5, "2.5": 6, "2.6": 7}[version]:
        _refuse("store_upgrade_required")
    if not is_driver and projection != PROJECTION:
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
    sandbox = store.setting("command_sandbox")
    if not sandbox or sandbox.get("qualification") != "synthetic":
        _refuse("check_binding_unresolved")
    registration = {"projection": projection, "binding_digest": b.digest,
                    "context": context,
                    "policy_digests": sorted(doc.digest for doc in resolver.documents),
                    "check_launcher_digest": digest(sandbox), "transport": "operator_registered_fixture"}
    if is_driver:
        registration.update(schema_version=version, driver_config_digest=profile.digest)
    else:
        registration["runtime_profile_digest"] = profile.digest
    registration["digest"] = digest(registration)
    # Check identity links and representability before persisting this route.
    from .executors.registry import contract_for
    contract_for(profile.to_dict(), task_version=version, projection=projection).represent(
        b, i, p, resolver, profile.to_dict(), registration)
    documents = (b, i, p, *resolver.documents, profile) if is_driver else (b, i, p, *resolver.documents)
    for document in documents:
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


def _registration(store, binding_digest):
    _require(store)
    row = store.db.execute("SELECT document FROM execution_projections WHERE binding_digest=?", (binding_digest,)).fetchone()
    if row is None:
        _refuse("execution_binding_unregistered")
    registration = loads(row[0])
    if registration.get("binding_digest") != binding_digest or digest(registration) != registration.get("digest"):
        _refuse("store_integrity")
    return registration


def registered_profile(store, binding_digest):
    registration = _registration(store, binding_digest)
    if registration.get("projection") != PROJECTION or "runtime_profile_digest" not in registration:
        _refuse()
    return exact_document(store, registration["runtime_profile_digest"], RuntimeProfile).to_dict(), registration


def registered_driver_config(store, binding_digest):
    if store.format_version not in (4, 5, 6, 7, 8, 9, 10):
        _refuse("store_upgrade_required")
    registration = _registration(store, binding_digest)
    version = registration.get("schema_version")
    if version not in ("2.3", "2.4", "2.5", "2.6") or "driver_config_digest" not in registration:
        _refuse()
    if store.format_version < {"2.3": 4, "2.4": 5, "2.5": 6, "2.6": 7}[version]:
        _refuse("store_upgrade_required")
    reader = {"2.3": DriverConfig, "2.4": OllamaDriverConfig, "2.5": CursorDriverConfig, "2.6": AntigravityDriverConfig}[version]
    config = exact_document(store, registration["driver_config_digest"], reader).to_dict()
    from .executors.registry import contract_for
    contract_for(config, task_version=version, projection=registration["projection"])
    return config, registration


def worker_contract(store, spec, configuration):
    """Resolve an immutable driver selection; this does not grant dispatch."""
    from .executors.registry import contract_for
    if spec["schema_version"] == "2.9":
        from .muse_handoff import configuration as muse_configuration, PROJECTION
        retained = muse_configuration(store, spec["execution"]["driver_config_digest"])
        if retained != configuration:
            _refuse("execution_identity_mismatch")
        return contract_for(retained, task_version="2.9", projection=PROJECTION), None
    if spec["schema_version"] in {"1.0", "2.7"}:
        return contract_for(configuration), None
    getter = registered_driver_config if spec["schema_version"] in {"2.3", "2.4", "2.5", "2.6"} else registered_profile
    retained, registration = getter(store, spec["execution"]["binding_digest"])
    if retained != configuration:
        _refuse("execution_identity_mismatch")
    binding = exact_document(store, registration["binding_digest"], ExecutionBinding).to_dict()
    provider = exact_document(store, binding["provider_profile_digest"], ProviderProfile).to_dict()
    return contract_for(configuration, task_version=spec["schema_version"], projection=registration["projection"]), provider


def resolve(store, spec, *, mode="start", authority_id=None):
    """Resolve current trusted facts; caller owns the transaction/fence boundary."""
    if spec["schema_version"] == "2.9":
        from .muse_handoff import resolve as resolve_muse
        return resolve_muse(store, spec, mode=mode, authority_id=authority_id)
    is_driver = spec["schema_version"] in {"2.3", "2.4", "2.5", "2.6"}
    getter = registered_driver_config if is_driver else registered_profile
    profile, registration = getter(store, spec["execution"]["binding_digest"])
    if is_driver and spec["execution"]["driver_config_digest"] != profile["digest"]:
        _refuse("execution_identity_mismatch")
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
    from .executors.registry import contract_for
    contract = contract_for(profile, task_version=spec["schema_version"], projection=registration["projection"])
    check, sandbox = contract.represent(b, installation, provider, policies, profile, registration)
    check_profile = exact_document(store, check["runtime_profile_digest"], RuntimeProfile).to_dict()
    if (check_profile["qualification"] != "synthetic" or check_profile["adapter"] != "codex-cli"
            or check_profile["permission_policy"] != {} or check_profile["toolchain_read_roots"]
            or check_profile["digest"] == profile["digest"]
            or check_profile["permission_policy_digest"] != sandbox["permission_policy_digest"]
            or digest(store.setting("command_sandbox")) != registration["check_launcher_digest"]):
        _refuse("check_binding_mismatch")
    policy_values = [doc.to_dict() for doc in sorted(policies.documents, key=lambda item: item.digest)]
    effective_context = digest({"policies":policy_values,"driver_config_digest":profile["digest"]}) if is_driver else digest(policy_values)
    if registration["context"]["effective_context_digest"] != effective_context:
        _refuse("execution_context_mismatch")
    destination = provider.to_dict()["profile_id"] if is_driver else profile["inference_destination_id"]
    if (spec["qualification"] != "synthetic" or spec["permissions"]["inference_destination_id"] != destination
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
    evaluated_at = now()
    arguments = dict(installation=installation, provider=provider, context=registration["context"],
        receipts=setting["receipts"], trust=trust, evidence=evidence, now=evaluated_at, minimum_level="offline_fixture")
    decision = evaluate(b, mode="start", **arguments)
    if not decision.decision.to_dict()["requirements_satisfied"]:
        _refuse("qualification_unsatisfied")
    lookup, capture_refs = None, None
    if spec["schema_version"] == "2.4":
        from .runtime_profiles import FixtureRouteObservation, require_route_capture
        lookup = evaluate(b, mode="provider_lookup", **arguments)
        capture_refs = require_route_capture(decision, lookup,
            FixtureRouteObservation.from_dict(profile["fixture_route_observation"]), evidence)
    from .executors.registry import executor_for
    contract.factory(profile, provider.to_dict()).preflight(qualification=spec["qualification"], budget=budget)
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
    snapshot = {"kind": "admission_snapshot", "schema_version": spec["schema_version"], "spec_digest": spec["digest"],
                "binding": bv, "installation": installation.to_dict(), "provider": provider.to_dict(),
                "policies": [doc.to_dict() for doc in policies.documents], "projection": registration,
                "decision": decision.decision.to_dict(), "report": decision.report.to_dict(),
                "check_profile_digest": check_profile["digest"],
                "trust_digest": trust.digest, "authority_id": authority_id,
                "limitations": ["Synthetic protocol transport; no actual provider, instruction/tool isolation or containment proof."]}
    if is_driver:
        snapshot["driver_config"] = profile
    else:
        snapshot["runtime_profile_digest"] = profile["digest"]
    if lookup is not None:
        snapshot.update(provider_lookup_decision=lookup.decision.to_dict(), provider_lookup_report=lookup.report.to_dict(),
            provider_route_observation_digests=list(capture_refs))
        snapshot["limitations"].append("Offline Ollama fixture: no server request, remote cessation or real cost accounting proof.")
    snapshot["digest"] = digest(snapshot)
    return snapshot, profile, check_profile
