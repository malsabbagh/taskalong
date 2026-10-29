"""Exact immutable document history; storage supplies no current authority."""
from .bindings import ExecutionBinding, HarnessInstallation, ProviderProfile
from .contracts import RuntimeProfile
from .muse_handoff import MuseConfiguration
from .muse_lifecycle import MuseProductionConfiguration
from .errors import TaskAlongError
from .qualification import QualificationDecision
from .execution import InstructionBundle, ToolPolicy, SandboxPolicy, CheckBinding
from .executors.config import AntigravityDriverConfig, CursorDriverConfig, DriverConfig, OllamaDriverConfig, read_driver_config
from .store import encode, key_check, now
from .validation import digest, loads
from .trial import (LocalReviewAssessment, TrialActivation, TrialDriverConfig, TrialPacketProjection,
                    TrialReviewerProfile, TrialReviewReceipt, TrialPublishIntent, TrialTaskSpec, TrialWorkerPacket)


_TYPES = {"runtime_profile":RuntimeProfile, "harness_installation":HarnessInstallation, "provider_profile":ProviderProfile,
          "execution_binding":ExecutionBinding, "qualification_decision":QualificationDecision}
_TYPES.update({cls.schema_name.replace("-", "_"): cls for cls in (InstructionBundle, ToolPolicy, SandboxPolicy, CheckBinding)})
_TYPES["driver_config"] = DriverConfig
_TYPES["capture_config"] = MuseConfiguration
_TRIAL_TYPES = {cls.schema_name.replace("-", "_"): cls for cls in
                (TrialDriverConfig, TrialTaskSpec, TrialWorkerPacket, TrialPacketProjection, TrialReviewerProfile,
                 TrialActivation, TrialPublishIntent, TrialReviewReceipt, LocalReviewAssessment)}


def _require(store):
    if store.format_version not in (2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12):
        raise TaskAlongError("store_upgrade_required", "Versioned history requires the explicit backed-up store upgrade.", exit_code=3)


def _identity(document):
    kind = document["kind"]
    if kind == "harness_installation":
        return document["installation_id"]
    if kind in {"runtime_profile", "provider_profile"}:
        return document["profile_id"]
    if kind == "qualification_decision":
        return document["subject"]["binding_digest"] + ":" + document["mode"]
    return document["digest"]


def record_document(store, document, *, operation_key):
    from .trial import TrialDocument
    if isinstance(document, TrialDocument) and store.format_version < 8:
        raise TaskAlongError("store_upgrade_required", "Trial document history requires explicit format-8 maintenance.", exit_code=3)
    _require(store)
    key_check(operation_key)
    if type(document) not in (*_TYPES.values(), OllamaDriverConfig, CursorDriverConfig, AntigravityDriverConfig, MuseProductionConfiguration, *_TRIAL_TYPES.values()):
        raise TaskAlongError("history_document_invalid", "Only validated immutable profile/binding/decision documents can be stored.")
    document = type(document)(document.to_bytes())
    value = document.to_dict()
    if value["schema_version"] == "2.12" and store.format_version < 12:
        raise TaskAlongError("store_upgrade_required", "Production Muse requires format-12 maintenance.", exit_code=3)
    if value["schema_version"] == "2.9" and store.format_version < 9:
        raise TaskAlongError("store_upgrade_required", "Muse configuration requires explicit format-9 maintenance.", exit_code=3)
    if value["schema_version"] == "2.2" and store.format_version < 3:
        raise TaskAlongError("store_upgrade_required", "V2 execution policy history requires format 3.", exit_code=3)
    if value["schema_version"] == "2.3" and store.format_version < 4:
        raise TaskAlongError("store_upgrade_required", "Driver configuration history requires explicit format-4 maintenance.", exit_code=3)
    if value["schema_version"] == "2.4" and store.format_version < 5:
        raise TaskAlongError("store_upgrade_required", "Ollama fixture history requires explicit format-5 maintenance.", exit_code=3)
    if value["schema_version"] == "2.5" and store.format_version < 6:
        raise TaskAlongError("store_upgrade_required", "Cursor fixture history requires explicit format-6 maintenance.", exit_code=3)
    if value["schema_version"] == "2.6" and store.format_version < 7:
        raise TaskAlongError("store_upgrade_required", "Antigravity fixture history requires explicit format-7 maintenance.", exit_code=3)
    request = {"kind":value["kind"], "identity":_identity(value), "digest":document.digest, "schema_version":value["schema_version"]}
    request_digest = digest(request, exclude_digest=False)
    response = request | {"historical_only":True}
    with store.transaction() as db:
        prior = store._prior(db, "history.record", "", operation_key, request_digest)
        if prior is not None:
            return prior
        row = db.execute("SELECT kind,identity,schema_version,document FROM document_history WHERE digest=?", (document.digest,)).fetchone()
        if row is not None and tuple(row) != (value["kind"], request["identity"], value["schema_version"], document.to_bytes().decode()):
            raise TaskAlongError("store_integrity", "The historical content identity disagrees with its stored bytes.", exit_code=70)
        db.execute("INSERT OR IGNORE INTO document_history VALUES(?,?,?,?,?,?)", (value["kind"], request["identity"], document.digest,
                   value["schema_version"], document.to_bytes().decode(), now()))
        db.execute("INSERT INTO operations VALUES(?,?,?,?,?)", ("history.record", "", operation_key, request_digest, encode(response)))
    return response


def document_history(store, kind, identity):
    _require(store)
    if type(kind) is not str or kind not in (_TYPES | _TRIAL_TYPES) or type(identity) is not str or not 1 <= len(identity) <= 256:
        raise TaskAlongError("history_document_invalid", "An exact supported history kind and identity are required.")
    records = []
    for row in store.db.execute("SELECT digest,schema_version,document FROM document_history WHERE kind=? AND identity=? ORDER BY recorded_at,digest LIMIT 1001", (kind,identity)):
        if len(records) == 1000:
            raise TaskAlongError("history_limit", "This history exceeds the bounded reader; no partial history is returned.", exit_code=3)
        value = loads(row["document"])
        if value.get("schema_version") == "2.12":
            if store.format_version < 12 or kind != "driver_config":
                raise TaskAlongError("store_integrity", "Production Muse history is outside its format fence.", exit_code=70)
            document = MuseProductionConfiguration.from_dict(value)
        elif value.get("schema_version") == "2.8":
            if store.format_version < 8 or kind not in _TRIAL_TYPES:
                raise TaskAlongError("store_integrity", "Trial history is outside its explicit format fence.", exit_code=70)
            document = _TRIAL_TYPES[kind].from_dict(value)
        else:
            if kind not in _TYPES:
                raise TaskAlongError("store_integrity", "The historical kind has no reader for this version.", exit_code=70)
            document = read_driver_config(value) if kind == "driver_config" else _TYPES[kind].from_dict(value)
        value = document.to_dict()
        if document.digest != row["digest"] or _identity(value) != identity or value["schema_version"] != row["schema_version"]:
            raise TaskAlongError("store_integrity", "Historical columns disagree with the immutable document.", exit_code=70)
        records.append(document)
    return tuple(records)
