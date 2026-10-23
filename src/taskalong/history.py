"""Exact immutable document history; storage supplies no current authority."""
from .bindings import ExecutionBinding, HarnessInstallation, ProviderProfile
from .contracts import RuntimeProfile
from .errors import TaskAlongError
from .qualification import QualificationDecision
from .execution import InstructionBundle, ToolPolicy, SandboxPolicy, CheckBinding
from .executors.config import DriverConfig
from .store import encode, key_check, now
from .validation import digest, loads


_TYPES = {"runtime_profile":RuntimeProfile, "harness_installation":HarnessInstallation, "provider_profile":ProviderProfile,
          "execution_binding":ExecutionBinding, "qualification_decision":QualificationDecision}
_TYPES.update({cls.schema_name.replace("-", "_"): cls for cls in (InstructionBundle, ToolPolicy, SandboxPolicy, CheckBinding)})
_TYPES["driver_config"] = DriverConfig


def _require(store):
    if store.format_version not in (2, 3, 4):
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
    _require(store)
    key_check(operation_key)
    if type(document) not in _TYPES.values():
        raise TaskAlongError("history_document_invalid", "Only validated immutable profile/binding/decision documents can be stored.")
    document = type(document)(document.to_bytes())
    value = document.to_dict()
    if value["schema_version"] == "2.2" and store.format_version < 3:
        raise TaskAlongError("store_upgrade_required", "V2 execution policy history requires format 3.", exit_code=3)
    if value["schema_version"] == "2.3" and store.format_version < 4:
        raise TaskAlongError("store_upgrade_required", "Driver configuration history requires explicit format-4 maintenance.", exit_code=3)
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
    if type(kind) is not str or kind not in _TYPES or type(identity) is not str or not 1 <= len(identity) <= 256:
        raise TaskAlongError("history_document_invalid", "An exact supported history kind and identity are required.")
    records = []
    for row in store.db.execute("SELECT digest,schema_version,document FROM document_history WHERE kind=? AND identity=? ORDER BY recorded_at,digest LIMIT 1001", (kind,identity)):
        if len(records) == 1000:
            raise TaskAlongError("history_limit", "This history exceeds the bounded reader; no partial history is returned.", exit_code=3)
        document = _TYPES[kind].from_dict(loads(row["document"]))
        value = document.to_dict()
        if document.digest != row["digest"] or _identity(value) != identity or value["schema_version"] != row["schema_version"]:
            raise TaskAlongError("store_integrity", "Historical columns disagree with the immutable document.", exit_code=70)
        records.append(document)
    return tuple(records)
