"""One-shot local-controller exposure history; never provider settlement.

Private writers run only inside the existing authoritative Store transaction.
The public view is read-only. There is deliberately no reset, settlement,
retry, PID signalling, credential lookup or task-selected observer interface.
"""
import re
from datetime import datetime
from .errors import TaskAlongError
from .store import encode, now
from .validation import canonical_bytes, digest, loads

_PHASES = {"reserved", "release_attempted", "not_sent", "local_stopped", "local_unknown"}
_KEYS = {"format", "run_id", "attempt_id", "phase", "configuration_digest",
    "runtime_subject_digest", "previous_digest", "observation", "at", "digest"}


def _fail(code="muse_exposure_invalid"):
    raise TaskAlongError(code, "Muse exposure is held or inconsistent; inspect retained evidence without redispatch.",
        exit_code=5, effect_outcome="not_sent")


def _require(store, db=None):
    if store.format_version != 13:
        _fail("store_upgrade_required")
    if db is not None and (db is not store.db or not db.in_transaction):
        _fail("muse_exposure_transaction_required")


def _observation(store, event, attempt):
    phase=event["phase"]; value=event["observation"]
    for key in ("configuration_digest","runtime_subject_digest","digest"):
        if type(event[key]) is not str or re.fullmatch(r"[a-f0-9]{64}",event[key]) is None: _fail()
    if type(event["at"]) is not str or not event["at"].endswith("Z"): _fail()
    datetime.fromisoformat(event["at"].replace("Z","+00:00"))
    if phase=="reserved":
        expected={"local_invocation_limit":1,"remote_usage":"not_observed","account_cap_enforced":False}
        if canonical_bytes(value)!=canonical_bytes(expected): _fail()
    elif phase=="release_attempted":
        receipt=attempt.get("process_receipt")
        if type(receipt) is not dict: _fail()
        expected={"owned_receipt_digest":digest(receipt),"remote_usage":"unknown","provider_cancellation_confirmed":False}
        if canonical_bytes(value)!=canonical_bytes(expected): _fail()
    else:
        keys={"process_digest","local_cessation_confirmed","remote_usage","provider_cancellation_confirmed","account_cap_enforced","stop_reason"}
        if type(value) is not dict or set(value)!=keys: _fail()
        process=attempt.get("process")
        if type(process) is not dict or value["process_digest"]!=digest(process): _fail()
        complete=(process.get("termination_confirmed") is True and process.get("group_termination_confirmed") is True
            and process.get("unaccounted_descendants") is False)
        no_send=(phase=="not_sent" and attempt.get("spawn_phase")=="not_dispatched"
            and not attempt.get("process_receipt") and process.get("termination_confirmed") is True
            and store.db.execute("SELECT 1 FROM operations WHERE command='executor.prepare' AND run_id=? AND operation_key=?",
                (attempt["run_id"],attempt["attempt_id"])).fetchone() is None)
        if phase=="not_sent" and not no_send: _fail()
        if phase=="local_stopped" and not complete: _fail()
        if phase=="local_unknown" and value["local_cessation_confirmed"] is not False: _fail()
        expected={"process_digest":digest(process),"local_cessation_confirmed":phase!="local_unknown",
            "remote_usage":"not_sent" if no_send else "unknown","provider_cancellation_confirmed":False,
            "account_cap_enforced":False,"stop_reason":"not_dispatched" if no_send else
                "timeout" if process.get("timed_out") is True else "cancelled" if process.get("cancelled") is True else
                "output_limit" if process.get("output_limited") is True else "local_result"}
        if canonical_bytes(value)!=canonical_bytes(expected): _fail()


def _history(store):
    try:
        return _read_history(store)
    except TaskAlongError as exc:
        if exc.code in {"store_upgrade_required","muse_exposure_invalid","muse_exposure_limit"}:
            raise
        _fail()
    except (KeyError, TypeError, ValueError, AttributeError):
        _fail()


def _read_history(store):
    _require(store)
    rows=store.db.execute("SELECT sequence,attempt_id,run_id,phase,document FROM muse_exposure_events ORDER BY sequence LIMIT 1001").fetchall()
    if len(rows)>1000: _fail("muse_exposure_limit")
    histories={}
    for row in rows:
        event=loads(row["document"])
        if (set(event)!=_KEYS or event["format"]!="muse-exposure-event/1"
                or event["phase"] not in _PHASES or event["digest"]!=digest(event)
                or any(event[k]!=row[k] for k in ("attempt_id","run_id","phase"))): _fail()
        items=histories.setdefault(event["attempt_id"],[])
        if not items:
            if event["phase"]!="reserved" or event["previous_digest"] is not None: _fail()
        else:
            previous=items[-1]
            if (event["previous_digest"]!=previous["digest"]
                    or any(event[k]!=previous[k] for k in ("run_id","configuration_digest","runtime_subject_digest"))
                    or previous["phase"] not in {"reserved","release_attempted"}
                    or event["phase"]=="reserved"
                    or (event["phase"]=="release_attempted" and previous["phase"]!="reserved")
                    or (event["phase"]=="not_sent" and previous["phase"]!="reserved")): _fail()
        # Bind every observation back to the exact original core-owned attempt.
        run=store.run(event["run_id"]); attempt=store.detail("attempts",event["attempt_id"])
        spec=store.spec(run)
        if (spec["schema_version"]!="2.12" or attempt["run_id"]!=run["run_id"]
                or attempt.get("driver_config_digest")!=event["configuration_digest"]
                or spec["execution"]["driver_config_digest"]!=event["configuration_digest"]
                or attempt.get("admission",{}).get("runtime_subject_digest")!=event["runtime_subject_digest"]): _fail()
        _observation(store,event,attempt)
        items.append(event)
    return histories


def _append(store, db, attempt, phase, observation):
    _require(store,db)
    history=_history(store).get(attempt["attempt_id"],[])
    previous=history[-1] if history else None
    event={"format":"muse-exposure-event/1","run_id":attempt["run_id"],"attempt_id":attempt["attempt_id"],
        "phase":phase,"configuration_digest":attempt["driver_config_digest"],
        "runtime_subject_digest":attempt["admission"]["runtime_subject_digest"],
        "previous_digest":previous["digest"] if previous else None,"observation":observation,"at":now()}
    event["digest"]=digest(event)
    db.execute("INSERT INTO muse_exposure_events(attempt_id,run_id,phase,document) VALUES(?,?,?,?)",
        (event["attempt_id"],event["run_id"],phase,encode(event)))
    _history(store)
    return event


def reserve(store, db, attempt):
    """Called after authoritative attempt INSERT, in its same transaction."""
    _require(store,db)
    histories=_history(store)
    if attempt["attempt_id"] in histories: _fail("muse_redispatch_forbidden")
    # Global within this Store: changing a destination alias is not an escape.
    if any(items[-1]["phase"]!="not_sent" for items in histories.values()):
        _fail("muse_remote_exposure_held")
    return _append(store,db,attempt,"reserved",{
        "local_invocation_limit":1,"remote_usage":"not_observed", "account_cap_enforced":False})


def before_release(store, db, attempt, receipt):
    """Durably mark possible exposure before the owned gate can be opened."""
    _require(store,db)
    items=_history(store).get(attempt["attempt_id"],[])
    if not items or items[-1]["phase"]!="reserved": _fail("muse_redispatch_forbidden")
    return _append(store,db,attempt,"release_attempted",{
        "owned_receipt_digest":digest(receipt),"remote_usage":"unknown",
        "provider_cancellation_confirmed":False})


def finish(store, db, attempt, process, *, local_confirmed, not_dispatched):
    """Local observation only. Never clear a possibly released exposure."""
    _require(store,db)
    items=_history(store).get(attempt["attempt_id"],[])
    if not items: _fail()
    if items[-1]["phase"] not in {"reserved","release_attempted"}: _fail("muse_redispatch_forbidden")
    released=any(e["phase"]=="release_attempted" for e in items)
    # The workflow computes these from authoritative operations and typed owned
    # observations, inside its fenced finish. No caller-supplied usage settles.
    no_send=(not released and not_dispatched is True and local_confirmed is True)
    complete=(local_confirmed is True and process.get("termination_confirmed") is True
        and process.get("group_termination_confirmed") is True
        and process.get("unaccounted_descendants") is False)
    phase="not_sent" if no_send else "local_stopped" if complete else "local_unknown"
    return _append(store,db,attempt,phase,{
        "process_digest":digest(process),"local_cessation_confirmed":complete or no_send,
        "remote_usage":"not_sent" if no_send else "unknown",
        "provider_cancellation_confirmed":False,"account_cap_enforced":False,
        "stop_reason":"not_dispatched" if no_send else
            "timeout" if process.get("timed_out") is True else
            "cancelled" if process.get("cancelled") is True else
            "output_limit" if process.get("output_limited") is True else "local_result"})


def view(store):
    """Recovery inspection launches nothing and changes no records."""
    histories=_history(store)
    entries=[]
    for attempt_id,items in histories.items():
        last=items[-1]; phase=last["phase"]
        entries.append({"run_id":last["run_id"],"attempt_id":attempt_id,"phase":phase,
            "event_digest":last["digest"],"remote_usage":"not_sent" if phase=="not_sent" else "unknown",
            "local_cessation_confirmed":last["observation"].get("local_cessation_confirmed",False),
            "held":phase!="not_sent"})
    return {"format":"muse-exposure-view/1","store_uuid":store.store_uuid,"entries":entries,
        "new_local_invocation_allowed_by_exposure":not any(e["held"] for e in entries),
        "production_dispatch_allowed":False,"account_spending_cap_enforced":False,
        "automatic_redispatch_allowed":False,"remote_settlement_supported":False,
        "scope":"this TaskAlong Store; other stores, manual clients and remote requests are outside this local limit"}
