"""Explicit, finite successors of observed local timeouts; never a retry loop.

Authority is the trusted OS caller's explicit command, not provider text or a
serialized plan. Every slot is exclusive and retained even if setup fails. Old
claims, unknown remote usage and descendant uncertainty are never refunded.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import uuid

from . import muse_experimental as muse
from . import supervised_pilot as pilot
from .artifact_io import read_regular
from .errors import TaskAlongError
from .store import identifier, key_check
from .validation import canonical_bytes, digest, loads, screen_sensitive

_DEADLINES = (360, 720)
_MESSAGES = {
    "provider_successor_history_changed": "Retained successor history is missing, unsafe or changed. Preserve all files; no successor was dispatched.",
    "provider_successor_plan_changed": "The reviewed successor plan or active configuration changed. Inspect it again; no new request is authorized by the old plan.",
    "provider_successor_reserved": "This predecessor already has a reserved successor. Observe the existing run; do not dispatch another.",
    "provider_successor_key_conflict": "This operation key is already bound to a different successor request.",
    "provider_successor_output_overlap": "Select a new output outside every previous run, bundle and successor control directory.",
    "provider_successor_result_exists": "Output or a conflicting terminal result exists. Inspect it instead of dispatching again.",
    "provider_successor_cancellation_unconfirmed": "The retained native cancellation observation is unavailable or conflicts with the requested run.",
}


def _fail(code="provider_successor_ineligible", message=None):
    muse._fail(code, message or _MESSAGES.get(code,"The previous run has no qualifying local timeout. Preserve its history and inspect existing results; no successor was dispatched."))


def _id(value):
    try:
        if type(value) is not str or str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, AttributeError):
        _fail("provider_successor_invalid", "Select an existing provider run ID.")
    return value


def _read_run(store, run_id):
    record = store.setting("provider-run:" + _id(run_id))
    if (type(record) is not dict or record.get("run_id") != run_id
            or record.get("format") not in ("local-provider-run/1", "local-provider-run/2")
            or record.get("provider") != "muse" or record.get("digest") != digest(record)
            or type(record.get("revision")) is not int or record["revision"] < 1):
        _fail()
    root = pilot._root(record["output"])
    raw = read_regular(root, f"events/{record['revision']:04d}.json", max_bytes=1048576, private=True, expected_mode=0o400)
    if raw != canonical_bytes(record):
        _fail("provider_successor_history_changed")
    return record, root


def _timeout(store, run_id):
    record, root = _read_run(store, run_id)
    process = record.get("process")
    if (record["state"] != "failed" or record.get("error") != "provider_local_failure"
            or type(record.get("controller_submissions")) is not int or record["controller_submissions"] != 1
            or record.get("remote_usage")!="unknown" or record.get("descendant_cessation")!="unknown"
            or record.get("native_internal_retries")!="unknown" or record.get("automatic_retry_allowed") is not False
            or record.get("patch_applied") is not False or record.get("acceptance_allowed") is not False
            or type(process) is not dict
            or process.get("timed_out") is not True or process.get("root_exit_observed") is not True
            or type(process.get("root_exit_code")) is not int
            or process.get("group_termination_confirmed") is not True
            or process.get("cancelled") is not False or process.get("output_limited") is not False
            or process.get("mode") != "darwin-foreground-experiment/1"
            or process.get("tracking_errors") != [] or process.get("boundary_failures") != []
            or process.get("failure_code") is not None or process.get("protocol_error") is not None):
        _fail()
    receipt = process.get("receipt")
    if type(receipt) is not dict or receipt != record.get("process_receipt"):
        _fail()
    config = store.setting("provider-config:" + record["configuration_digest"])
    muse._checked_configuration(config)
    if (config["digest"] != record["configuration_digest"]
            or receipt.get("executable_sha256") != config["binary"]["sha256"]):
        _fail("provider_successor_history_changed")
    bundle_root, manifest = pilot._bundle(record["bundle"])
    if manifest["digest"] != record["bundle_digest"]:
        _fail("provider_successor_history_changed")
    # Any staged/partially staged result is a stop, not permission to regenerate.
    if any(path.exists() or path.is_symlink() for path in
           (root/"proposal", root/"response.json", bundle_root/"response-claim.json")):
        _fail("provider_successor_result_exists", "A response or proposal already exists; inspect it instead of dispatching a successor.")
    artifacts = {}
    def read(name, maximum):
        raw = read_regular(root, name, max_bytes=maximum, private=True, expected_mode=0o400)
        artifacts[name] = hashlib.sha256(raw).hexdigest()
        return raw
    if loads(read("process.json",1048576)) != process:
        _fail("provider_successor_history_changed")
    stdout, stderr = read("stdout.bin",config["max_output_bytes"]), read("stderr.bin",config["max_output_bytes"])
    if (len(stdout)+len(stderr) > config["max_output_bytes"]
            or process.get("retained_output_bytes") != len(stdout)+len(stderr)
            or process.get("retained_stdout_bytes") != len(stdout)
            or process.get("retained_stderr_bytes") != len(stderr)):
        _fail("provider_successor_history_changed")
    prompt = pilot._prompt(manifest["request"],manifest["digest"])
    if read("prompt.txt",1048576) != prompt:
        _fail("provider_successor_history_changed")
    invocation = loads(read("invocation.json",1048576))
    session = invocation.get("session_id")
    _id(session)
    if (invocation.get("configuration_digest") != config["digest"]
            or invocation.get("bundle_digest") != manifest["digest"]
            or invocation.get("argv") != muse._argv(config,provider="meta",workspace=root/"workspace",prompt=root/"prompt.txt",session=session)):
        _fail("provider_successor_history_changed")
    session_rows, native_run = muse._session_records(stdout,session)
    stdout_terminals = [r for r in session_rows if r.get("payload_type", "").startswith("run.terminal.")]
    if (len(stdout_terminals)>1 or any(r["payload_type"]!="run.terminal.cancelled"
            or r["payload"].get("kind")!="run_terminal" or r["payload"].get("terminal")!="cancelled"
            for r in stdout_terminals)):
        _fail("provider_successor_result_exists", "A terminal response or conflicting outcome already exists; inspect it instead of dispatching again.")
    # A complete bound proposal may be present in deltas even when the final
    # native completion marker lost a race with the deadline. Never regenerate
    # it automatically. Unsupported output shapes require inspection as well.
    fragments=[]
    for row in session_rows:
        if row.get("payload_type")=="run.output.delta":
            if type(row["payload"].get("text")) is not str:_fail("provider_successor_result_exists")
            fragments.append(row["payload"]["text"])
    for text in ["".join(fragments),*[r["payload"].get("text","") for r in stdout_terminals]]:
        if not text:continue
        if type(text) is not str:_fail("provider_successor_result_exists")
        text=text.strip()
        if text.startswith("```json\n") and text.endswith("\n```"):text=text[8:-4].strip()
        try:
            loads(text)
        except TaskAlongError:
            pass
        else:
            _fail("provider_successor_result_exists")
    try:
        muse._decode(stdout,session,max_proposal_bytes=config.get("max_proposal_bytes",65536))
    except TaskAlongError as exc:
        if exc.code != "provider_response_unrecognized":
            _fail("provider_successor_result_exists")
    else:
        _fail("provider_successor_result_exists")
    raw, _ = muse._journal_source(config,session,started_unix_ms=receipt.get("started_unix_ms"))
    rows, configured, metadata = muse._journal_rows(raw)
    terminals = [r["payload"]["event"] for r in rows
                 if r.get("payload",{}).get("kind")=="run"
                 and r["payload"].get("run_id")==native_run
                 and r["payload"].get("event",{}).get("kind")=="terminal"]
    if (len(configured)!=1 or configured[0].get("toolset",{}).get("active_tools")!=[]
            or configured[0].get("reminder_roster",{}).get("agents")!=[]
            or metadata.get("provider_id")!="meta" or metadata.get("model_id")!=config["model"]
            or len(terminals)!=1 or terminals[0].get("terminal")!="cancelled"
            or terminals[0].get("reason")!="cancelled during model step"):
        _fail("provider_successor_cancellation_unconfirmed")
    # Native cancellation is an observation, NOT remote usage settlement.
    artifacts["native_journal"] = hashlib.sha256(raw).hexdigest()
    return record, root, config, manifest, artifacts


def _scope(config):
    value = {k:v for k,v in config.items() if k not in {"format","digest","attempt_seconds"}}
    value.setdefault("max_proposal_bytes",65536)
    return value


def _anchor(original):
    return pilot._root(str(Path(original["output"]).parent / (".taskalong-muse-successors-"+original["run_id"])))


def _anchor_view(store, original, enrollment):
    """A separate retained control directory fences copied/restored databases.

    Original run/bundle bytes remain untouched. This is a cooperative local
    one-shot fence, not protection against an OS operator deleting history.
    """
    anchor=_anchor(original)
    registered=store.setting("provider-successor-root:muse:"+original["run_id"])
    if not anchor.exists():
        if registered is not None:_fail("provider_successor_history_changed")
        return anchor
    if registered!=enrollment:
        _fail("provider_successor_history_changed", "A retained ladder exists outside this database. Preserve it; do not initialize a replacement.")
    raw=read_regular(anchor,"enrollment.json",max_bytes=65536,private=True,expected_mode=0o400)
    if raw!=canonical_bytes(enrollment):_fail("provider_successor_history_changed")
    parent=original["run_id"]
    for ordinal in (1,2):
        name=f"slot-{ordinal}.json"
        existing=store.setting("provider-successor:muse:"+parent) if parent else None
        if ordinal > enrollment["max_new_controller_submissions"]:
            if existing is not None or (anchor/name).exists() or (anchor/name).is_symlink():
                _fail("provider_successor_history_changed")
            continue
        if (anchor/name).exists() or (anchor/name).is_symlink():
            value=loads(read_regular(anchor,name,max_bytes=65536,private=True,expected_mode=0o400))
            if type(value) is not dict or value!=existing or value.get("digest")!=digest(value) or value.get("ordinal")!=ordinal:
                _fail("provider_successor_history_changed")
            parent=value["run_id"]
        else:
            if existing is not None:_fail("provider_successor_history_changed")
            parent=None
    return anchor


def _material_unchecked(store, predecessor, config):
    parent, root, previous_config, manifest, artifacts = _timeout(store,predecessor)
    link = parent.get("manual_successor")
    if link is None:
        if parent["format"]!="local-provider-run/1":
            _fail("provider_successor_limit")
        seconds=previous_config["attempt_seconds"]
        if seconds<=60:
            deadlines=_DEADLINES
        elif seconds==360:
            deadlines=(720,)
        else:
            _fail("provider_successor_limit", "A ladder requires an original timeout of at most 60 seconds or exactly 360 seconds.")
        original, ordinal = parent, 1
    else:
        if (parent["format"]!="local-provider-run/2" or type(link) is not dict
                or link.get("run_id")!=parent["run_id"] or type(link.get("ordinal")) is not int or link["ordinal"]!=1
                or link.get("predecessor_run_id")!=link.get("root_run_id")
                or link.get("bundle_digest")!=parent["bundle_digest"]
                or link.get("configuration_digest")!=parent["configuration_digest"]
                or previous_config["attempt_seconds"]!=360
                or store.setting("provider-successor:muse:"+link["predecessor_run_id"])!=link
                or store.setting("provider-successor-run:muse:"+parent["run_id"])!=link):
            _fail("provider_successor_limit", "This ladder has no further successor slot.")
        original, _, original_config, _, _ = _timeout(store,link["root_run_id"])
        if original.get("manual_successor") is not None or original["format"]!="local-provider-run/1" or original_config["attempt_seconds"]>60:
            _fail("provider_successor_history_changed")
        first_plan, _, _, _ = _material(store,link["root_run_id"],previous_config)
        if first_plan["digest"] != link.get("plan_digest"):
            _fail("provider_successor_history_changed")
        ordinal = 2
        deadlines=_DEADLINES
    original_claim = store.setting("provider-claim:muse:"+manifest["digest"])
    if (type(original_claim) is not dict or original_claim.get("run_id")!=original["run_id"]
            or original_claim.get("output")!=original["output"] or original_claim.get("bundle_digest")!=manifest["digest"]
            or original["bundle_digest"]!=manifest["digest"] or _scope(config)!=_scope(previous_config)):
        _fail("provider_successor_configuration_mismatch", "Keep the original task, binary, account, model, context and capture/proposal limits unchanged.")
    required = deadlines[ordinal-1]
    if config["format"]!="local-muse-provider/3" or config["attempt_seconds"]!=required:
        _fail("provider_successor_deadline", f"Configure the explicit {required}-second successor deadline; no request was sent.")
    enrollment = {"format":"manual-muse-ladder/1","root_run_id":original["run_id"],
        "root_record_digest":original["digest"],"bundle_digest":manifest["digest"],
        "state_scope":hashlib.sha256(str(store.root).encode()).hexdigest(),
        "deadlines_seconds":list(deadlines),"max_new_controller_submissions":len(deadlines)}
    existing = store.setting("provider-successor-root:muse:"+original["run_id"])
    if existing is not None and existing!=enrollment:
        _fail("provider_successor_history_changed")
    if ordinal==2 and existing is None:
        _fail("provider_successor_history_changed")
    _anchor_view(store,original,enrollment)
    history = [{"run_id":r["run_id"],"controller_submissions":r["controller_submissions"],
                "remote_usage":r.get("remote_usage","unknown"),"descendant_cessation":r.get("descendant_cessation","unknown")}
               for r in ([original] if ordinal==1 else [original,parent])]
    plan = {"format":"manual-muse-successor-plan/1","provider":"muse","predecessor_run_id":predecessor,
        "predecessor_digest":parent["digest"],"root_run_id":original["run_id"],"ordinal":ordinal,
        "bundle_digest":manifest["digest"],"configuration_digest":config["digest"],
        "attempt_seconds":required,"max_output_bytes":config["max_output_bytes"],
        "max_proposal_bytes":config["max_proposal_bytes"],"artifact_hashes":artifacts,"enrollment":enrollment,
        "remaining_controller_slots_including_this":len(deadlines)+1-ordinal,"remaining_local_meta_seconds_including_this":sum(deadlines[ordinal-1:]),
        "history":history,"automatic_retry_allowed":False,"remote_usage_settled":False,
        "complete_descendant_cessation_proven":False,"model_free":True}
    plan["digest"]=digest(plan)
    return plan, parent, root, manifest


def _material(store, predecessor, config):
    try:
        return _material_unchecked(store,predecessor,config)
    except (KeyError,TypeError,ValueError,AttributeError):
        _fail("provider_successor_history_changed")


def plan(store, *, predecessor):
    config=muse._configuration(store)
    value, _, _, _=_material(store,_id(predecessor),config)
    reserved=store.setting("provider-successor:muse:"+predecessor)
    if reserved is not None:
        _fail("provider_successor_reserved", "This predecessor already has a reserved successor. Read its existing status; never dispatch it again.")
    return value


def _check(store, reservation, config):
    if (type(reservation) is not dict or not {"predecessor_run_id","run_id","key_digest","plan_digest"}.issubset(reservation)
            or any(type(reservation[k]) is not str for k in ("predecessor_run_id","run_id","key_digest","plan_digest"))
            or reservation.get("digest")!=digest(reservation)
            or store.setting("provider-successor:muse:"+reservation["predecessor_run_id"])!=reservation
            or store.setting("provider-successor-run:muse:"+reservation["run_id"])!=reservation
            or store.setting("provider-successor-key:muse:"+reservation["key_digest"])!=reservation):
        _fail("provider_successor_history_changed")
    if store.setting("provider:muse") != config:
        _fail("provider_successor_plan_changed")
    fresh, _, _, _=_material(store,reservation["predecessor_run_id"],config)
    if fresh["digest"]!=reservation["plan_digest"]:
        _fail("provider_successor_plan_changed")
    return fresh


def claim_submission(store, bundle_root, manifest, record, reservation, config):
    _check(store,reservation,config)
    with store.transaction() as db:
        current=store.setting("provider-run:"+reservation["predecessor_run_id"])
        if current is None or current.get("digest")!=reservation["predecessor_digest"] or store.setting("provider:muse")!=config:
            _fail("provider_successor_plan_changed")
        pilot._write(bundle_root,"provider-submission.json",canonical_bytes({"provider":"muse","run_id":record["run_id"],
            "bundle_digest":manifest["digest"],"predecessor_run_id":reservation["predecessor_run_id"],"reservation_digest":reservation["digest"]}))


def inspect_reserved(store, run_id):
    value=store.setting("provider-successor-run:muse:"+run_id)
    if value is None:return None
    if type(value) is not dict or value.get("run_id")!=run_id or value.get("digest")!=digest(value):
        _fail("provider_successor_history_changed")
    return {"format":"local-provider-reservation/1","run_id":run_id,"revision":0,"state":"reserved_incomplete",
        "manual_successor":value,"output":value["output"],"controller_submissions":None,"remote_usage":"unknown",
        "descendant_cessation":"unknown","automatic_retry_allowed":False,"patch_applied":False,"acceptance_allowed":False}


def execute(store, *, predecessor, key, plan_digest, output):
    _id(predecessor);key_check(key);screen_sensitive(key)
    if type(plan_digest) is not str or len(plan_digest)!=64 or any(c not in "0123456789abcdef" for c in plan_digest):
        _fail("provider_successor_invalid")
    target=pilot._root(output)
    key_digest=hashlib.sha256(key.encode()).hexdigest()
    existing=store.setting("provider-successor-key:muse:"+key_digest)
    identity={"predecessor_run_id":predecessor,"plan_digest":plan_digest,"output":str(target)}
    if existing is not None:
        if type(existing) is not dict or existing.get("digest")!=digest(existing) or any(existing.get(k)!=v for k,v in identity.items()):_fail("provider_successor_key_conflict")
        return muse.inspect(store,existing["run_id"])
    config=muse._configuration(store)
    proof,parent,parent_root,manifest=_material(store,predecessor,config)
    if proof["digest"]!=plan_digest:_fail("provider_successor_plan_changed")
    original,original_root=_read_run(store,proof["root_run_id"])
    for protected in (parent_root,pilot._root(parent["bundle"]),original_root,pilot._root(original["bundle"]),_anchor(original)):
        if target.is_relative_to(protected) or protected.is_relative_to(target):_fail("provider_successor_output_overlap")
    pilot._destination(output)
    budget=muse._budget(config,pilot._prompt(manifest["request"],manifest["digest"]))
    if not budget["input_echoes_fit"]:_fail("provider_capture_budget_insufficient")
    reservation={"format":"manual-muse-successor/1",**identity,"run_id":identifier(),"key_digest":key_digest,
        "root_run_id":proof["root_run_id"],"ordinal":proof["ordinal"],"predecessor_digest":parent["digest"],
        "bundle_digest":manifest["digest"],"configuration_digest":config["digest"],"attempt_seconds":proof["attempt_seconds"],
        "history":proof["history"]}
    reservation["digest"]=digest(reservation)
    # Reserve before ANY native preflight. Denial, crash or other failure consumes
    # the logical slot. A repeated command only observes; it never resumes code.
    with store.transaction() as db:
        again=store.setting("provider-successor-key:muse:"+key_digest)
        if again is not None:
            if type(again) is not dict or again.get("digest")!=digest(again) or any(again.get(k)!=v for k,v in identity.items()):_fail("provider_successor_key_conflict")
            return muse.inspect(store,again["run_id"])
        if store.setting("provider-successor:muse:"+predecessor) is not None:_fail("provider_successor_reserved")
        if store.setting("provider-run:"+predecessor)!=parent or store.setting("provider:muse")!=config:_fail("provider_successor_plan_changed")
        enrollment_key="provider-successor-root:muse:"+proof["root_run_id"]
        prior=store.setting(enrollment_key)
        if prior is not None and prior!=proof["enrollment"]:_fail("provider_successor_history_changed")
        anchor=_anchor_view(store,original,proof["enrollment"])
        if prior is None:
            # Exclusive directory creation arbitrates even a copy made before
            # enrollment. A partial/crashed creation is retained, never reset.
            try:anchor.mkdir(mode=0o700)
            except FileExistsError:_fail("provider_successor_history_changed")
            pilot._write(anchor,"enrollment.json",canonical_bytes(proof["enrollment"]))
        pilot._write(anchor,f"slot-{proof['ordinal']}.json",canonical_bytes(reservation))
        db.execute("INSERT OR IGNORE INTO settings VALUES (?,?)",(enrollment_key,canonical_bytes(proof["enrollment"]).decode()))
        for name in ("provider-successor:muse:"+predecessor,"provider-successor-run:muse:"+reservation["run_id"],"provider-successor-key:muse:"+key_digest):
            db.execute("INSERT INTO settings VALUES (?,?)",(name,canonical_bytes(reservation).decode()))
    return muse.run(store,request=manifest["request"],output=output,_successor=reservation)
