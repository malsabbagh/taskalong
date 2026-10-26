"""Closed synthetic artifact handoff; Workflow retains all lifecycle ownership.

This family never transfers native sessions, credentials or worker authority.
Content hashes identify private bytes; authoritative Store operations establish
their associations. Existing single-step and ordered 2.7 meanings are unchanged.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import ClassVar

from .contracts import JsonDocument
from .errors import TaskAlongError
from .paths import safe_relative
from .store import encode
from .validation import canonical_bytes, digest, loads, seal_versioned, validate, validate_versioned

VERSION = "2.10"
MAX_BYTES = 1048576
MAX_TARGET_BYTES = 8388608


def refuse(code="artifact_handoff_invalid", *, uncertain=False):
    raise TaskAlongError(code, "The immutable synthetic handoff is unavailable, unauthorized or inconsistent.",
                         exit_code=5 if uncertain else 3, effect_outcome="uncertain" if uncertain else "not_sent")


@dataclass(frozen=True, slots=True)
class ArtifactTaskSpec(JsonDocument):
    schema_name: ClassVar[str] = "task-spec"

    def __post_init__(self):
        object.__setattr__(self, "_canonical", canonical_bytes(validate_versioned(
            self.schema_name, loads(self._canonical), expected_version=VERSION)))


def semantics(value, name):
    from .steps import contains, semantics as ordered_semantics
    if name == "task-spec":
        ordinary = copy.deepcopy(value)
        for step in ordinary["steps"]:
            step["inputs"] = [item for item in step["inputs"] if "path" in item]
        ordered_semantics(ordinary, name)
        routes = value["execution"]["routes"]
        route_ids = {r["route_id"] for r in routes}
        if len(route_ids) != len(routes) or value["execution"]["check_route_id"] not in route_ids:
            refuse("artifact_route_invalid")
        if (len({r["binding_digest"] for r in routes}) != len(routes)
                or len({r["configuration_digest"] for r in routes}) != len(routes)):
            refuse("artifact_route_invalid")
        destinations = value["permissions"]["disclosure_destination_ids"]
        if len(set(destinations)) != len(destinations) or any(r["disclosure_destination_id"] not in destinations for r in routes):
            refuse("artifact_disclosure_forbidden")
        prior = {}
        for step in value["steps"]:
            if step["route_id"] not in route_ids:
                refuse("artifact_route_invalid")
            for path in step["import_scope"]["files"]:
                safe_relative(path, allow_directory=True)
                if not contains(value["scope"], path):
                    refuse("artifact_import_scope")
            if not set(step["import_scope"]["operations"]) <= set(value["scope"]["operations"]):
                refuse("artifact_import_scope")
            outputs = step["outputs"]
            if len({o["output_id"] for o in outputs}) != len(outputs) or len({o["path"] for o in outputs}) != len(outputs):
                refuse("artifact_output_duplicate")
            for output in outputs:
                safe_relative(output["path"])
                if output["path"].startswith(".taskalong-scratch/") or not contains(step["scope"], output["path"]):
                    refuse("artifact_output_scope")
                if (not set(output["allowed_target_binding_digests"]) <= {r["binding_digest"] for r in routes}
                        or not set(output["allowed_disclosure_destination_ids"]) <= set(destinations)):
                    refuse("artifact_disclosure_forbidden")
            seen = set()
            for selector in step["inputs"]:
                identity = ("file", selector["path"]) if "path" in selector else (selector["from_step_id"], selector["output_id"])
                if identity in seen:
                    refuse("artifact_selector_duplicate")
                seen.add(identity)
                if "path" in selector:
                    continue
                producer = prior.get(selector["from_step_id"])
                output = next((o for o in producer["outputs"] if o["output_id"] == selector["output_id"]), None) if producer else None
                if output is None or selector["expected_kind"] != output["artifact_kind"] or selector["max_bytes"] > output["max_bytes"]:
                    refuse("artifact_selector_invalid")
                route = next(r for r in routes if r["route_id"] == step["route_id"])
                if (route["binding_digest"] not in output["allowed_target_binding_digests"]
                        or route["disclosure_destination_id"] not in output["allowed_disclosure_destination_ids"]):
                    refuse("artifact_disclosure_forbidden")
            prior[step["step_id"]] = step
    elif name == "file-set-patch":
        paths = []
        for item in value["files"]:
            safe_relative(item["path"])
            if item["path"].startswith(".taskalong-scratch/"):
                refuse("artifact_import_scope")
            if ((item["before_sha256"] is None) != (item["before_bytes"] is None)
                    or (item["operation"] == "add") != (item["before_sha256"] is None)
                    or item["operation"] == "add" and item["mode"] != "100644"):
                refuse("artifact_patch_invalid")
            paths.append(item["path"])
        disjoint(paths)
    elif name == "result-view":
        ordered_semantics(value, name)


def disjoint(paths):
    for index, path in enumerate(paths):
        if any(path == other or path.startswith(other + "/") or other.startswith(path + "/") for other in paths[:index]):
            refuse("artifact_patch_overlap")


def route(spec, step_index=0, *, check=False):
    identity = spec["execution"]["check_route_id"] if check else spec["steps"][step_index]["route_id"]
    return next(r for r in spec["execution"]["routes"] if r["route_id"] == identity)


def admit(store, spec, step_index=0, *, authority_id=None, check=False):
    """Independently admit an existing exact route; no task-selected fallback."""
    from .admission import _registration, resolve
    r = route(spec, step_index, check=check)
    registration = _registration(store, r["binding_digest"])
    version = "2.3" if registration.get("schema_version") == "2.3" else "2.2" if "runtime_profile_digest" in registration else None
    if version is None:
        refuse("artifact_route_unsupported")
    expected_projection = "claude-print-fixture/1" if version == "2.3" else "codex-v1-fixture/1"
    if registration["projection"] != expected_projection:
        refuse("artifact_route_unsupported")
    execution = {"binding_digest":r["binding_digest"]}
    if version == "2.3":
        execution["driver_config_digest"] = r["configuration_digest"]
    elif registration["runtime_profile_digest"] != r["configuration_digest"]:
        refuse("artifact_route_changed")
    # The route admits a single bounded fresh invocation. The outer Workflow
    # separately conserves the complete task's worker and verifier reservations.
    budget = spec["budget"] | {"max_attempts":1, "total_active_seconds":spec["budget"]["attempt_seconds"]}
    budget.pop("attempt_output_bytes", None)
    view = spec | {"schema_version":version, "execution":execution, "budget":budget,
                   "permissions":spec["permissions"] | {"inference_destination_id":r["disclosure_destination_id"]}}
    snapshot, configuration, checker = resolve(store, view, mode="start", authority_id=authority_id)
    if configuration["digest"] != r["configuration_digest"] or r["disclosure_destination_id"] not in spec["permissions"]["disclosure_destination_ids"]:
        refuse("artifact_route_changed")
    return snapshot, configuration, checker


def preflight(workflow, spec):
    if workflow.store.format_version < 11:
        refuse("store_upgrade_required")
    ordinary = copy.deepcopy(spec)
    for step in ordinary["steps"]:
        step["inputs"] = [i for i in step["inputs"] if "path" in i]
    # Repository-file inputs retain M10's immutable-base meaning, but are read
    # through the new bounded no-follow primitive in this new family.
    repository = workflow.store.repository(spec["repository"]["registration_id"])
    from .workspace import git
    from .artifact_io import read_regular
    for step in ordinary["steps"]:
        for item in step["inputs"]:
            read_regular(repository["path"], item["path"], max_bytes=MAX_BYTES, expected_sha256=item["sha256"])
            if hashlib.sha256(git(repository["path"], "show", spec["repository"]["base_commit"]+":"+item["path"], binary=True)).hexdigest() != item["sha256"]:
                refuse("step_input_changed")
    checkers = [admit(workflow.store, spec, i)[2]["digest"] for i in range(len(spec["steps"]))]
    if any(c != admit(workflow.store, spec, check=True)[2]["digest"] for c in checkers):
        refuse("artifact_check_binding_changed")
    return spec


def inputs(spec, root, step_index=None):
    from .artifact_io import read_regular
    for step in spec["steps"] if step_index is None else [spec["steps"][step_index]]:
        for item in step["inputs"]:
            if "path" in item:
                read_regular(root, item["path"], max_bytes=MAX_BYTES, expected_sha256=item["sha256"])


def subject(run, attempt):
    return {"run_id":run["run_id"], "spec_digest":run["spec_digest"], "step_id":attempt["step_id"],
            "step_index":attempt["step_index"], "attempt_id":attempt["attempt_id"], "lease_generation":attempt["lease_generation"]}


def blob_document(store, sha, name):
    return validate_versioned(name, loads(store.get_blob(sha)), expected_version=VERSION)


def artifact_bytes(store, reference):
    row = store.db.execute("SELECT bytes,media_type,redaction_version FROM blobs WHERE sha256=?", (reference["sha256"],)).fetchone()
    if row is None or tuple(row) != (reference["bytes"],reference["media_type"],reference["redaction_version"]):
        refuse("artifact_metadata_changed")
    raw = store.get_blob(reference["sha256"])
    if len(raw) != reference["bytes"]:
        refuse("artifact_size_limit")
    return raw


def patch_files(store, output, outputs):
    patch = blob_document(store, output["artifact"]["sha256"], "file-set-patch")
    files, payloads = [], {}
    volume = output["artifact"]["bytes"]
    for item in patch["files"]:
        payload = next((o for o in outputs if o["output_id"] == item["payload_output_id"]), None)
        if payload is None or payload["artifact_kind"] != "utf8_text":
            refuse("artifact_patch_payload")
        ref = payload["artifact"]
        artifact_bytes(store, ref)
        if item["after_sha256"] != ref["sha256"] or item["after_bytes"] != ref["bytes"]:
            refuse("artifact_patch_payload")
        volume += ref["bytes"]
        files.append({k:v for k,v in item.items() if k != "payload_output_id"} | {"payload_sha256":ref["sha256"]})
        payloads[payload["output_id"]] = {"output_id":payload["output_id"], "artifact":ref}
    return files, [payloads[k] for k in sorted(payloads)], volume


def capture_outputs(store, run, attempt, result, receipt_sha):
    """Read producer files only while its settled source fence is current."""
    from .artifact_io import read_regular
    spec = store.spec(run)
    store.require_fence(run, attempt["lease_generation"])
    store.authority(run,{"execute","verify","commit_candidate"},spec["digest"],attempt["admission"]["authority_id"])
    if run["active_attempt_id"] != attempt["attempt_id"] or result["process"].get("termination_confirmed") is not True:
        refuse("artifact_producer_unsettled")
    if result["process"].get("receipt") != attempt.get("process_receipt"):
        refuse("artifact_proof_forged")
    admission, configuration, _ = admit(store, spec, attempt["step_index"])
    if (admission["projection"] != attempt["dispatch_admission"]["projection"]
            or admission["trust_digest"] != attempt["dispatch_admission"]["trust_digest"]):
        refuse("artifact_route_changed")
    from .workflow import Workflow
    manager = Workflow(store)._manager(run)
    if manager.snapshot(attempt["workspace"],spec["scope"],expected_head=spec["repository"]["base_commit"])["content_digest"] != result["checkpoint"]["content_digest"]:
        refuse("artifact_producer_changed")
    outputs = []
    for declaration in spec["steps"][attempt["step_index"]]["outputs"]:
        raw = read_regular(attempt["workspace"]["path"], declaration["path"], max_bytes=declaration["max_bytes"])
        if declaration["artifact_kind"] == "utf8_text":
            try:
                raw.decode("utf-8", "strict")
            except UnicodeError:
                refuse("artifact_kind_invalid")
            if b"\0" in raw:
                refuse("artifact_kind_invalid")
            from .validation import screen_sensitive
            screen_sensitive(raw.decode("utf-8"))
        else:
            validate_versioned("file-set-patch", loads(raw), expected_version=VERSION)
        ref = store.put_blob(raw, media_type="text/plain" if declaration["artifact_kind"] == "utf8_text" else "application/json")
        artifact_bytes(store, ref)
        outputs.append({"output_id":declaration["output_id"], "declaration_digest":digest(declaration), "path":declaration["path"],
                        "artifact_kind":declaration["artifact_kind"], "classification":declaration["classification"], "artifact":ref, "payloads":[]})
    for output in outputs:
        if output["artifact_kind"] == "file_set_patch":
            _, output["payloads"], volume = patch_files(store, output, outputs)
            declaration = next(o for o in spec["steps"][attempt["step_index"]]["outputs"] if o["output_id"] == output["output_id"])
            if volume > declaration["max_bytes"]:
                refuse("artifact_size_limit")
    if manager.snapshot(attempt["workspace"],spec["scope"],expected_head=spec["repository"]["base_commit"])["content_digest"] != result["checkpoint"]["content_digest"]:
        refuse("artifact_producer_changed")
    document = seal_versioned("output-manifest", subject(run, attempt) | {
        "producer_receipt_blob_sha256":receipt_sha,"packet_digest":attempt["packet"]["digest"],
        "admission_digest":attempt["dispatch_admission"]["digest"],"binding_digest":admission["binding"]["digest"],
        "configuration_digest":configuration["digest"],"base_commit":spec["repository"]["base_commit"],
        "checkpoint_digest":digest(result["checkpoint"]),"content_digest":result["checkpoint"]["content_digest"],"outputs":outputs}, version=VERSION)
    return store.put_blob(canonical_bytes(document))["sha256"]


def producer(store, run, index):
    spec = store.spec(run)
    state = run["steps"][index]
    receipt_sha = state["receipt_digest"]
    if state["status"] != "completed" or receipt_sha is None or state["output_manifest_blob_sha256"] is None:
        refuse("artifact_output_missing")
    receipt = blob_document(store, receipt_sha, "step-receipt")
    attempt = store.detail("attempts", receipt["attempt_id"])
    manifest = blob_document(store, state["output_manifest_blob_sha256"], "output-manifest")
    expected = subject(run, attempt) | {"producer_receipt_blob_sha256":receipt_sha,
        "packet_digest":attempt["packet"]["digest"],"admission_digest":attempt["dispatch_admission"]["digest"],
        "binding_digest":route(spec,index)["binding_digest"],"configuration_digest":route(spec,index)["configuration_digest"],
        "base_commit":spec["repository"]["base_commit"],"checkpoint_digest":receipt["checkpoint_digest"],
        "content_digest":receipt["final_snapshot_digest"]}
    if (any(manifest[k] != v for k,v in expected.items()) or attempt.get("output_manifest_blob_sha256") != state["output_manifest_blob_sha256"]
            or attempt["status"] != "completed" or attempt.get("termination_confirmed") is not True):
        refuse("artifact_producer_changed")
    finish = store.operation("executor.finish", run["run_id"], attempt["attempt_id"], {"state":"completed", "artifact":attempt["result_artifact"]})
    if finish is None or finish["steps"][index]["output_manifest_blob_sha256"] != state["output_manifest_blob_sha256"]:
        refuse("artifact_proof_forged")
    declarations = spec["steps"][index]["outputs"]
    if len(declarations) != len(manifest["outputs"]):
        refuse("artifact_output_missing")
    for declaration, output in zip(declarations, manifest["outputs"]):
        if (output["declaration_digest"] != digest(declaration) or output["output_id"] != declaration["output_id"]
                or output["path"] != declaration["path"] or output["artifact_kind"] != declaration["artifact_kind"]
                or output["classification"] != declaration["classification"]):
            refuse("artifact_output_changed")
        raw = artifact_bytes(store, output["artifact"])
        if len(raw) != output["artifact"]["bytes"] or len(raw) > declaration["max_bytes"]:
            refuse("artifact_size_limit")
        if output["artifact_kind"] == "file_set_patch":
            _, refs, volume = patch_files(store, output, manifest["outputs"])
            if refs != output["payloads"] or volume > declaration["max_bytes"]:
                refuse("artifact_patch_payload")
    return receipt, manifest


def expected_manifest(workspace, before, files, store):
    from .workspace import _tree
    baseline = _tree(workspace["path"], workspace["base_commit"])
    manifest = {f["path"]:f for f in before}
    for item in files:
        payload = store.get_blob(item["payload_sha256"])
        # _git supplies bytes over stdin; it does not write objects or filters.
        from .workspace import _git
        blob = _git(workspace["path"], "hash-object", "--stdin", data=payload).stdout.decode().strip()
        if baseline.get(item["path"]) == (item["mode"], blob):
            manifest.pop(item["path"], None)
        else:
            manifest[item["path"]] = {"path":item["path"],"operation":"modify" if item["path"] in baseline else "add",
                "mode":item["mode"],"sha256":item["after_sha256"],"bytes":item["after_bytes"]}
    return [manifest[k] for k in sorted(manifest)]


def prepare_import(store, run, attempt, manager, workspace):
    """Own/journal imports after target reservation, before executor intent."""
    from .artifact_io import read_regular, stage_regular, apply_regular
    from .steps import contains
    from .workflow import _effect, _observe_effect
    spec = store.spec(run)
    index = attempt["step_index"]
    state = run["steps"][index]
    if len(state["attempt_ids"]) > 1:
        first = store.detail("attempts", state["attempt_ids"][0])
        if not first.get("import_committed"):
            refuse("artifact_import_unsettled")
        # Fresh target session, same exact import and first-start transition.
        return inherit_import(store, run, attempt, first)
    admission = attempt["dispatch_admission"]
    _, configuration, _ = admit(store,spec,index,authority_id=attempt["admission"]["authority_id"])
    if attempt.get("import_journal_blob_sha256"):
        journal_sha = attempt["import_journal_blob_sha256"]
        journal = blob_document(store,journal_sha,"import-journal")
        if any(journal[k] != v for k,v in subject(run,attempt).items()):
            refuse("artifact_import_changed")
        fields = {k:v for k,v in journal.items() if k not in {"kind","schema_version","digest","files","before_manifest"}}
        entries, files = journal["entries"], journal["files"]
        authority = store.authority(run,{"execute","verify","commit_candidate"},spec["digest"],journal["authority_id"])
    else:
        snapshot = manager.snapshot(workspace,spec["scope"],expected_head=spec["repository"]["base_commit"])
        entries, files, volume = [], [], 0
        selectors = [s for s in spec["steps"][index]["inputs"] if "from_step_id" in s]
        target = route(spec,index)
        for selector in selectors:
            pi = next(i for i,s in enumerate(spec["steps"]) if s["step_id"] == selector["from_step_id"])
            receipt, manifest = producer(store, run, pi)
            declaration = next(o for o in spec["steps"][pi]["outputs"] if o["output_id"] == selector["output_id"])
            if target["binding_digest"] not in declaration["allowed_target_binding_digests"] or target["disclosure_destination_id"] not in declaration["allowed_disclosure_destination_ids"]:
                refuse("artifact_disclosure_forbidden")
            output = next(o for o in manifest["outputs"] if o["output_id"] == selector["output_id"])
            size = output["artifact"]["bytes"]
            if output["artifact_kind"] == "file_set_patch":
                patch, _, size = patch_files(store,output,manifest["outputs"])
                files.extend(patch)
                for payload in output["payloads"]:
                    export = next(o for o in spec["steps"][pi]["outputs"] if o["output_id"] == payload["output_id"])
                    if target["binding_digest"] not in export["allowed_target_binding_digests"] or target["disclosure_destination_id"] not in export["allowed_disclosure_destination_ids"]:
                        refuse("artifact_disclosure_forbidden")
            if size > selector["max_bytes"]:
                refuse("artifact_size_limit")
            volume += size
            entries.append({"selector":selector,"producer_receipt_blob_sha256":run["steps"][pi]["receipt_digest"],
                "producer_output_manifest_blob_sha256":run["steps"][pi]["output_manifest_blob_sha256"],"producer_step_index":pi,
                "producer_attempt_id":receipt["attempt_id"],"producer_checkpoint_digest":receipt["checkpoint_digest"],
                "producer_content_digest":receipt["final_snapshot_digest"],"source_binding_digest":manifest["binding_digest"],"output":output,
                "staged_relative_path":"handoff/"+attempt["attempt_id"]+"/inputs/"+str(len(entries)).zfill(4)})
        if volume > MAX_TARGET_BYTES or len(files) > 256:
            refuse("artifact_size_limit")
        disjoint([f["path"] for f in files])
        for f in files:
            if not contains(spec["steps"][index]["import_scope"],f["path"]) or f["operation"] not in spec["steps"][index]["import_scope"]["operations"]:
                refuse("artifact_import_scope")
            if f["before_sha256"] is not None:
                read_regular(workspace["path"], f["path"], max_bytes=MAX_BYTES, expected_sha256=f["before_sha256"], expected_bytes=f["before_bytes"])
        after = expected_manifest(workspace,snapshot["manifest"],files,store)
        authority = store.authority(run,{"execute","verify","commit_candidate"},spec["digest"])
        fields = subject(run,attempt) | {"workspace_id":workspace["workspace_id"],"binding_digest":target["binding_digest"],
            "configuration_digest":configuration["digest"],"admission_digest":admission["digest"],"disclosure_destination_id":target["disclosure_destination_id"],
            "authority_id":authority["authority_id"],"selectors_digest":digest(selectors),
            "predecessor_receipt_blob_sha256":run["steps"][index-1]["receipt_digest"] if index else None,
            "before_content_digest":snapshot["content_digest"],"after_content_digest":digest(after),"entries":entries}
        journal = seal_versioned("import-journal",fields | {"files":files,"before_manifest":snapshot["manifest"]},version=VERSION)
        journal_sha = store.put_blob(canonical_bytes(journal))["sha256"]
    prior = store.operation("artifact.import.prepare",run["run_id"],attempt["attempt_id"],{"journal_blob_sha256":journal_sha})
    if attempt.get("import_journal_blob_sha256") and prior is None:
        refuse("artifact_proof_forged")
    if prior is None:
        def prepared(current,db):
            store.require_fence(current,attempt["lease_generation"],db=db)
            if current["state"] == "cancel_pending":
                refuse("cancel_pending")
            item=store.detail("attempts",attempt["attempt_id"])
            item["import_journal_blob_sha256"]=journal_sha
            item["import_admission"]=admission
            db.execute("UPDATE attempts SET document=? WHERE attempt_id=?",(encode(item),attempt["attempt_id"]))
            _effect(db,current,"artifact.import",attempt["attempt_id"],{"journal_blob_sha256":journal_sha})
        store.mutate(run["run_id"],"artifact.import.prepare",attempt["attempt_id"],None,{"journal_blob_sha256":journal_sha},prepared,fence=attempt["lease_generation"])
    if attempt.get("import_committed"):
        validate_import(store,run,attempt,staged=True)
        current=store.run(run["run_id"])
        for effect_id in current["pending_effect_ids"]:
            effect=store.detail("effects",effect_id)
            if effect["kind"]=="artifact.import" and effect["operation_key"]==attempt["attempt_id"]:
                _observe_effect(store,run["run_id"],effect_id,{"journal_blob_sha256":journal_sha,
                    "resolved_inputs_blob_sha256":attempt["resolved_inputs_blob_sha256"]})
        return store.detail("attempts",attempt["attempt_id"])
    # Exact journal/recovery; only known before/after states may be reconciled.
    for f in files:
        current=store.run(run["run_id"])
        if current["state"] == "cancel_pending":
            refuse("cancel_pending",uncertain=True)
        apply_regular(workspace["path"],f["path"],store.get_blob(f["payload_sha256"]),before_sha256=f["before_sha256"],
                      before_bytes=f["before_bytes"],mode=f["mode"],allow_after=True)
    scratch=Path(workspace["path"])/workspace["scratch_relative"]
    for entry in entries:
        ref=entry["output"]["artifact"]
        try:
            read_regular(scratch,entry["staged_relative_path"],max_bytes=MAX_BYTES,expected_sha256=ref["sha256"],expected_bytes=ref["bytes"],private=True,expected_mode=0o400)
        except TaskAlongError:
            # O_EXCL creation preserves an existing conflicting path.
            stage_regular(scratch,entry["staged_relative_path"],artifact_bytes(store,ref),expected_sha256=ref["sha256"])
        for pi,payload in enumerate(entry["output"]["payloads"]):
            path=entry["staged_relative_path"]+"-payload-"+str(pi)
            try:
                read_regular(scratch,path,max_bytes=MAX_BYTES,expected_sha256=payload["artifact"]["sha256"],private=True,expected_mode=0o400)
            except TaskAlongError:
                stage_regular(scratch,path,artifact_bytes(store,payload["artifact"]),expected_sha256=payload["artifact"]["sha256"])
    if manager.snapshot(workspace,spec["scope"],expected_head=spec["repository"]["base_commit"])["content_digest"] != journal["after_content_digest"]:
        refuse("artifact_import_changed",uncertain=True)
    resolution=seal_versioned("resolved-inputs",fields | {"import_journal_blob_sha256":journal_sha},version=VERSION)
    resolution_sha=store.put_blob(canonical_bytes(resolution))["sha256"]
    def committed(current,db):
        if current["state"] == "cancel_pending":
            refuse("cancel_pending",uncertain=True)
        store.authority(current,{"execute","verify","commit_candidate"},spec["digest"],authority["authority_id"])
        fresh,_,_=admit(store,spec,index,authority_id=authority["authority_id"])
        if fresh["projection"] != admission["projection"] or fresh["trust_digest"] != admission["trust_digest"]:
            refuse("artifact_route_changed",uncertain=True)
        item=store.detail("attempts",attempt["attempt_id"])
        item.update(import_committed=True,resolved_inputs_blob_sha256=resolution_sha,import_journal_blob_sha256=journal_sha,
                    import_origin_attempt_id=attempt["attempt_id"])
        db.execute("UPDATE attempts SET document=? WHERE attempt_id=?",(encode(item),attempt["attempt_id"]))
    store.mutate(run["run_id"],"artifact.import.commit",attempt["attempt_id"],None,{"journal_blob_sha256":journal_sha,"resolved_inputs_blob_sha256":resolution_sha},committed,fence=attempt["lease_generation"])
    current=store.run(run["run_id"])
    effect=next(store.detail("effects",eid) for eid in current["pending_effect_ids"] if store.detail("effects",eid)["kind"]=="artifact.import")
    _observe_effect(store,run["run_id"],effect["effect_id"],{"journal_blob_sha256":journal_sha,"resolved_inputs_blob_sha256":resolution_sha})
    return store.detail("attempts",attempt["attempt_id"])


def inherit_import(store,run,attempt,first):
    def inherited(current,db):
        item=store.detail("attempts",attempt["attempt_id"])
        item.update({k:first[k] for k in ("import_committed","resolved_inputs_blob_sha256","import_journal_blob_sha256","import_origin_attempt_id")})
        db.execute("UPDATE attempts SET document=? WHERE attempt_id=?",(encode(item),attempt["attempt_id"]))
    store.mutate(run["run_id"],"artifact.import.inherit",attempt["attempt_id"],None,{"origin_attempt_id":first["attempt_id"]},inherited,fence=attempt["lease_generation"])
    return store.detail("attempts",attempt["attempt_id"])


def settle_cancelled_import(store,run,attempt):
    """Observe only known journaled states; cancellation performs no more writes."""
    from .artifact_io import read_regular
    from .paths import contained_path
    from .workflow import _observe_effect
    if not attempt.get("import_journal_blob_sha256"):
        return
    journal_sha=attempt["import_journal_blob_sha256"]
    journal=blob_document(store,journal_sha,"import-journal")
    if any(journal[k]!=v for k,v in subject(run,attempt).items()):
        refuse("artifact_import_changed",uncertain=True)
    for item in journal["files"]:
        target=contained_path(attempt["workspace"]["path"],item["path"])
        if item["before_sha256"] is None and not target.exists() and not target.is_symlink():
            continue
        raw=read_regular(attempt["workspace"]["path"],item["path"],max_bytes=MAX_BYTES)
        observed=(hashlib.sha256(raw).hexdigest(),len(raw))
        if observed not in {(item["before_sha256"],item["before_bytes"]),(item["after_sha256"],item["after_bytes"])}:
            refuse("artifact_import_changed",uncertain=True)
    for effect_id in run["pending_effect_ids"]:
        effect=store.detail("effects",effect_id)
        if effect["kind"]=="artifact.import" and effect["operation_key"]==attempt["attempt_id"]:
            _observe_effect(store,run["run_id"],effect_id,{"journal_blob_sha256":journal_sha,"cancelled":True})


def validate_import(store,run,attempt,*,staged=False):
    spec=store.spec(run); origin=store.detail("attempts",attempt["import_origin_attempt_id"])
    if (origin["step_index"]!=attempt["step_index"] or origin["step_id"]!=attempt["step_id"]
            or origin["attempt_id"]!=run["steps"][attempt["step_index"]]["attempt_ids"][0]):
        refuse("artifact_import_changed")
    if not attempt.get("import_committed") or any(attempt[k]!=origin[k] for k in ("resolved_inputs_blob_sha256","import_journal_blob_sha256")):
        refuse("artifact_import_unsettled")
    resolution=blob_document(store,attempt["resolved_inputs_blob_sha256"],"resolved-inputs")
    journal=blob_document(store,attempt["import_journal_blob_sha256"],"import-journal")
    if (resolution["import_journal_blob_sha256"]!=attempt["import_journal_blob_sha256"]
            or any(resolution[k]!=v for k,v in subject(run,origin).items())
            or any(journal[k]!=v for k,v in resolution.items() if k not in {"kind","digest","import_journal_blob_sha256"})):
        refuse("artifact_import_changed")
    committed=store.operation("artifact.import.commit",run["run_id"],origin["attempt_id"],
        {"journal_blob_sha256":attempt["import_journal_blob_sha256"],"resolved_inputs_blob_sha256":attempt["resolved_inputs_blob_sha256"]})
    if committed is None:
        refuse("artifact_proof_forged")
    selectors=[s for s in spec["steps"][attempt["step_index"]]["inputs"] if "from_step_id" in s]
    if resolution["selectors_digest"]!=digest(selectors) or len(selectors)!=len(resolution["entries"]):
        refuse("artifact_selector_changed")
    expected_route=route(spec,attempt["step_index"])
    if (resolution["binding_digest"]!=expected_route["binding_digest"]
            or resolution["configuration_digest"]!=expected_route["configuration_digest"]
            or resolution["disclosure_destination_id"]!=expected_route["disclosure_destination_id"]
            or resolution["workspace_id"]!=origin["workspace"]["workspace_id"]):
        refuse("artifact_import_changed")
    for selector,entry in zip(selectors,resolution["entries"]):
        if spec["steps"][entry["producer_step_index"]]["step_id"]!=selector["from_step_id"]:
            refuse("artifact_producer_changed")
        receipt,manifest=producer(store,run,entry["producer_step_index"])
        if (entry["selector"]!=selector or entry["producer_receipt_blob_sha256"]!=run["steps"][entry["producer_step_index"]]["receipt_digest"]
                or entry["producer_output_manifest_blob_sha256"]!=run["steps"][entry["producer_step_index"]]["output_manifest_blob_sha256"]
                or entry["output"] not in manifest["outputs"] or entry["producer_checkpoint_digest"]!=receipt["checkpoint_digest"]):
            refuse("artifact_producer_changed")
        if staged:
            from .artifact_io import read_regular
            scratch=Path(attempt["workspace"]["path"])/attempt["workspace"]["scratch_relative"]
            ref=entry["output"]["artifact"]
            read_regular(scratch,entry["staged_relative_path"],max_bytes=MAX_BYTES,expected_sha256=ref["sha256"],expected_bytes=ref["bytes"],private=True,expected_mode=0o400)
            for pi,payload in enumerate(entry["output"]["payloads"]):
                read_regular(scratch,entry["staged_relative_path"]+"-payload-"+str(pi),max_bytes=MAX_BYTES,
                    expected_sha256=payload["artifact"]["sha256"],expected_bytes=payload["artifact"]["bytes"],private=True,expected_mode=0o400)
    return resolution,journal


def compile_packet(store,run,attempt,fields,admission):
    from .admission import worker_contract
    spec=store.spec(run);index=attempt["step_index"];r=route(spec,index)
    resolution,_=validate_import(store,run,attempt,staged=True)
    canonical=seal_versioned("worker-packet",fields | {"result_schema_id":"urn:taskalong:schema:v2.3:worker-result" if admission["schema_version"]=="2.3" else "urn:taskalong:schema:v1:worker-result", "step_id":attempt["step_id"],"step_index":index,
        "binding_digest":r["binding_digest"],"configuration_digest":r["configuration_digest"],"admission_digest":admission["digest"],
        "resolved_inputs_blob_sha256":attempt["resolved_inputs_blob_sha256"],"import_journal_blob_sha256":attempt["import_journal_blob_sha256"],
        "predecessor_receipt_blob_sha256":resolution["predecessor_receipt_blob_sha256"]},version=VERSION)
    route_version=admission["schema_version"]
    view=spec | {"schema_version":route_version,"execution":{"binding_digest":r["binding_digest"]}}
    if route_version=="2.3":view["execution"]["driver_config_digest"]=r["configuration_digest"]
    _,configuration,_=admit(store,spec,index)
    contract,provider=worker_contract(store,view,configuration)
    wire_fields=copy.deepcopy(fields)
    wire_fields["extensions"]["taskalong:handoff"]={"canonical_packet_digest":canonical["digest"],
        "resolved_inputs_blob_sha256":attempt["resolved_inputs_blob_sha256"],"import_journal_blob_sha256":attempt["import_journal_blob_sha256"],
        "staged_inputs":[{"path":attempt["workspace"]["scratch_relative"]+e["staged_relative_path"],"sha256":e["output"]["artifact"]["sha256"],
            "bytes":e["output"]["artifact"]["bytes"],"payloads":[{"path":attempt["workspace"]["scratch_relative"]+e["staged_relative_path"]+"-payload-"+str(pi),
                "sha256":payload["artifact"]["sha256"],"bytes":payload["artifact"]["bytes"]} for pi,payload in enumerate(e["output"]["payloads"])]} for e in resolution["entries"]]}
    if route_version=="2.2":
        wire_fields["bindings"]["runtime_profile_digest"]=configuration["digest"]
    route_packet,wire,route_projection=contract.compile_packet(wire_fields,admission)
    mapping=seal_versioned("packet-projection",subject(run,attempt) | {"workspace_id":attempt["workspace"]["workspace_id"],
        "binding_digest":r["binding_digest"],"configuration_digest":r["configuration_digest"],"admission_digest":admission["digest"],
        "resolved_inputs_blob_sha256":attempt["resolved_inputs_blob_sha256"],"import_journal_blob_sha256":attempt["import_journal_blob_sha256"],
        "predecessor_receipt_blob_sha256":resolution["predecessor_receipt_blob_sha256"],"canonical_packet_digest":canonical["digest"],
        "wire_packet_digest":wire["digest"],"route_packet_blob_sha256":store.put_blob(canonical_bytes(route_packet))["sha256"],"route_projection_blob_sha256":store.put_blob(canonical_bytes(route_projection))["sha256"],"wire_version":wire["schema_version"]},version=VERSION)
    return canonical,wire,mapping,contract,provider


def validate_packet(store,run,attempt,*,before_spawn=False):
    mapping=validate_versioned("packet-projection",attempt["packet_projection"],expected_version=VERSION)
    canonical=validate_versioned("worker-packet",attempt["canonical_packet"],expected_version=VERSION)
    packet=validate_versioned("worker-packet",attempt["packet"],expected_version=mapping["wire_version"])
    resolution,_=validate_import(store,run,attempt)
    route_version="2.3" if mapping["wire_version"]=="2.3" else "2.2"
    route_packet=validate_versioned("worker-packet",loads(store.get_blob(mapping["route_packet_blob_sha256"])),expected_version=route_version)
    route_mapping=validate_versioned("packet-projection",loads(store.get_blob(mapping["route_projection_blob_sha256"])),expected_version=route_version)
    prepared=store.operation("executor.prepare",run["run_id"],attempt["attempt_id"],{"packet_digest":packet["digest"]})
    if prepared is None or prepared["active_attempt_id"]!=attempt["attempt_id"]:
        refuse("artifact_proof_forged")
    if not before_spawn:
        spawned=store.operation("executor.spawned",run["run_id"],attempt["attempt_id"],{"receipt":attempt.get("process_receipt")})
        if spawned is None or not attempt.get("process_receipt"):
            refuse("artifact_proof_forged")
    if (route_mapping["canonical_packet_digest"]!=route_packet["digest"] or route_mapping["wire_packet_digest"]!=packet["digest"]
            or route_mapping["admission_digest"]!=attempt["dispatch_admission"]["digest"]
            or route_mapping["projection_digest"]!=attempt["dispatch_admission"]["projection"]["digest"]
            or any(canonical[k]!=packet[k] for k in ("run_id","attempt_id","spec_digest","packet_id","goal","non_goals","scope","checks","remaining_budget","qualification"))
            or any(canonical["bindings"][k]!=packet["bindings"][k] for k in canonical["bindings"])
            or any(canonical[k]!=v for k,v in subject(run,attempt).items() if k!="lease_generation")
            or canonical["bindings"]["lease_generation"]!=attempt["lease_generation"]
            or canonical["bindings"]["workspace_id"]!=attempt["workspace"]["workspace_id"]):
        refuse("artifact_packet_changed")
    spec=store.spec(run)
    step=spec["steps"][attempt["step_index"]]
    normalized_scope={"files":sorted(step["scope"]["files"]),"operations":sorted(step["scope"]["operations"])}
    if (any(canonical[k]!=v for k,v in {"goal":step["goal"],"non_goals":spec["non_goals"],
            "scope":normalized_scope,"checks":spec["checks"]}.items())
            or canonical["bindings"]["base_commit"]!=spec["repository"]["base_commit"]
            or canonical["bindings"]["initial_content_digest"]!=attempt["starting_snapshot_digest"]
            or any(route_mapping[k]!=canonical[k] for k in ("run_id","attempt_id","spec_digest","admission_digest"))
            or route_packet["binding_digest"]!=canonical["binding_digest"]
            or route_packet["admission_digest"]!=canonical["admission_digest"]
            or route_version=="2.2" and packet["extensions"].get("taskalong:canonical_packet_digest")!=route_packet["digest"]
            or route_version=="2.3" and canonical_bytes(route_packet)!=canonical_bytes(packet)):
        refuse("artifact_packet_changed")
    expected=subject(run,attempt) | {"workspace_id":attempt["workspace"]["workspace_id"],"canonical_packet_digest":canonical["digest"],
        "wire_packet_digest":packet["digest"],"binding_digest":route(store.spec(run),attempt["step_index"])["binding_digest"],
        "configuration_digest":route(store.spec(run),attempt["step_index"])["configuration_digest"],
        "resolved_inputs_blob_sha256":attempt["resolved_inputs_blob_sha256"],"import_journal_blob_sha256":attempt["import_journal_blob_sha256"],
        "admission_digest":attempt["dispatch_admission"]["digest"],"predecessor_receipt_blob_sha256":resolution["predecessor_receipt_blob_sha256"]}
    if (any(mapping[k]!=v for k,v in expected.items())
            or any(canonical[k]!=v for k,v in expected.items() if k in canonical and k not in {"kind","schema_version","digest"})
            or packet["extensions"]["taskalong:handoff"]["canonical_packet_digest"]!=canonical["digest"]):
        refuse("artifact_packet_changed")
    return packet


def validate_worker(store,run,attempt,worker):
    packet=validate_packet(store,run,attempt)
    version="2.3" if packet["schema_version"]=="2.3" else "1.0"
    worker=validate_versioned("worker-result",worker,expected_version=version)
    if version=="2.3" and (worker["session_id"]!=packet["session_id"] or any(worker[k]!=packet["bindings"][k] for k in ("driver_config_digest","provider_profile_digest"))):
        refuse("worker_binding_mismatch")
    return worker
