"""Bounded ordered fixture tasks in the existing run, lease and effect lifecycle.

Portable plans do not select providers or grant authority. Receipts refer to
immutable private blobs, and reservations never refund observed or lost work.
"""
from __future__ import annotations

from dataclasses import dataclass
import copy
import hashlib
from pathlib import Path
from typing import ClassVar

from .contracts import JsonDocument
from .errors import TaskAlongError
from .paths import safe_relative
from .validation import canonical_bytes, digest, loads, seal_versioned, validate, validate_versioned


def refuse(code, message):
    raise TaskAlongError(code, message, exit_code=3)


def enabled(spec):
    return spec["schema_version"] in {"2.7", "2.10"}


@dataclass(frozen=True, slots=True)
class OrderedTaskSpec(JsonDocument):
    schema_name: ClassVar[str] = "task-spec"

    def __post_init__(self):
        value = validate_versioned(self.schema_name, loads(self._canonical), expected_version="2.7")
        object.__setattr__(self, "_canonical", canonical_bytes(value))


def contains(scope, path):
    return any(path == item or item.endswith("/") and path.startswith(item) for item in scope["files"])


def delta(before_manifest, after_manifest, scope):
    before = {f["path"]:f for f in before_manifest}
    after = {f["path"]:f for f in after_manifest}
    changed = sorted(p for p in before.keys() | after.keys() if before.get(p) != after.get(p))
    result = []
    for path in changed:
        # Manifests describe changes from the task base. A previously added
        # file exists at this step's start; changing it is now a modification.
        if path in before and before[path]["operation"] == "add" and path not in after:
            refuse("step_delete_unsupported", "A step cannot delete a file added by an earlier attempt.")
        operation = "add" if path not in before and after[path]["operation"] == "add" else "modify"
        if not contains(scope, path) or operation not in scope["operations"]:
            refuse("step_scope_violation", "The worker changed bytes outside its current step scope.")
        result.append({"path":path,"operation":operation})
    return result


def semantics(value, name):
    if name != "task-spec":
        if name == "result-view" and (value["independently_accepted"] != (value["outcome"] == "accepted")
                or value["independently_accepted"] != (value["state"] == "accepted")):
            refuse("ordered_result_invalid", "Accepted state, outcome and independent acceptance must agree.")
        if name == "result-view" and value["independently_accepted"] and (
                value["acceptance_digest"] is None or value["execution_chain_digest"] is None
                or value["completed_steps"] != value["total_steps"] or value["final_verification"]["status"] != "passed"):
            refuse("ordered_result_invalid", "Acceptance requires the complete result chain and successful final verification.")
        return
    steps = value["steps"]
    if len({step["step_id"] for step in steps}) != len(steps):
        refuse("duplicate_step_id", "Step IDs must be unique within the ordered task.")
    for step in steps:
        if not step["goal"].strip() or not step["step_id"].strip():
            refuse("invalid_step", "Each required step needs an ID and a nonempty goal.")
        if sum(len(x.encode("utf-8")) for x in [step["goal"], *value["non_goals"]]) > 16384:
            refuse("invalid_step", "A step goal and task non-goals must fit the existing 16 KiB worker packet bound.")
        for path in step["scope"]["files"]:
            safe_relative(path, allow_directory=True)
            if not contains(value["scope"], path):
                refuse("step_scope_expansion", "Every step edit path must fit the task scope.")
        if not set(step["scope"]["operations"]) <= set(value["scope"]["operations"]):
            refuse("step_scope_expansion", "Every step edit operation must fit the task scope.")
        if len({item["path"] for item in step["inputs"]}) != len(step["inputs"]):
            refuse("duplicate_step_input", "A step cannot repeat an input path.")
        for item in step["inputs"]:
            safe_relative(item["path"])
    b, f = value["budget"], value["final_verification"]
    if b["hard_tokens"] is not None or b["hard_cost_usd"] is not None:
        refuse("hard_budget_unsupported", "The fixture cannot enforce hard token or cost limits.")
    if (b["max_attempts"] < len(steps)
            or b["total_active_seconds"] < len(steps)*b["attempt_seconds"] + f["total_active_seconds"]
            or b["max_output_bytes"] < len(steps)*b["attempt_output_bytes"] + f["max_output_bytes"]):
        refuse("insufficient_task_limits", "Declared task limits must fund all required steps and one final verification pass.")
    # The unchanged reviewer owns two 15-second probes and a 60-second review.
    if f["total_active_seconds"] < sum(c["timeout_seconds"] for c in value["checks"]) + 90:
        refuse("insufficient_verification_limits", "Final verification must reserve all checks and the reviewer's two 15-second probes plus 60-second review.")
    if set(value["permissions"]["allowed_effects"]) != {"execute", "verify", "commit_candidate"}:
        refuse("ordered_effects_unsupported", "Ordered fixture tasks permit execution and independent verification only.")


def inputs(spec, root, step_index=None):
    """Check every declared repository-file input before any worker launch."""
    if spec["schema_version"] == "2.10":
        from .artifact_handoff import inputs as artifact_inputs
        return artifact_inputs(spec, root, step_index)
    root = Path(root)
    for step in spec["steps"] if step_index is None else [spec["steps"][step_index]]:
        for item in step["inputs"]:
            path = root / item["path"]
            if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file():
                refuse("step_input_unavailable", "Step inputs must be existing regular repository files.")
            if path.stat().st_size > 1048576 or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
                refuse("step_input_changed", "Declared repository input bytes no longer match their SHA-256.")


def preflight(workflow, spec):
    if spec["schema_version"] == "2.10":
        from .artifact_handoff import preflight as artifact_preflight
        return artifact_preflight(workflow, spec)
    repository = workflow.store.repository(spec["repository"]["registration_id"])
    inputs(spec, repository["path"])
    from .workspace import git
    for step in spec["steps"]:
        for item in step["inputs"]:
            original = git(repository["path"], "show", spec["repository"]["base_commit"] + ":" + item["path"], binary=True)
            if hashlib.sha256(original).hexdigest() != item["sha256"]:
                refuse("step_input_changed", "Inputs must bind existing repository bytes at the immutable task base.")
    profile = workflow._profile(spec)
    if profile["qualification"] != "synthetic" or profile["credential_source_ref"] is not None:
        refuse("ordered_configuration_unsupported", "Select one existing synthetic Codex fixture without credentials.")
    workflow._executor(spec, profile).preflight(qualification="synthetic", budget=spec["budget"])
    return spec


def initialize(run, spec):
    run.update(schema_version=spec["schema_version"], current_step_index=0,
        steps=[{"step_id":s["step_id"], "status":"pending", "attempt_ids":[], "receipt_digest":None} for s in spec["steps"]],
        reservations=[], reservation_totals={"attempts":0,"active_seconds":0,"output_bytes":0},
        final_verification_ids=[], execution_chain_digest=None)
    if spec["schema_version"] == "2.10":
        run["cancellation_requested"] = False
        for step in run["steps"]:
            step["output_manifest_blob_sha256"] = None


def reserve(run, spec, *, reservation_id, kind, owner_id):
    if kind == "worker":
        amounts = {"attempts":1,"active_seconds":spec["budget"]["attempt_seconds"],"output_bytes":spec["budget"]["attempt_output_bytes"]}
        # Preserve enough allowance for the remaining required steps and final pass.
        remaining = len(spec["steps"]) - run["current_step_index"] - 1
        future = {"attempts":remaining,"active_seconds":remaining*spec["budget"]["attempt_seconds"] + spec["final_verification"]["total_active_seconds"],
                  "output_bytes":remaining*spec["budget"]["attempt_output_bytes"] + spec["final_verification"]["max_output_bytes"]}
    else:
        if len(run["final_verification_ids"]) >= spec["final_verification"]["max_passes"]:
            refuse("budget_exhausted", "The declared final verification passes are exhausted.")
        amounts = {"attempts":0,"active_seconds":spec["final_verification"]["total_active_seconds"],"output_bytes":spec["final_verification"]["max_output_bytes"]}
        future = dict.fromkeys(amounts, 0)
    limits = {"attempts":spec["budget"]["max_attempts"],"active_seconds":spec["budget"]["total_active_seconds"],"output_bytes":spec["budget"]["max_output_bytes"]}
    if any(run["reservation_totals"][k]+amounts[k]+future[k] > limits[k] for k in amounts):
        refuse("budget_exhausted", "Persisted no-refund reservations cannot fund this launch and the remaining required work.")
    reservation = {"reservation_id":reservation_id,"kind":kind,"owner_id":owner_id,**amounts}
    run["reservations"].append(reservation)
    for k in amounts:
        run["reservation_totals"][k] += amounts[k]
    return reservation


def validate_chain(store, run, *, live=False, complete=False):
    """Re-read every successful attempt and immutable receipt at each boundary."""
    spec = store.spec(run)
    validate_versioned("task-run", run, expected_version=spec["schema_version"])
    if len(run["steps"]) != len(spec["steps"]) or any(a["step_id"] != b["step_id"] for a,b in zip(run["steps"],spec["steps"])):
        refuse("step_order_invalid", "The persisted step order differs from the immutable task.")
    totals = {key:sum(r[key] for r in run["reservations"]) for key in run["reservation_totals"]}
    if (totals != run["reservation_totals"] or totals["attempts"] != len(run["attempts"])
            or totals["attempts"] != run["budget_consumed"]["attempts"]
            or len({r["reservation_id"] for r in run["reservations"]}) != len(run["reservations"])
            or totals["attempts"] > spec["budget"]["max_attempts"]
            or totals["active_seconds"] > spec["budget"]["total_active_seconds"]
            or totals["output_bytes"] > spec["budget"]["max_output_bytes"]):
        refuse("reservation_changed", "The conserved reservation inventory is inconsistent.")
    prior = None
    count = 0
    for index, state in enumerate(run["steps"]):
        ref = state["receipt_digest"]
        if ref is None:
            if state["status"] == "completed":
                refuse("step_receipt_missing", "A completed step requires its retained immutable receipt.")
            continue
        if count != index or state["status"] != "completed":
            refuse("step_order_invalid", "Completed receipts must form an ordered prefix.")
        receipt = validate_versioned("step-receipt", loads(store.get_blob(ref)), expected_version=spec["schema_version"])
        item = store.detail("attempts", receipt["attempt_id"])
        if spec["schema_version"] == "2.10":
            from .artifact_handoff import validate_packet, validate_worker
            packet = validate_packet(store, run, item)
            worker = validate_worker(store, run, item, loads(store.get_blob(receipt["result_digest"])))
        else:
            packet = validate("worker-packet", item["packet"])
            worker = validate("worker-result", loads(store.get_blob(receipt["result_digest"])))
        expected = {"run_id":run["run_id"],"spec_digest":spec["digest"],"step_id":spec["steps"][index]["step_id"],
            "step_index":index,"lease_generation":item["lease_generation"],"packet_digest":item["packet"]["digest"],
            "result_digest":(item.get("result_artifact") or {}).get("sha256"),"process_digest":digest(item["process"]),
            "checkpoint_digest":digest(item["checkpoint"]),"starting_snapshot_digest":item["starting_snapshot_digest"],
            "final_snapshot_digest":item["checkpoint"]["content_digest"],"reservation_digest":digest(item["reservation"]),"predecessor_digest":prior}
        if (receipt["digest"] != digest(receipt) or any(receipt[k] != v for k,v in expected.items())
                or receipt["attempt_id"] not in state["attempt_ids"] or item["step_index"] != index
                or item["status"] != "completed" or item.get("termination_confirmed") is not True
                or worker["packet_digest"] != item["packet"]["digest"] or worker["attempt_id"] != item["attempt_id"]
                or worker["spec_digest"] != spec["digest"] or worker["status"] != "completed"
                or worker["run_id"] != run["run_id"] or item["reservation"] not in run["reservations"]
                or packet["extensions"].get("taskalong:ordered_step") != {"step_id":spec["steps"][index]["step_id"],
                    "step_index":index,"step_digest":digest(spec["steps"][index]), "predecessor_digest":prior,
                    "reservation_digest":digest(item["reservation"]),"inputs":spec["steps"][index]["inputs"]}):
            refuse("step_receipt_changed", "An ordered step result, checkpoint or reservation has changed.")
        if spec["schema_version"] == "2.10":
            from .artifact_handoff import validate_import, producer
            resolution, journal = validate_import(store, run, item, staged=live)
            first = store.detail("attempts", state["attempt_ids"][0])
            if (first["starting_snapshot_digest"] != journal["after_content_digest"]
                    or journal["predecessor_receipt_blob_sha256"] != prior
                    or index and journal["before_content_digest"] != loads(store.get_blob(prior))["final_snapshot_digest"]
                    or any(receipt[k] != item[k] for k in ("resolved_inputs_blob_sha256", "import_journal_blob_sha256"))
                    or receipt["canonical_packet_digest"] != item["canonical_packet"]["digest"]
                    or receipt["packet_projection_blob_sha256"] != hashlib.sha256(canonical_bytes(item["packet_projection"])).hexdigest()):
                refuse("artifact_import_changed", "The ordered import transition or packet has changed.")
            producer(store, run, index)
        if spec["schema_version"] == "2.7" and index and item["starting_snapshot_digest"] != validate_versioned("step-receipt", loads(store.get_blob(prior)), expected_version="2.7")["final_snapshot_digest"]:
            # Retried work may retain partial edits: its first attempt, not its
            # eventual successful attempt, must start at the predecessor.
            first = store.detail("attempts", state["attempt_ids"][0])
            preceding = loads(store.get_blob(prior))
            if first["starting_snapshot_digest"] != preceding["final_snapshot_digest"]:
                refuse("step_chain_changed", "The next step did not retain the previous workspace checkpoint.")
        prior, count = ref, count+1
    if complete and count != len(spec["steps"]):
        refuse("steps_incomplete", "Final verification requires every required step to complete.")
    allowed_index = {count, max(0,count-1)} if count < len(spec["steps"]) else {count-1}
    if run["current_step_index"] not in allowed_index:
        refuse("step_order_invalid", "The current step is inconsistent with its completed predecessors.")
    if live and run["attempts"]:
        item = store.detail("attempts", run["attempts"][-1]["attempt_id"])
        workspace = store.lease(run)["workspace"]
        from .workflow import Workflow
        manager = Workflow(store)._manager(run)
        manager.validate(workspace, run["lease_generation"])
        snapshot = manager.snapshot(workspace, spec["scope"], expected_head=run["candidate"]["commit"] if run["candidate"] else spec["repository"]["base_commit"])
        if (item.get("checkpoint") or {}).get("content_digest") != snapshot["content_digest"]:
            refuse("checkpoint_stale", "The live workspace no longer matches the stopped ordered checkpoint.")
    return digest({"spec_digest":spec["digest"],"step_receipts":[s["receipt_digest"] for s in run["steps"]]})


def completed_receipt(store, run, item, result, worker):
    fields = {"run_id":run["run_id"],"spec_digest":run["spec_digest"],"step_id":run["steps"][item["step_index"]]["step_id"],
        "step_index":item["step_index"],"attempt_id":item["attempt_id"],"lease_generation":item["lease_generation"],
        "packet_digest":item["packet"]["digest"],"result_digest":hashlib.sha256(canonical_bytes(worker)).hexdigest(),
        "process_digest":digest(result["process"]),"checkpoint_digest":digest(result["checkpoint"]),
        "starting_snapshot_digest":item["starting_snapshot_digest"],"final_snapshot_digest":result["checkpoint"]["content_digest"],
        "reservation_digest":digest(item["reservation"]),"predecessor_digest":run["steps"][item["step_index"]-1]["receipt_digest"] if item["step_index"] else None}
    if store.spec(run)["schema_version"] == "2.10":
        fields.update(resolved_inputs_blob_sha256=item["resolved_inputs_blob_sha256"],
            import_journal_blob_sha256=item["import_journal_blob_sha256"],canonical_packet_digest=item["canonical_packet"]["digest"],
            packet_projection_blob_sha256=hashlib.sha256(canonical_bytes(item["packet_projection"])).hexdigest())
    return store.put_blob(canonical_bytes(seal_versioned("step-receipt", fields, version=store.spec(run)["schema_version"])))["sha256"]


def require_finish_identity(run, spec, item):
    """A live attempt may finish only its current immutable ordered step."""
    index = item.get("step_index")
    if (type(index) is not int or not 0 <= index < len(spec["steps"])
            or index != run["current_step_index"] or index >= len(run["steps"])
            or item.get("attempt_id") != run["active_attempt_id"]
            or item.get("step_id") != spec["steps"][index]["step_id"]
            or run["steps"][index]["step_id"] != spec["steps"][index]["step_id"]
            or item["attempt_id"] not in run["steps"][index]["attempt_ids"]):
        raise TaskAlongError("step_identity_mismatch", "The finishing attempt does not own the current ordered step.", exit_code=4)


def view(store, run):
    validate_chain(store, run)
    acceptance = store.detail("acceptances", run["acceptance_id"]) if run["acceptance_id"] else None
    accepted = bool(acceptance and acceptance["decision"] == "accepted" and run["state"] == "accepted")
    if accepted:
        validate("acceptance", acceptance)
        chain = validate_chain(store, run, live=True, complete=True)
        if (acceptance["extensions"].get("taskalong:execution_chain_digest") != chain
                or acceptance["candidate"] != run["candidate"] or acceptance["spec_digest"] != run["spec_digest"]):
            refuse("ordered_acceptance_changed", "Final acceptance does not match the actual ordered results and candidate.")
    completed = sum(s["status"] == "completed" for s in run["steps"])
    step_results = []
    for state in run["steps"]:
        attempts = []
        for attempt_id in state["attempt_ids"]:
            item = store.detail("attempts", attempt_id)
            process = item.get("process") or {}
            result_digest = (item.get("result_artifact") or {}).get("sha256")
            if result_digest:
                store.get_blob(result_digest)
            attempts.append({"attempt_id":attempt_id,"status":item["status"],"error":item.get("error"),
                "termination_confirmed":item.get("termination_confirmed") is True,"worker_result_digest":result_digest,
                "checkpoint_digest":digest(item["checkpoint"]) if item.get("checkpoint") else None,
                "output_bytes":process.get("output_bytes"),"duration_ms":process.get("duration_ms")})
        step_results.append({"step_id":state["step_id"],"receipt_digest":state["receipt_digest"],"attempts":attempts})
    checks, review_result = [], None
    if acceptance:
        for evidence_id in acceptance["evidence_ids"]:
            record = validate("evidence", store.detail("evidence", evidence_id))
            if record["type"] == "command":
                check = next((c for c in store.spec(run)["checks"] if digest(c) == record["inputs"]["check_digest"]), None)
                if check:
                    checks.append({"id":check["id"],"result":record["result"],"evidence_digest":digest(record)})
            elif record["type"] == "review":
                review_result = record["result"]
    else:
        # No acceptance may yet exist after a stopped/failed final pass.
        for evidence_id in run["evidence_ids"]:
            record = validate("evidence", store.detail("evidence", evidence_id))
            if record["type"] == "command":
                check = next((c for c in store.spec(run)["checks"] if digest(c) == record["inputs"]["check_digest"]), None)
                if check:
                    checks = [c for c in checks if c["id"] != check["id"]]
                    checks.append({"id":check["id"],"result":record["result"],"evidence_digest":digest(record)})
    reason = run["blockers"][0]["code"] if run["blockers"] else None
    if accepted: outcome, actions = "accepted", []
    elif run["state"] == "cancelled": outcome, actions = "cancelled", []
    elif run["active_attempt_id"] or run["pending_effect_ids"] or run["state"] == "cancel_pending": outcome, actions = "unknown" if run["state"] == "blocked" else "pending", ["reconcile"]
    elif completed == len(run["steps"]): outcome, actions = "failed" if reason else "steps_completed", ["verify"]
    elif run["steps"][run["current_step_index"]]["status"] == "failed": outcome, actions = "failed", ["retry"]
    elif completed: outcome, actions = "pending", ["advance"]
    else: outcome, actions = "pending", ["start"]
    if actions == ["retry"] and not store.detail("attempts", run["steps"][run["current_step_index"]]["attempt_ids"][-1]).get("checkpoint"):
        actions = ["inspect"]
    if actions and actions[0] in {"start","advance","retry","verify"}:
        probe = copy.deepcopy(run)
        if actions == ["advance"]:
            probe["current_step_index"] += 1
        try:
            reserve(probe, store.spec(run), reservation_id="00000000-0000-4000-8000-000000000000",
                kind="verification" if actions == ["verify"] else "worker", owner_id="inspection")
        except TaskAlongError as exc:
            if exc.code != "budget_exhausted":
                raise
            actions = ["inspect"]
            reason = reason or "budget_exhausted"
    verification_status = "passed" if accepted else "failed" if any(c["result"] != "passed" for c in checks) else "running" if run["state"] == "verifying" else "blocked" if completed == len(run["steps"]) and reason else "pending"
    if reason == "required_review_missing":
        review_result = "missing"
    extra = {}
    if run["schema_version"] == "2.10":
        extra["handoffs"] = []
        for brief in run["attempts"]:
            item = store.detail("attempts", brief["attempt_id"])
            extra["handoffs"].append({"step_id":item["step_id"],"attempt_id":item["attempt_id"],
                "resolved_inputs_blob_sha256":item.get("resolved_inputs_blob_sha256"),
                "import_journal_blob_sha256":item.get("import_journal_blob_sha256"),
                "canonical_packet_digest":(item.get("canonical_packet") or {}).get("digest"),
                "wire_packet_digest":(item.get("packet") or {}).get("digest")})
    worker_processes = [store.detail("attempts", item["attempt_id"]).get("process") or {} for item in run["attempts"]]
    duration = sum(p["duration_ms"] for p in worker_processes) if all(p.get("termination_confirmed") is True and type(p.get("duration_ms")) is int for p in worker_processes) else None
    captured = sum(p["output_bytes"] for p in worker_processes) if all(p.get("termination_confirmed") is True and type(p.get("output_bytes")) is int for p in worker_processes) else None
    for row in store.db.execute("SELECT document FROM effects WHERE run_id=? AND kind='verifier.capture'", (run["run_id"],)):
        effect = loads(row[0])
        response = effect.get("response") or {}
        if effect["phase"] != "observed" or response.get("termination_confirmed") is not True or type(response.get("output_bytes")) is not int:
            captured = None
        elif captured is not None:
            captured += response["output_bytes"]
    observed = {"worker_duration_ms":duration,"captured_output_bytes":captured,
        **{key:run["budget_consumed"][key] for key in ("input_tokens","output_tokens","cost_usd")}}
    return seal_versioned("result-view", {**extra,"run_id":run["run_id"],"revision":run["revision"],"state":run["state"],
        "outcome":outcome,"independently_accepted":accepted,"steps":run["steps"],"current_step_index":run["current_step_index"],
        "completed_steps":completed,"total_steps":len(run["steps"]),"reservation_totals":run["reservation_totals"],
        "observed_usage":observed,"execution_chain_digest":run["execution_chain_digest"],
        "acceptance_digest":digest(acceptance) if acceptance else None,"stop_reason":reason,"next_actions":actions,
        "step_results":step_results,"final_verification":{"passes_reserved":len(run["final_verification_ids"]),
            "status":verification_status,"checks":checks,"review_result":review_result},
        "production_dispatch_allowed":False}, version=run["schema_version"])
