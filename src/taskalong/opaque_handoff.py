"""Shared opaque-output Store handoff mechanics; contracts supply exact readers.

No qualification is granted here. The closed built-in contract's resolver must
recheck actual admission before completion, verification, acceptance or reuse.
"""
import hashlib
from .errors import TaskAlongError
from .store import encode
from .validation import canonical_bytes, digest, loads, seal_versioned, validate, validate_versioned

class OpaqueHandoff:
    def __init__(self, *, version, projection, resolve, refuse, bind_subject=lambda p,a,u,m: {}):
        self.version, self.projection = version, projection
        self.resolve, self.refuse, self.bind_subject = resolve, refuse, bind_subject

    def _confirmed(self, process):
        return (type(process) is dict and process.get("termination_confirmed") is True
                and process.get("group_termination_confirmed") is True
                and process.get("unaccounted_descendants") is False)


    def _operation(self, store, run_id, command, attempt_id, request):
        row = store.db.execute("SELECT request_digest FROM operations WHERE command=? AND run_id=? AND operation_key=?",
                              (command, run_id, attempt_id)).fetchone()
        if row is None or row[0] != digest(request):
            self.refuse("muse_handoff_invalid")


    def retain_capture(self, store, run_id, attempt_id, result):
        """Retain originals from the trusted in-process owner, not receipt self-claims."""
        capture = result.pop("_muse_capture", None)
        if capture is None:
            self.refuse("muse_capture_missing")
        run = store.run(run_id)
        attempt = store.detail("attempts", attempt_id)
        packet = validate_versioned("worker-packet", attempt["packet"], expected_version=self.version)
        directory = store.root / "attempts" / attempt_id / "muse-raw"
        if capture.directory != directory:
            self.refuse("muse_capture_missing")
        expected = {"input.bin": canonical_bytes(packet), "receipt.json": capture.receipt_json}
        if capture.original is not None:
            expected.update({"stdout.bin": capture.original[0], "stderr.bin": capture.original[1]})
        refs = {}
        for name, raw in expected.items():
            path = directory / name
            if (path.is_symlink() or not path.is_file() or path.stat().st_size != len(raw)
                    or path.read_bytes() != raw):
                self.refuse("muse_capture_invalid")
            refs[name] = store.put_blob(raw, media_type=("application/octet-stream"
                if name in {"stdout.bin", "stderr.bin"} else "application/json"))
        process = result["process"]
        if capture.process is not None and process.get("receipt") != attempt.get("process_receipt"):
            self.refuse("muse_process_mismatch")
        record = {"packet_digest": packet["digest"], "admission_digest": attempt["dispatch_admission"]["digest"],
            "driver_config_digest": attempt["driver_config_digest"], "refs": refs,
            "process": process, "error": result.get("error"), "capture_status": capture.status}
        record["digest"] = digest(record)
        def retained(current, db):
            item = store.detail("attempts", attempt_id)
            if current["active_attempt_id"] != attempt_id or item["lease_generation"] != current["lease_generation"]:
                self.refuse("lease_fenced")
            item["muse_capture"] = record
            db.execute("UPDATE attempts SET document=? WHERE attempt_id=?", (encode(item), attempt_id))
        store.mutate(run_id, "muse.capture", attempt_id, None, {"capture_digest": record["digest"]}, retained,
                     events=[("muse.capture.retained", {"attempt_id": attempt_id})], fence=run["lease_generation"])


    def _subject(self, store, run, spec, attempt, manager, workspace):
        store.require_fence(run, attempt["lease_generation"])
        if (run["lease_generation"] != attempt["lease_generation"]
                or run["attempts"][-1]["attempt_id"] != attempt["attempt_id"]):
            self.refuse("muse_handoff_stale")
        packet = validate_versioned("worker-packet", attempt["packet"], expected_version=self.version)
        admission = attempt["dispatch_admission"]
        authority = store.authority(run, {"execute", "verify", "commit_candidate"}, spec["digest"], admission["authority_id"])
        fresh, config, _ = self.resolve(store, spec, authority_id=authority["authority_id"])
        if ((canonical_bytes(fresh) != canonical_bytes(admission) if self.version == "2.12" else fresh != admission)
                or digest(admission) != admission["digest"]):
            self.refuse("admission_changed")
        expected_bindings = {"run_id": run["run_id"], "attempt_id": attempt["attempt_id"], "spec_digest": spec["digest"]}
        if (any(packet[k] != v for k, v in expected_bindings.items())
                or packet["admission_digest"] != admission["digest"]
                or packet["bindings"]["driver_config_digest"] != config["digest"]
                or packet["bindings"]["workspace_id"] != workspace["workspace_id"]
                or packet["bindings"]["lease_generation"] != run["lease_generation"]
                or attempt["workspace"] != workspace or attempt["canonical_packet"] != packet):
            self.refuse("muse_handoff_stale")
        mapping = validate_versioned("packet-projection", attempt["packet_projection"], expected_version=self.version)
        if (mapping["canonical_packet_digest"] != packet["digest"] or mapping["wire_packet_digest"] != packet["digest"]
                or mapping["projection_digest"] != admission["projection"]["digest"]
                or mapping["admission_digest"] != admission["digest"] or mapping["driver_config_digest"] != config["digest"]
                or any(mapping[k] != v for k, v in expected_bindings.items())
                or packet["bindings"]["base_commit"] != spec["repository"]["base_commit"]
                or packet["scope"] != spec["scope"] or packet["checks"] != spec["checks"]):
            self.refuse("muse_handoff_invalid")
        self._operation(store, run["run_id"], "executor.prepare", attempt["attempt_id"], {"packet_digest": packet["digest"]})
        self._operation(store, run["run_id"], "executor.spawned", attempt["attempt_id"], {"receipt": attempt["process_receipt"]})
        for value in (packet, mapping):
            if store.get_blob(hashlib.sha256(canonical_bytes(value)).hexdigest()) != canonical_bytes(value):
                self.refuse("muse_handoff_invalid")
        capture = attempt.get("muse_capture")
        if (not capture or digest(capture) != capture["digest"] or capture["error"] is not None
                or capture["capture_status"] != "local_turn_completed"
                or set(capture["refs"]) != {"input.bin", "stdout.bin", "stderr.bin", "receipt.json"}
                or capture["packet_digest"] != packet["digest"]
                or capture["admission_digest"] != admission["digest"]
                or capture["driver_config_digest"] != config["digest"]):
            self.refuse("muse_capture_invalid")
        self._operation(store, run["run_id"], "muse.capture", attempt["attempt_id"], {"capture_digest": capture["digest"]})
        process = capture["process"]
        if (not self._confirmed(process) or process.get("exit_code") != 0
                or any(process.get(k) for k in ("timed_out", "cancelled", "output_limited", "protocol_error"))
                or process.get("receipt") != attempt["process_receipt"]
                or process["receipt"]["executable_sha256"] != config["executable"]["sha256"]):
            self.refuse("muse_termination_unconfirmed")
        for ref in capture["refs"].values():
            raw = store.get_blob(ref["sha256"])
            if len(raw) != ref["bytes"]:
                self.refuse("muse_capture_invalid")
        if store.get_blob(capture["refs"]["input.bin"]["sha256"]) != canonical_bytes(packet):
            self.refuse("muse_capture_invalid")
        manager.validate(workspace, run["lease_generation"])
        head = run["candidate"]["commit"] if run.get("candidate") else spec["repository"]["base_commit"]
        snapshot = manager.snapshot(workspace, spec["scope"], expected_head=head)
        observed = {"head": packet["bindings"]["initial_head"], "content_digest": snapshot["content_digest"],
                    "manifest_sha256": digest(snapshot["manifest"]), "changed_files": snapshot["changed_files"]}
        extra = self.bind_subject(packet, admission, authority, mapping)
        return {"extensions": {}, "producer_role": "supervisor", "projection": self.projection, **expected_bindings, **extra,
            "packet_digest": packet["digest"], "admission_digest": admission["digest"], "driver_config_digest": config["digest"],
            "authority_id": authority["authority_id"], "workspace_id": workspace["workspace_id"],
            "lease_generation": run["lease_generation"], "capture_digest": capture["digest"],
            "process_observation_digest": digest(process), "process_receipt_digest": digest(attempt["process_receipt"]),
            "workspace_snapshot": observed, "observed_model": None, "observed_session": None,
            "usage": {"input_tokens": None, "output_tokens": None, "cost_usd": None}, "outcome": "local_turn_completed"}


    def create_handoff(self, store, run_id, attempt_id, manager, workspace):
        run = store.run(run_id)
        # Cancellation prohibits new handoffs, not validation of an already
        # committed completed handoff during cancellation reconciliation.
        if run["active_attempt_id"] != attempt_id or run["state"] != "running":
            self.refuse("lease_fenced")
        spec = store.spec(run)
        attempt = store.detail("attempts", attempt_id)
        return seal_versioned("execution-handoff", self._subject(store, run, spec, attempt, manager, workspace), version=self.version)


    def validate_handoff(self, store, run, spec, attempt, manager, workspace, *, before_finish=False, handoff=None):
        if before_finish:
            if run["state"] != "running" or run["active_attempt_id"] != attempt["attempt_id"]:
                self.refuse("muse_handoff_stale")
        else:
            ref = attempt.get("execution_handoff")
            if not ref or attempt["status"] != "completed" or attempt["termination_confirmed"] is not True:
                self.refuse("muse_handoff_missing")
            capture = attempt.get("muse_capture")
            if type(capture) is not dict or type(capture.get("process")) is not dict:
                self.refuse("muse_capture_invalid")
            if attempt.get("process") != capture["process"]:
                self.refuse("muse_process_mismatch")
            handoff = loads(store.get_blob(ref["sha256"]))
            row = store.db.execute("SELECT request_digest FROM operations WHERE command='executor.finish' AND run_id=? AND operation_key=?",
                (run["run_id"], attempt["attempt_id"])).fetchone()
            if row is None or row[0] != digest({"state": "completed", "artifact": None, "execution_handoff": ref}):
                self.refuse("muse_handoff_invalid")
        validated = validate_versioned("execution-handoff", handoff, expected_version=self.version)
        expected = seal_versioned("execution-handoff", self._subject(store, run, spec, attempt, manager, workspace), version=self.version)
        if validated != expected:
            self.refuse("muse_handoff_stale")
        return validated


    def validate_current(self, store, run):
        if not run["attempts"]:
            return None
        attempt = store.detail("attempts", run["attempts"][-1]["attempt_id"])
        if attempt["status"] == "completed" or run["acceptance_id"]:
            from .workflow import Workflow
            return self.validate_handoff(store, run, store.spec(run), attempt,
                Workflow(store)._manager(run), store.lease(run)["workspace"])
        return None


    def capabilities_view(self, store, run, spec, mode):
        satisfied, reasons = False, []
        try:
            if mode != "start":
                self.refuse("execution_mode_unsupported")
            self.resolve(store, spec)
            satisfied = True
        except TaskAlongError as error:
            reasons = [error.code]
        return seal_versioned("capabilities-view", {"run_id": run["run_id"], "revision": run["revision"],
            "mode": mode, "configuration_digest": spec["execution"]["driver_config_digest"],
            "requirements_satisfied": satisfied, "decision_digest": None, "reason_codes": reasons,
            "production_dispatch_allowed": False}, version=self.version)


    def result_view(self, store, run):
        handoff = self.validate_current(store, run)
        attempt = store.detail("attempts", run["attempts"][-1]["attempt_id"]) if run["attempts"] else None
        acceptance = store.detail("acceptances", run["acceptance_id"]) if run["acceptance_id"] else None
        if acceptance is not None:
            acceptance = validate("acceptance", acceptance)
            if (acceptance["run_id"] != run["run_id"] or acceptance["spec_digest"] != run["spec_digest"]
                    or acceptance["candidate"] != run["candidate"]):
                self.refuse("store_integrity")
        accepted = bool(acceptance and acceptance["decision"] == "accepted" and run["state"] == "accepted")
        if run["state"] == "cancelled":
            outcome = "cancelled"
        elif run["state"] == "cancel_pending":
            outcome = "pending"
        elif accepted:
            outcome = "accepted"
        elif run["active_attempt_id"] or run["pending_effect_ids"]:
            outcome = "unknown" if run["state"] == "blocked" else "pending"
        elif handoff is not None:
            outcome = "execution_handoff_ready"
        else:
            outcome = "failed" if run["state"] == "failed" else "unknown" if run["state"] == "blocked" else "pending"
        artifacts = {}
        for evidence_id in run["evidence_ids"]:
            for ref in store.detail("evidence", evidence_id)["artifacts"]:
                store.get_blob(ref["sha256"])
                artifacts[ref["sha256"]] = ref
        ref = attempt.get("execution_handoff") if attempt else None
        if ref:
            artifacts[ref["sha256"]] = ref
        return seal_versioned("result-view", {"run_id": run["run_id"], "revision": run["revision"],
            "state": run["state"], "outcome": outcome, "independently_accepted": accepted,
            "acceptance_digest": digest(acceptance) if acceptance else None,
            "execution_handoff_digest": ref["sha256"] if ref else None,
            "canonical_packet_digest": attempt["packet"]["digest"] if attempt and attempt.get("packet") else None,
            "evidence_artifacts": [artifacts[k] for k in sorted(artifacts)], "production_dispatch_allowed": False}, version=self.version)
