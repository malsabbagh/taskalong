"""The provider-neutral local facade used by CLI and orchestrators."""
from __future__ import annotations

import os
from pathlib import Path
import shutil

from .errors import TaskAlongError
from .paths import default_state_dir
from .store import Store, identifier
from .validation import canonical_bytes, digest, seal_versioned, validate, validate_versioned
from .workflow import Workflow


class RunService:
    """Trusted operating-system control plane. Worker JSON is never a command.

    The single-user facade trusts its caller's operating-system identity; it does
    not authenticate a human from a name or claim. Injected synthetic transports
    are operator configuration, never portable task permissions.
    """
    def __init__(self, state_dir=None):
        self._store = Store(state_dir or default_state_dir())
        self._workflow = Workflow(self._store)

    def close(self):
        self._store.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def register_repository(self, path, workspace_root=None):
        return self._workflow.register_repository(path, workspace_root)

    def register_profile(self, profile):
        return self._workflow.register_profile(profile)

    def configure_muse(self, configuration):
        """Register production intent only; never qualify or launch Muse."""
        from .muse_production import configure
        return configure(self._store, configuration)

    def muse_readiness(self, profile_id, configuration_digest):
        from .muse_production import readiness
        return readiness(self._store, profile_id, configuration_digest)

    def prepare_muse(self, spec, *, inputs):
        """Retain measured production inputs without granting runtime authority."""
        from .muse_preparation import prepare
        return prepare(self._store, spec, inputs=inputs)

    def muse_preparation(self, preparation_digest):
        from .muse_preparation import observe
        return observe(self._store, preparation_digest)

    def configure_muse_driver(self, configuration):
        from .muse_lifecycle import configure
        return configure(self._store, configuration)

    def configure_muse_capture(self, configuration):
        """Trusted original synthetic Muse registration, not a live capability grant."""
        from .muse_handoff import configure
        return configure(self._store, configuration)

    def configure_execution(self, **configuration):
        """Trusted operator fixture registration; task/worker JSON cannot call it."""
        from .admission import configure_execution
        return configure_execution(self._store, **configuration)

    def register_trial_document(self, document, *, operation_key):
        """Trusted offline history only; no registration can enable E1 dispatch."""
        from .trial_control import register_trial_document
        return register_trial_document(self._store, document, operation_key=operation_key)

    def configure_review(self, config_path, *, fixture_response=None, executable=None, python_executable=None):
        return self._workflow.configure_review(config_path, fixture_response=fixture_response, executable=executable, python_executable=python_executable)

    def configure_command_sandbox(self, executable_path):
        return self._workflow.configure_command_sandbox(executable_path)

    def configure_publication(self, gh_path, git_remote, *, qualification="synthetic"):
        return self._workflow.configure_publication(gh_path, git_remote, qualification=qualification)

    def authorize(self, run_id, *, decision_digest, scope, qualification=None):
        return self._workflow.authorize(run_id, decision_digest=decision_digest, scope=scope, qualification=qualification)

    def submit(self, spec, *, operation_key):
        return self._workflow.submit(spec, operation_key=operation_key)

    def validate_task(self, spec):
        return self._workflow.validate_task(spec)

    def advance(self, run_id, *, expected_step_id, predecessor_digest, operation_key, expected_revision):
        return self._workflow.start(run_id, mode="advance", expected_step_id=expected_step_id,
            predecessor_digest=predecessor_digest, operation_key=operation_key, expected_revision=expected_revision)

    def retry(self, run_id, *, expected_step_id, operation_key, expected_revision):
        return self._workflow.start(run_id, mode="retry", expected_step_id=expected_step_id,
            operation_key=operation_key, expected_revision=expected_revision)

    def start(self, run_id, *, operation_key, expected_revision, authority_id=None):
        return self._workflow.start(run_id, operation_key=operation_key, expected_revision=expected_revision, authority_id=authority_id)

    def inspect(self, run_id):
        run = self._store.run(run_id)
        if run["schema_version"] in {"2.7", "2.10"}:
            from .steps import view
            summary = view(self._store, run)
            return run | {"next_actions":summary["next_actions"], "stop_reason":summary["stop_reason"]}
        return run

    def capabilities(self, run_id, *, mode="start"):
        """Current read-only scoped assessment, never dispatch authorization."""
        if type(mode) is not str or mode not in {"start", "restart", "native_resume", "observe", "cancel", "result"}:
            raise TaskAlongError("execution_mode_unsupported", "Select an explicit supported observation mode.")
        run = self._store.run(run_id)
        spec = self._store.spec(run)
        if spec["schema_version"] == "2.12":
            from .muse_lifecycle import capabilities_view
            return capabilities_view(self._store, run, spec, mode)
        if spec["schema_version"] == "2.9":
            from .muse_handoff import capabilities_view
            return capabilities_view(self._store, run, spec, mode)
        binding, satisfied, decision, reasons = None, None, None, ["v1_runtime_unqualified"]
        if spec["schema_version"] in {"2.2", "2.3", "2.4", "2.5", "2.6"}:
            binding = spec["execution"]["binding_digest"]
            try:
                if mode not in {"start", "restart"}:
                    raise TaskAlongError("execution_mode_unsupported", "This projection has no qualification for the selected mode.")
                from .admission import resolve
                snapshot, _, _ = resolve(self._store, spec, mode=mode)
                satisfied, decision, reasons = True, snapshot["decision"]["digest"], []
            except TaskAlongError as exc:
                satisfied, reasons = False, [exc.code]
        return seal_versioned("capabilities-view", {"run_id": run_id, "revision": run["revision"], "mode": mode,
            "binding_digest": binding, "requirements_satisfied": satisfied, "decision_digest": decision,
            "reason_codes": reasons, "production_dispatch_allowed": False}, version="2.2")

    def result(self, run_id):
        """Read persisted outcomes/immutable references; never reconcile or launch.

        A completed worker remains distinct from independent acceptance. Raw
        task/policy bodies, runtime paths, credentials and logs are excluded.
        """
        run = self._store.run(run_id)
        if run["schema_version"] in {"2.7", "2.10"}:
            from .steps import view
            return view(self._store, run)
        if self._store.spec(run)["schema_version"] == "2.12":
            from .muse_lifecycle import result_view
            return result_view(self._store, run)
        if self._store.spec(run)["schema_version"] == "2.9":
            from .muse_handoff import result_view
            return result_view(self._store, run)
        attempt = self._store.detail("attempts", run["attempts"][-1]["attempt_id"]) if run["attempts"] else None
        from .executors.observed_capture import validate_completed_run
        validate_completed_run(self._store, run)
        acceptance = self._store.detail("acceptances", run["acceptance_id"]) if run["acceptance_id"] else None
        if acceptance is not None:
            acceptance = validate("acceptance", acceptance)
            if (acceptance["run_id"] != run_id or acceptance["spec_digest"] != run["spec_digest"]
                    or acceptance["candidate"] != run["candidate"] or acceptance["qualification"] != run["qualification"]):
                raise TaskAlongError("store_integrity", "The stored acceptance belongs to different immutable inputs.", exit_code=70)
        accepted = bool(acceptance and acceptance["decision"] == "accepted" and run["state"] in {"accepted", "publishing", "draft_published"})
        if run["state"] == "cancelled":
            outcome = "cancelled"
        elif accepted:
            outcome = "accepted"
        elif run["active_attempt_id"] or run["pending_effect_ids"]:
            outcome = "unknown" if run["state"] == "blocked" else "pending"
        elif attempt and attempt["status"] == "completed" and attempt.get("termination_confirmed"):
            outcome = "worker_completed"
        elif run["state"] == "failed":
            outcome = "failed"
        elif run["state"] == "blocked":
            outcome = "unknown"
        else:
            outcome = "pending"
        artifacts = []
        for evidence_id in run["evidence_ids"]:
            record = self._store.detail("evidence", evidence_id)
            artifacts.extend(record["artifacts"])
        if attempt:
            artifacts.extend(attempt.get("canonical_evidence_refs", []))
            if attempt.get("result_artifact"):
                artifacts.append(attempt["result_artifact"])
        unique = {item["sha256"]:item for item in artifacts}
        for key in unique:
            self._store.get_blob(key)
        packet_digest = None
        if attempt and attempt.get("canonical_packet"):
            version = attempt["canonical_packet"].get("schema_version")
            if version not in {"2.2", "2.3", "2.4", "2.5", "2.6"}:
                raise TaskAlongError("store_integrity", "The stored packet version is unsupported.", exit_code=70)
            packet = validate_versioned("worker-packet", attempt["canonical_packet"], expected_version=version)
            mapping = validate_versioned("packet-projection", attempt["packet_projection"], expected_version=version)
            if mapping["canonical_packet_digest"] != packet["digest"] or mapping["wire_packet_digest"] != attempt["packet"]["digest"]:
                raise TaskAlongError("store_integrity", "The stored canonical/wire packet identities disagree.", exit_code=70)
            if version in {"2.3", "2.4"}:
                spec = self._store.spec(run)
                if spec["schema_version"] != version:
                    raise TaskAlongError("store_integrity", "The stored driver packet belongs to another task format.", exit_code=70)
                wire = validate_versioned("worker-packet", attempt["packet"], expected_version=version)
                dispatch = attempt["dispatch_admission"]
                expected = {"driver_config_digest":spec["execution"]["driver_config_digest"],
                            "provider_profile_digest":dispatch["provider"]["digest"]}
                if (digest(dispatch) != dispatch["digest"]
                        or packet["admission_digest"] != dispatch["digest"]
                        or mapping["projection_digest"] != dispatch["projection"]["digest"]
                        or packet["binding_digest"] != spec["execution"]["binding_digest"]
                        or packet["spec_digest"] != run["spec_digest"] or packet["run_id"] != run_id
                        or packet["attempt_id"] != attempt["attempt_id"] or packet["session_id"] != attempt["attempt_id"]
                        or canonical_bytes(packet) != canonical_bytes(wire)
                        or any(packet["bindings"][key] != value or mapping[key] != value for key,value in expected.items())
                        or mapping["session_id"] != packet["session_id"]
                        or any(mapping[key] != packet[key] for key in ("run_id","attempt_id","spec_digest","admission_digest"))):
                    raise TaskAlongError("store_integrity", "The stored driver packet/context identities disagree.", exit_code=70)
            packet_digest = packet["digest"]
        return seal_versioned("result-view", {"run_id":run_id, "revision":run["revision"], "state":run["state"],
            "outcome":outcome, "independently_accepted":accepted, "acceptance_digest":digest(acceptance) if acceptance else None,
            "worker_result_digest":attempt["result_artifact"]["sha256"] if attempt and attempt.get("result_artifact") else None,
            "canonical_packet_digest":packet_digest, "evidence_artifacts": [unique[key] for key in sorted(unique)],
            "production_dispatch_allowed":False}, version="2.2")

    def events(self, run_id, *, after_seq=0, limit=1000):
        return self._store.events(run_id, after_seq, limit)

    def cancel(self, run_id, *, operation_key, expected_revision):
        return self._workflow.cancel(run_id, operation_key=operation_key, expected_revision=expected_revision)

    def retire_workspace(self, run_id, *, operation_key, expected_revision):
        return self._workflow.retire_workspace(run_id, operation_key=operation_key, expected_revision=expected_revision)

    def reconcile(self, run_id, *, operation_key, expected_revision):
        return self._workflow.reconcile(run_id, operation_key=operation_key, expected_revision=expected_revision)

    def resume(self, run_id, *, mode, operation_key, expected_revision, authority_id=None):
        return self._workflow.start(run_id, operation_key=operation_key, expected_revision=expected_revision, authority_id=authority_id, mode=mode)

    def verify(self, run_id, *, operation_key, expected_revision):
        return self._workflow.verify(run_id, operation_key=operation_key, expected_revision=expected_revision)

    def publish_intent(self, run_id):
        return self._workflow.publish_intent(run_id)

    def publish(self, run_id, *, intent_digest, operation_key, expected_revision):
        return self._workflow.publish(run_id, intent_digest=intent_digest, operation_key=operation_key, expected_revision=expected_revision)

    def export(self, run_id, *, output):
        run = self._store.run(run_id)
        # Never include private spec/task prose, profiles, sessions, process identities,
        # authority details, blob bytes, configured paths or command output.
        evidence = [self._store.detail("evidence", eid) for eid in run["evidence_ids"]]
        for record in evidence:
            for artifact in record["artifacts"]:
                self._store.get_blob(artifact["sha256"])
        events, cursor = [], 0
        while True:
            page = self._store.events(run_id, cursor)
            events.extend(page)
            if len(page) < 1000:
                break
            cursor = page[-1]["seq"]
        manifest = {"kind": "run_export", "schema_version": "1.0", "run": run, "events": events,
                    "evidence": [{key: record[key] for key in ("evidence_id", "type", "subject", "inputs", "result", "artifacts", "qualification")} for record in evidence], "raw_content_included": False}
        target = Path(output).absolute()
        for part in [target, *target.parents]:
            if part.is_symlink():
                raise TaskAlongError("unsafe_export_path", "Export cannot traverse symbolic links.", exit_code=3)
        if target.exists():
            raise TaskAlongError("export_exists", "Export destination must be new.")
        target.mkdir(mode=0o700, parents=True)
        destination = target / "manifest.json"
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical_bytes(manifest))
        return {"run_id": run_id, "raw_content_included": False, "file": "manifest.json"}

    def doctor(self, *, profile_id=None, workspace=None, git_common_dir=None):
        from .executors.registry import default_runtime_requirements, executor_for
        if profile_id is None:
            return {**default_runtime_requirements(), "package_version": "0.1.0a1",
                    "tools": {name: bool(shutil.which(name)) for name in ("git", "codex", "gh", "review-sensei")},
                    "production_dispatch_qualified": False, "live_inference": False,
                    "diagnostic_scope": "Tool presence and static unmet requirements only; no runtime or provider was invoked."}
        profile = self._store.profile(profile_id)
        if workspace is None or git_common_dir is None:
            raise TaskAlongError("doctor_workspace_required", "Model-free probes require an explicit disposable workspace and Git control path.")
        return executor_for(profile).doctor(workspace=workspace, control_dir=self._store.root, git_common_dir=git_common_dir)
