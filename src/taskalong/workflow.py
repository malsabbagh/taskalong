"""One bounded development workflow, independent of provider routing."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import time

from .errors import TaskAlongError
from .executors.registry import capture_for_version
from .store import Store, encode, identifier, now
from .validation import canonical_bytes, digest, load_json, seal, validate, validate_versioned, screen_sensitive
from .workspace import WorkspaceManager, inspect_repository, repository_guard

EFFECTS = {"execute", "verify", "commit_candidate", "push_branch", "create_draft_pr"}
TERMINAL = {"cancelled", "failed", "draft_published"}


def _worker_identity_key(spec):
    return "driver_config_digest" if spec["schema_version"] in {"2.3", "2.4", "2.5", "2.6", "2.9"} else "profile_digest"


def _internal_key(prefix, value):
    return prefix + ":" + hashlib.sha256(value.encode()).hexdigest()


def _effect(db, run, kind, operation_key, request):
    effect = {"effect_id": identifier(), "run_id": run["run_id"], "kind": kind, "operation_key": operation_key, "request_digest": digest(request), "request": request, "phase": "prepared", "response": None}
    db.execute("INSERT INTO effects VALUES (?,?,?,?,?,?,?)", (effect["effect_id"], run["run_id"], operation_key, kind, effect["request_digest"], "prepared", encode(effect)))
    run["pending_effect_ids"].append(effect["effect_id"])
    return effect


def _observe_effect(store, run_id, effect_id, response, *, phase="observed"):
    def change(run, db):
        effect = store.detail("effects", effect_id)
        effect.update(phase=phase, response=response)
        db.execute("UPDATE effects SET phase=?,document=? WHERE effect_id=?", (phase, encode(effect), effect_id))
        if phase == "observed":
            run["pending_effect_ids"] = [v for v in run["pending_effect_ids"] if v != effect_id]
    return store.mutate(run_id, "effect." + phase, effect_id, None, {"effect_id": effect_id, "response": response}, change, events=[("effect." + phase, {"effect_id": effect_id})])


class _TerminalRunObserved(Exception):
    """Roll back a stale internal blocker without emitting a terminal event."""


def _block(store, run_id, code, *, phase=None, uncertain=False, effect_outcome=None):
    outcome = "uncertain" if uncertain else effect_outcome or "not_sent"
    if outcome not in {"not_sent", "known", "uncertain"}:
        raise ValueError("Invalid internal effect outcome")
    current = store.run(run_id)
    if current["state"] in TERMINAL:
        return current
    def change(run, db):
        if run["state"] in TERMINAL:
            raise _TerminalRunObserved
        run["blocked_from"] = phase or (run["blocked_from"] if run["state"] == "blocked" else run["state"])
        run["state"] = "blocked"
        run["acceptance_id"] = None if run.get("acceptance_id") and phase != "publishing" else run.get("acceptance_id")
        run["blockers"] = [{"code": code, "message": "This boundary requires explicit reconciliation.", "recovery": [{"action": "inspect_and_reconcile"}], "effect_outcome": outcome}]
    try:
        return store.mutate(run_id, "block", identifier(), None, {"code": code, "phase": phase, "uncertain": uncertain, "effect_outcome": outcome}, change, events=[("run.blocked", {"code": code, "effect_outcome": outcome})])
    except _TerminalRunObserved:
        return store.run(run_id)


class Workflow:
    def __init__(self, store: Store):
        self.store = store

    def _refuse_trial_run(self, run_id):
        # Read the immutable subject before even idempotency replay or a guard
        # file can route a manually inserted E1 run through old fixture logic.
        if self.store.spec(self.store.run(run_id))["schema_version"] == "2.8":
            raise TaskAlongError("trial_runtime_unqualified", "The E1 trial runtime is not qualified or enabled.", exit_code=3)

    def register_repository(self, path, workspace_root=None):
        info = inspect_repository(path)
        root = Path(workspace_root).absolute() if workspace_root else Path(info["path"]).parent / ".taskalong-workspaces" / hashlib.sha256(info["identity"].encode()).hexdigest()[:16]
        for protected in (Path(info["path"]), self.store.root):
            if root == protected or protected in root.parents or root in protected.parents:
                raise TaskAlongError("unsafe_workspace_root", "Workspace storage must be separate from primary and control storage.", exit_code=3)
        with repository_guard(info["common_dir"], self.store.store_uuid):
            return self.store.register_repository({**info, "registration_id": identifier(), "store_uuid": self.store.store_uuid, "workspace_root": str(root)})

    def register_profile(self, profile):
        profile = seal("runtime-profile", profile)
        return self.store.register_profile(profile)

    def configure_review(self, config_path, *, fixture_response=None, executable=None, python_executable=None):
        import shutil
        selected = executable or shutil.which("review-sensei")
        config_path = Path(config_path).absolute()
        if not config_path.is_file() or config_path.is_symlink():
            raise TaskAlongError("review_config_missing", "Review config must be an existing operator-selected file.", exit_code=3)
        if not selected or not Path(selected).is_file() or not os.access(selected, os.X_OK):
            raise TaskAlongError("review_executable_missing", "The independent reviewer executable is unavailable; activate its environment or select its executable explicitly.",
                               exit_code=3, recovery=[{"action": "select_installed_reviewer", "option": "--executable", "expected_version": "0.8.8"}])
        executable = str(Path(selected).absolute())
        setting = {"config_path": str(config_path), "config_digest": hashlib.sha256(config_path.read_bytes()).hexdigest(), "fixture_response": str(Path(fixture_response).absolute()) if fixture_response else None, "executable": executable, "executable_sha256": hashlib.sha256(Path(executable).read_bytes()).hexdigest(), "python_executable": python_executable or str(Path(executable).parent / "python")}
        self.store.set_setting("review", setting)
        return {"config_digest": setting["config_digest"], "fixture": bool(fixture_response)}

    def configure_command_sandbox(self, executable_path):
        path = Path(executable_path).absolute()
        if not path.is_file() or path.is_symlink():
            raise TaskAlongError("sandbox_missing", "Synthetic command launcher must be an existing executable.", exit_code=3)
        setting = {"qualification": "synthetic", "executable": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        self.store.set_setting("command_sandbox", setting)
        return {"qualification": "synthetic", "sha256": setting["sha256"]}

    def configure_publication(self, gh_path, git_remote, *, qualification="synthetic"):
        if qualification != "synthetic":
            raise TaskAlongError("publication_configuration_unsupported", "Production publication requires a separately qualified repository transport.", exit_code=3)
        path = Path(gh_path).absolute()
        remote = Path(git_remote).absolute()
        if not path.is_file() or not remote.is_dir():
            raise TaskAlongError("transport_missing", "Synthetic publication needs an external fake executable and local bare remote.", exit_code=3)
        value = {"qualification": qualification, "gh_path": str(path), "gh_sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "git_remote": str(remote)}
        self.store.set_setting("publication_transport", value)
        return {"qualification": qualification}

    def validate_task(self, spec):
        return self.submit(spec, operation_key=None, _validate_only=True)

    def submit(self, spec, *, operation_key, _validate_only=False):
        if type(spec) is not dict:
            raise TaskAlongError("invalid_document", "A task specification must be a JSON object.")
        screen_sensitive(spec)
        if spec.get("schema_version") == "2.8":
            from .trial import TrialTaskSpec
            TrialTaskSpec.from_dict(spec)
            raise TaskAlongError("trial_runtime_unqualified", "The E1 trial runtime is not qualified or enabled.", exit_code=3)
        # Select only the newly supported version explicitly. All other input
        # retains the original v1 CLI admission/error boundary.
        if spec.get("schema_version") == "2.7":
            from .steps import OrderedTaskSpec, preflight
            spec = OrderedTaskSpec.from_dict(spec).to_dict()
            if not _validate_only:
                prior = self.store.operation("submit", "", operation_key, spec)
                if prior is not None:
                    return prior
            if self.store.format_version < 10:
                raise TaskAlongError("store_upgrade_required", "Ordered tasks require explicit format-10 maintenance.", exit_code=3)
            preflight(self, spec)
        elif spec.get("schema_version") not in ("2.2", "2.3", "2.4", "2.5", "2.6", "2.9"):
            spec = seal("task-spec", spec)
        else:
            from .execution import read_task_spec
            spec = read_task_spec(spec).to_dict()
            if not _validate_only:
                prior = self.store.operation("submit", "", operation_key, spec)
                if prior is not None:
                    return prior
            from .admission import resolve
            resolve(self.store, spec)
        repository = self.store.repository(spec["repository"]["registration_id"])
        info = inspect_repository(repository["path"])
        if info["identity"] != repository["identity"]:
            raise TaskAlongError("repository_identity_changed", "Registered Git identity has changed.", exit_code=3)
        profile = self._profile(spec)
        destination = profile.get("inference_destination_id")
        if spec["schema_version"] in {"2.3", "2.4", "2.5", "2.6"}:
            from .admission import worker_contract
            _, provider = worker_contract(self.store, spec, profile)
            destination = provider["profile_id"]
        if profile["qualification"] != spec["qualification"] or destination != spec["permissions"]["inference_destination_id"]:
            raise TaskAlongError("runtime_profile_mismatch", "The task must bind the exact registered profile and inference destination.", exit_code=3)
        # Resolve/validate only an existing commit; no fetch and no ref-dependent authority.
        from .workspace import git
        resolved = git(repository["path"], "rev-parse", "--verify", spec["repository"]["base_commit"] + "^{commit}").strip()
        if isinstance(resolved, bytes):
            resolved = resolved.decode()
        if resolved != spec["repository"]["base_commit"]:
            raise TaskAlongError("base_commit_mismatch", "Task base must be a full existing SHA-1 commit.")
        if _validate_only:
            return {"valid": True, "spec_digest": spec["digest"], "schema_version": spec["schema_version"], "step_count": len(spec.get("steps", []))}
        return self.store.create_run(spec, operation_key)

    def authorize(self, run_id, *, decision_digest, scope, qualification=None):
        self._refuse_trial_run(run_id)
        run = self.store.run(run_id)
        spec = self.store.spec(run)
        scope = sorted(set(scope))
        if not scope or not set(scope) <= EFFECTS or not set(scope) <= set(spec["permissions"]["allowed_effects"]):
            raise TaskAlongError("authority_scope_invalid", "Authority scope must fit the immutable task's effect limits.", exit_code=3)
        if qualification is not None and qualification != run["qualification"]:
            raise TaskAlongError("authority_qualification_mismatch", "Synthetic and production authority cannot be exchanged.", exit_code=3)
        if set(scope) & {"execute", "verify", "commit_candidate"} and decision_digest != spec["digest"]:
            raise TaskAlongError("authority_intent_mismatch", "Execution authority must bind the exact submitted task digest.", exit_code=3)
        expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(timespec="seconds").replace("+00:00", "Z")
        record = seal("authority", {"authority_id": identifier(), "run_id": run_id, "source": "local_operator", "principal": str(os.getuid()), "decision": "authorized", "scope": scope, "intent_digest": decision_digest, "issued_at": now(), "expires_at": expiry, "human_decision_observed": False, "qualification": run["qualification"]})
        return self.store.add_authority(run_id, record)

    def _manager(self, run):
        repository = self.store.repository(run["repository_registration_id"])
        return WorkspaceManager(repository["path"], self.store.store_uuid)

    def _profile(self, spec):
        if spec["schema_version"] == "2.9":
            from .muse_handoff import configuration
            return configuration(self.store, spec["execution"]["driver_config_digest"])
        if spec["schema_version"] in {"2.3", "2.4", "2.5", "2.6"}:
            from .admission import registered_driver_config
            return registered_driver_config(self.store, spec["execution"]["binding_digest"])[0]
        if spec["schema_version"] == "2.2":
            from .admission import registered_profile
            return registered_profile(self.store, spec["execution"]["binding_digest"])[0]
        profile = self.store.profile(spec["execution"]["profile_id"])
        if profile["digest"] != spec["execution"]["profile_digest"]:
            raise TaskAlongError("runtime_profile_mismatch", "Runtime policy changed after submission.", exit_code=3)
        return profile

    def _executor(self, spec, configuration):
        from .admission import worker_contract
        contract, provider = worker_contract(self.store, spec, configuration)
        return contract.factory(configuration, provider)

    def retire_workspace(self, run_id, *, operation_key, expected_revision):
        """Explicitly release repository exclusivity after a terminal run.

        All retained data remains owned by its original run. The OS operator's
        invocation authorizes this local control-plane change, not cleanup,
        workspace reuse, process signaling or another execution.
        """
        self._refuse_trial_run(run_id)
        prior = self.store.operation("retire-workspace", run_id, operation_key, {})
        if prior:
            return prior
        run = self.store.run(run_id)
        if type(expected_revision) is not int or run["revision"] != expected_revision:
            raise TaskAlongError("revision_conflict", "Inspect the terminal run before retiring its workspace.", exit_code=4)
        if run["state"] not in TERMINAL | {"accepted"}:
            raise TaskAlongError("retirement_not_terminal", "Only a completed or accepted quiescent run can retire its workspace.", exit_code=3)
        from contextlib import ExitStack
        from ._supervisor import run_guard
        with ExitStack() as guards:
            for purpose in ("dispatch", "verify", "publish"):
                guards.enter_context(self.store.guard(run_id, purpose))
            guards.enter_context(run_guard(self.store.root, run_id))
            # A duplicate that committed while we acquired guards returns the
            # original receipt before inspecting the now-revoked fence.
            prior = self.store.operation("retire-workspace", run_id, operation_key, {})
            if prior:
                return prior
            run = self.store.run(run_id)
            self.store.require_fence(run, run["lease_generation"])
            lease = self.store.lease(run)
            manager = self._manager(run)
            if run["state"] == "accepted":
                if run["candidate"] is None:
                    raise TaskAlongError("candidate_missing", "Accepted workspace retirement requires its exact preserved candidate.", exit_code=3)
                manager.assert_candidate(lease["workspace"], run["candidate"], self.store.spec(run)["scope"])
            subject = manager.retirement_subject(lease["workspace"], run["lease_generation"])
            return self.store.retire_lease(run_id, operation_key=operation_key,
                                          expected_revision=expected_revision, workspace_subject=subject)

    def start(self, run_id, *, operation_key, expected_revision, authority_id=None, mode="start", expected_step_id=None, predecessor_digest=None):
        self._refuse_trial_run(run_id)
        with self.store.guard(run_id, "dispatch"):
            return self._start(run_id, operation_key=operation_key, expected_revision=expected_revision, authority_id=authority_id, mode=mode, expected_step_id=expected_step_id, predecessor_digest=predecessor_digest)

    def _start(self, run_id, *, operation_key, expected_revision, authority_id=None, mode="start", expected_step_id=None, predecessor_digest=None):
        command = mode if mode in {"advance", "retry"} else "start" if mode == "start" else "resume"
        request = {"mode": mode, "authority_id": authority_id}
        if mode in {"advance", "retry"}:
            request.update(expected_step_id=expected_step_id, predecessor_digest=predecessor_digest)
        prior = self.store.operation(command, run_id, operation_key, request)
        if prior:
            return prior
        run = self.store.run(run_id)
        if run["revision"] != expected_revision:
            raise TaskAlongError("revision_conflict", "Inspect the current revision before starting.", exit_code=4)
        spec = self.store.spec(run)
        if spec["schema_version"] == "2.7":
            from .steps import preflight
            preflight(self, spec)
        authority = self.store.authority(run, {"execute", "verify", "commit_candidate"}, spec["digest"], authority_id)
        admission = None
        if spec["schema_version"] in {"2.2", "2.3", "2.4", "2.5", "2.6", "2.9"}:
            from .admission import resolve
            admission, _, _ = resolve(self.store, spec, mode=mode, authority_id=authority["authority_id"])
        if not spec["permissions"]["local_edit"] or not spec["permissions"]["local_commit"] or not {"execute", "verify", "commit_candidate"} <= set(spec["permissions"]["allowed_effects"]):
            raise TaskAlongError("task_effect_forbidden", "This task does not permit the required local effects.", exit_code=3)
        from .executors.registry import executor_for
        profile = self._profile(spec)
        executor = self._executor(spec, profile)
        executor.preflight(qualification=run["qualification"], budget=spec["budget"])
        if mode == "start" and run["state"] != "created":
            raise TaskAlongError("invalid_run_state", "Start requires a newly created run; reconcile interrupted work explicitly.", exit_code=3)
        ordered = spec["schema_version"] == "2.7"
        target_index = run.get("current_step_index", 0)
        if ordered:
            from .steps import validate_chain, inputs
            validate_chain(self.store, run, live=bool(run["attempts"]))
            if mode not in {"start", "advance", "retry"}:
                raise TaskAlongError("ordered_mode_unsupported", "Use explicit advance or retry for ordered tasks.", exit_code=3)
            if mode != "start":
                if run["active_attempt_id"] or run["pending_effect_ids"] or run["candidate"] or run["state"] not in {"ready", "blocked"}:
                    raise TaskAlongError("step_not_settled", "Continuation requires settled worker effects and an exact checkpoint.", exit_code=3)
                last = self.store.detail("attempts", run["attempts"][-1]["attempt_id"])
                if not last.get("termination_confirmed"):
                    raise TaskAlongError("cancellation_unconfirmed", "Previous cessation remains uncertain.", exit_code=5)
                if mode == "advance":
                    if run["steps"][target_index]["status"] != "completed" or target_index+1 >= len(spec["steps"]):
                        raise TaskAlongError("advance_not_ready", "Advance requires a completed predecessor and a pending next step.", exit_code=3)
                    if predecessor_digest != run["steps"][target_index]["receipt_digest"]:
                        raise TaskAlongError("predecessor_changed", "Advance must name the exact completed predecessor receipt.", exit_code=3)
                    target_index += 1
                elif run["steps"][target_index]["status"] != "failed":
                    raise TaskAlongError("retry_not_ready", "Retry requires the current safely settled failed step.", exit_code=3)
                if expected_step_id != spec["steps"][target_index]["step_id"]:
                    raise TaskAlongError("step_identity_mismatch", "The requested step is not the valid next ordered step.", exit_code=3)
                inputs(spec, self.store.lease(run)["workspace"]["path"], target_index)
        if mode != "start" and not ordered:
            if mode not in {"native", "restart"} or run["state"] != "blocked" or run["active_attempt_id"] is not None or run["pending_effect_ids"]:
                raise TaskAlongError("resume_not_reconciled", "Resume needs a stopped, reconciled nonterminal run and an explicit mode.", exit_code=3)
            last = self.store.detail("attempts", run["attempts"][-1]["attempt_id"])
            if not last.get("termination_confirmed"):
                raise TaskAlongError("cancellation_unconfirmed", "Previous worker cessation is not confirmed; workspace remains quarantined.", exit_code=5, effect_outcome="uncertain")
            if mode == "native" and not last.get("thread_id"):
                raise TaskAlongError("native_resume_unavailable", "No observed exact runtime thread can be resumed.", exit_code=3)
            if run["candidate"]:
                raise TaskAlongError("resume_candidate_unsupported", "A frozen candidate requires verification, not another worker attempt.", exit_code=3)
            if spec["schema_version"] in {"2.5", "2.6"} and last["status"] == "completed":
                from .executors.observed_capture import validate_handoff
                validate_handoff(self.store, run, spec, last)
            checkpoint = last.get("checkpoint") or {}
            current_workspace = self.store.lease(run)["workspace"]
            snapshot = self._manager(run).snapshot(current_workspace, spec["scope"], expected_head=spec["repository"]["base_commit"])
            if (checkpoint.get("content_digest") != snapshot["content_digest"] or checkpoint.get("spec_digest") != spec["digest"] or checkpoint.get(_worker_identity_key(spec)) != profile["digest"]):
                raise TaskAlongError("checkpoint_stale", "The stopped checkpoint no longer matches workspace, task and runtime policy.", exit_code=3)
        budget = spec["budget"]
        used = run["budget_consumed"]
        if used["attempts"] >= budget["max_attempts"] or used["active_seconds"] + budget["attempt_seconds"] > budget["total_active_seconds"] or budget["max_output_bytes"] - used["output_bytes"] < 1024:
            raise TaskAlongError("budget_exhausted", "Persisted execution budget cannot fund another bounded attempt.", exit_code=3)
        registration = self.store.repository(run["repository_registration_id"])
        manager = self._manager(run)
        generation = self.store.next_lease_generation(run)
        if mode == "start":
            workspace_intent = manager.prepare(run_id, Path(registration["workspace_root"]) / run_id, spec["repository"]["base_commit"], generation=generation)
        else:
            workspace_intent = self.store.lease(run)["workspace"]
        attempt_id = identifier()
        attempt = {"attempt_id": attempt_id, "run_id": run_id, "ordinal": len(run["attempts"]) + 1, "mode": "start" if mode == "start" else ("native_resume" if mode == "native" else "restart"), "lease_generation": generation, "status": "prepared", "spawn_phase": "not_dispatched", "process_receipt": None, "created_at": now(), "deadline": (datetime.now(timezone.utc) + timedelta(seconds=budget["attempt_seconds"])).isoformat(timespec="seconds").replace("+00:00", "Z"), "thread_id": last.get("thread_id") if mode == "native" else None, "termination_confirmed": False, "packet": None, "workspace": workspace_intent}
        attempt[_worker_identity_key(spec)] = profile["digest"]
        if ordered:
            attempt.update(step_index=target_index, step_id=spec["steps"][target_index]["step_id"])
        def prepare(current, db):
            if current["state"] in TERMINAL:
                raise TaskAlongError("terminal_run", "Terminal runs require a separately authorized successor.", exit_code=3)
            if current["state"] == "cancel_pending":
                raise TaskAlongError("cancel_pending", "Cancellation prevents a new attempt.", exit_code=6)
            if admission is not None:
                # Resolve again inside the same SQLite transaction that owns the
                # lease, reservation, immutable snapshots and effect intent.
                self.store.authority(current, {"execute", "verify", "commit_candidate"}, spec["digest"], authority["authority_id"])
                fresh, _, _ = resolve(self.store, spec, mode=mode, authority_id=authority["authority_id"])
                attempt["admission"] = fresh
            if ordered:
                from .steps import reserve
                current["current_step_index"] = target_index
                attempt["reservation"] = reserve(current, spec, reservation_id=identifier(), kind="worker", owner_id=attempt_id)
                step = current["steps"][target_index]
                step["status"] = "running"
                step["attempt_ids"].append(attempt_id)
            self.store.acquire_lease(db, current, workspace_intent)
            current["state"] = "ready"
            current["blocked_from"] = None
            current["blockers"] = []
            current["active_attempt_id"] = attempt_id
            current["attempts"].append({"attempt_id": attempt_id, "ordinal": attempt["ordinal"], "mode": attempt["mode"], "status": "prepared"})
            # Reserve the full deadline before dispatch; loss cannot refund unobserved work.
            current["budget_consumed"]["attempts"] += 1
            current["budget_consumed"]["active_seconds"] += budget["attempt_seconds"]
            db.execute("INSERT INTO attempts VALUES (?,?,?,?,?)", (attempt_id, run_id, attempt["ordinal"], 1, encode(attempt)))
            effect = _effect(db, current, "workspace.create" if mode == "start" else "workspace.reacquire", operation_key, workspace_intent)
            attempt["workspace_effect_id"] = effect["effect_id"]
            db.execute("UPDATE attempts SET document=? WHERE attempt_id=?", (encode(attempt), attempt_id))
        prepared = self.store.mutate(run_id, command, operation_key, expected_revision, request, prepare, events=[("run.ready", {}), ("attempt.prepared" if mode == "start" else "attempt.resumed", {"attempt_id": attempt_id})])
        try:
            workspace = manager.create(workspace_intent) if mode == "start" else manager.advance_generation(workspace_intent, generation - 1, generation)
            self._workspace_ready(prepared, attempt, workspace)
            self._launch_supervisor(run_id, attempt_id)
        except TaskAlongError as exc:
            _block(self.store, run_id, exc.code, phase="ready", uncertain=exc.effect_outcome == "uncertain")
            raise
        return prepared if admission is not None or ordered else self.store.run(run_id)

    def _workspace_ready(self, run, attempt, workspace):
        def change(current, db):
            lease = self.store.lease(current)
            lease["workspace"] = workspace
            db.execute("UPDATE leases SET document=? WHERE repository_id=?", (encode(lease), current["repository_registration_id"]))
            item = self.store.detail("attempts", attempt["attempt_id"])
            item["workspace"] = workspace
            db.execute("UPDATE attempts SET document=? WHERE attempt_id=?", (encode(item), item["attempt_id"]))
        self.store.mutate(run["run_id"], "workspace.ready", attempt["attempt_id"], None, {"workspace_id": workspace["workspace_id"]}, change, events=[("effect.observed", {"effect_id": attempt["workspace_effect_id"]})], fence=run["lease_generation"])
        _observe_effect(self.store, run["run_id"], attempt["workspace_effect_id"], {"workspace_id": workspace["workspace_id"]})

    def _launch_supervisor(self, run_id, attempt_id):
        # Persist the uncertain outer launch window before Popen. A duplicate start never spawns.
        item = self.store.detail("attempts", attempt_id)
        ordinal = item.get("supervisor_launch_tries", 0) + 1
        if ordinal > 2:
            raise TaskAlongError("supervisor_retry_exhausted", "Repeated pre-dispatch supervisor failures require a new operator plan.", exit_code=3)
        dispatch_key = attempt_id + ":" + str(ordinal)
        def change(run, db):
            item = self.store.detail("attempts", attempt_id)
            item["supervisor_launch"] = "dispatching"
            item["supervisor_launch_tries"] = ordinal
            db.execute("UPDATE attempts SET document=? WHERE attempt_id=?", (encode(item), attempt_id))
        self.store.mutate(run_id, "supervisor.prepare", dispatch_key, None, {"attempt_id": attempt_id, "dispatch_ordinal": ordinal}, change, events=[("effect.prepared", {"kind": "supervisor.launch"})])
        environment = {k: v for k, v in os.environ.items() if k in {"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT", "PYTHONPATH", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM"}}
        try:
            process = subprocess.Popen([sys.executable, "-m", "taskalong._supervisor", "--state-dir", str(self.store.root), "--run-id", run_id, "--attempt-id", attempt_id], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=self.store.root, env=environment, start_new_session=True, close_fds=True)
        except OSError as exc:
            def not_sent(run, db):
                item = self.store.detail("attempts", attempt_id)
                item["supervisor_launch"] = None
                db.execute("UPDATE attempts SET document=? WHERE attempt_id=?", (encode(item), attempt_id))
            self.store.mutate(run_id, "supervisor.not_sent", dispatch_key, None, {}, not_sent, events=[("recovery.blocked", {"code": "supervisor_not_started"})])
            raise TaskAlongError("supervisor_not_started", "The supervisor could not start; explicit reconciliation may retry the proven no-dispatch boundary.", exit_code=3) from exc
        # Reap only the child we own. This thread does not signal or hold authority
        # over the supervisor's own worker; client exit leaves it independent.
        import threading
        threading.Thread(target=process.wait, daemon=True, name="taskalong-supervisor-reaper").start()

    def cancel(self, run_id, *, operation_key, expected_revision):
        self._refuse_trial_run(run_id)
        def change(run, db):
            if run["state"] in TERMINAL or run["state"] in {"accepted", "publishing"}:
                raise TaskAlongError("cancel_not_applicable", "This run has no cancellable local worker phase.", exit_code=3)
            run["state"] = "cancel_pending"
        return self.store.mutate(run_id, "cancel", operation_key, expected_revision, {}, change, events=[("cancel.requested", {})], actor="operator")

    def reconcile(self, run_id, *, operation_key, expected_revision):
        self._refuse_trial_run(run_id)
        with self.store.guard(run_id, "dispatch"):
            return self._reconcile(run_id, operation_key=operation_key, expected_revision=expected_revision)

    def _reconcile(self, run_id, *, operation_key, expected_revision):
        run = self.store.run(run_id)
        from .executors.observed_capture import validate_completed_run
        validate_completed_run(self.store, run)
        prior = self.store.operation("reconcile", run_id, operation_key, {})
        if prior:
            return prior
        if run["revision"] != expected_revision:
            raise TaskAlongError("revision_conflict", "Inspect the current revision before reconciliation.", exit_code=4)
        if run["blocked_from"] == "publishing" or run["state"] == "publishing":
            with self.store.guard(run_id, "publish"):
                intent = self.publish_intent(run_id)
                result = self._publish_effects(run_id, intent, reconcile_only=True)
                return self.store.mutate(run_id, "reconcile", operation_key, None, {}, lambda current, db: None, events=[("effect.observed" if result["state"] == "draft_published" else "effect.unknown", {"kind": "publication"})])
        if run["active_attempt_id"]:
            item = self.store.detail("attempts", run["active_attempt_id"])
            if item.get("spawn_phase") == "not_dispatched" and not item.get("supervisor_launch"):
                # Proven no dispatch: recover only the exact DB+common-marker intent.
                effect = self.store.detail("effects", item["workspace_effect_id"])
                manager = self._manager(run)
                if effect["kind"] == "workspace.reacquire":
                    self.store.require_fence(run, run["lease_generation"])
                    previous = self.store.detail("attempts", run["attempts"][-2]["attempt_id"])
                    spec = self.store.spec(run)
                    if spec["schema_version"] in {"2.5", "2.6"} and previous["status"] == "completed":
                        from .executors.observed_capture import validate_handoff
                        validate_handoff(self.store, run, spec, previous)
                    checkpoint = previous.get("checkpoint") or {}
                    observed = manager.observe_generation(effect["request"], run["lease_generation"] - 1, run["lease_generation"])
                    snapshot = manager.snapshot(observed, spec["scope"], expected_head=spec["repository"]["base_commit"])
                    if (not previous.get("termination_confirmed") or checkpoint.get("content_digest") != snapshot["content_digest"]
                            or checkpoint.get(_worker_identity_key(spec)) != self._profile(spec)["digest"] or checkpoint.get("spec_digest") != spec["digest"]):
                        raise TaskAlongError("checkpoint_stale", "The stopped checkpoint changed during interrupted reacquisition; preserve it.", exit_code=3)
                    workspace = manager.reconcile_generation(effect["request"], run["lease_generation"] - 1, run["lease_generation"])
                else:
                    workspace = manager.reconcile(item["workspace"])
                self._workspace_ready(run, item, workspace)
                self._launch_supervisor(run_id, item["attempt_id"])
                return self.store.mutate(run_id, "reconcile", operation_key, None, {}, lambda current, db: None, events=[("effect.observed", {"kind": "proven_no_dispatch_recovered"})])
            if item.get("status") in {"completed", "failed", "cancelled"} and item.get("termination_confirmed"):
                def change(current, db):
                    current["active_attempt_id"] = None
                    current["state"] = "blocked"
                    current["blocked_from"] = "running"
                    current["blockers"] = [{"code": "continuation_required", "message": "Choose an explicit continuation mode.", "recovery": [{"action": "resume_explicit_mode"}]}]
                    db.execute("UPDATE attempts SET active=0 WHERE attempt_id=?", (item["attempt_id"],))
                return self.store.mutate(run_id, "reconcile", operation_key, expected_revision, {}, change, events=[("recovery.blocked", {"code": "continuation_required"})])
            # Read-only live identity inspection cannot prove cessation after supervisor loss.
            from .process import receipt_is_alive
            if item.get("process_receipt") and receipt_is_alive(item["process_receipt"]):
                raise TaskAlongError("process_identity_unreconciled", "The recorded process or group is live or ambiguous; only its owning supervisor may cancel it.", exit_code=5, effect_outcome="uncertain")
            def unknown(current, db):
                current["state"] = "blocked"
                current["blocked_from"] = "running"
                current["blockers"] = [{"code": "start_unreconciled", "effect_outcome": "uncertain", "message": "Process cessation remains uncertain.", "recovery": [{"action": "operator_process_reconciliation"}]}]
                lease = self.store.lease(current)
                lease["state"] = "quarantined"
                db.execute("UPDATE leases SET state='quarantined',document=? WHERE repository_id=?", (encode(lease), current["repository_registration_id"]))
            return self.store.mutate(run_id, "reconcile", operation_key, expected_revision, {}, unknown, events=[("effect.unknown", {"code": "start_unreconciled"})])
        if run["pending_effect_ids"]:
            # Candidate object creation has deterministic inputs; safely repeat only plumbing CAS.
            for effect_id in run["pending_effect_ids"]:
                effect = self.store.detail("effects", effect_id)
                if effect["kind"] == "candidate.freeze":
                    candidate = self._manager(run).freeze(effect["request"])
                    self._candidate_observed(run_id, effect_id, candidate)
                else:
                    raise TaskAlongError("effect_unreconciled", "Pending effect needs exact adapter reconciliation before continuation.", exit_code=5, effect_outcome="uncertain")
        if self.store.run(run_id)["state"] == "cancel_pending":
            return self.store.mutate(run_id, "reconcile", operation_key, None, {}, self._confirm_cancel,
                events=[("cancel.confirmed", {"local_cessation": True})], actor="operator")
        def observed(current, db):
            pass
        return self.store.mutate(run_id, "reconcile", operation_key, None, {}, observed, events=[("recovery.blocked", {"code": "no_implicit_retry"})])

    def verify(self, run_id, *, operation_key, expected_revision):
        self._refuse_trial_run(run_id)
        with self.store.guard(run_id, "verify"):
            try:
                return self._verify(run_id, operation_key=operation_key, expected_revision=expected_revision)
            except TaskAlongError as exc:
                if exc.code == "verification_state_changed" and self.store.run(run_id)["state"] == "cancel_pending":
                    return self._cancel_verification(run_id)
                raise

    def _verify(self, run_id, *, operation_key, expected_revision):
        from .executors.observed_capture import validate_completed_run
        validate_completed_run(self.store, self.store.run(run_id))
        request = {}
        prior = self.store.operation("verify", run_id, operation_key, request)
        if prior:
            return prior
        run = self.store.run(run_id)
        if run["revision"] != expected_revision:
            raise TaskAlongError("revision_conflict", "Run revision changed before verification.", exit_code=4)
        spec = self.store.spec(run)
        self.store.authority(run, {"verify", "commit_candidate"}, spec["digest"])
        check_profile = None
        if spec["schema_version"] in {"2.2", "2.3", "2.4", "2.5", "2.6", "2.9"}:
            from .admission import resolve
            _, _, check_profile = resolve(self.store, spec)
        if run["active_attempt_id"] is not None or run["state"] not in {"verifying", "blocked", "accepted"}:
            raise TaskAlongError("workspace_not_quiescent", "Verification requires a completed, stopped worker.", exit_code=3)
        if run["pending_effect_ids"]:
            raise TaskAlongError("effect_unreconciled", "Verification requires every previous effect to be reconciled.", exit_code=5, effect_outcome="uncertain")
        attempt = self.store.detail("attempts", run["attempts"][-1]["attempt_id"])
        if not attempt.get("termination_confirmed") or attempt["status"] != "completed":
            raise TaskAlongError("worker_handoff_missing", "Verification requires the exact completed worker handoff.", exit_code=3)
        if spec["schema_version"] == "2.7":
            from .steps import validate_chain, reserve
            validate_chain(self.store, run, live=True, complete=True)
            def reserve_pass(current, db):
                if current["state"] == "cancel_pending":
                    raise TaskAlongError("cancel_pending", "Cancellation prevents final verification.", exit_code=6)
                reserve(current, spec, reservation_id=identifier(), kind="verification", owner_id=operation_key)
                current["final_verification_ids"].append(operation_key)
            self.store.mutate(run_id, "verification.reserve", operation_key, run["revision"], {}, reserve_pass)
            run = self.store.run(run_id)
        workspace = self.store.lease(run)["workspace"]
        manager = self._manager(run)
        manager.validate(workspace, run["lease_generation"])
        if not run["candidate"]:
            intent = manager.candidate_intent(workspace, spec["scope"], spec["repository"]["base_commit"], attempt["created_at"], "TaskAlong bounded candidate " + run_id)
            def freeze_intent(current, db):
                _effect(db, current, "candidate.freeze", operation_key, intent)
            prepared = self.store.mutate(run_id, "candidate.prepare", operation_key, run["revision"], {"intent_digest": digest(intent)}, freeze_intent, events=[("effect.prepared", {"kind": "candidate.freeze"})], fence=run["lease_generation"])
            effect_id = prepared["pending_effect_ids"][-1]
            candidate = manager.freeze(intent)
            run = self._candidate_observed(run_id, effect_id, candidate)
        candidate = run["candidate"]
        manager.assert_candidate(workspace, candidate, spec["scope"])
        if run["state"] != "verifying":
            def entering(current, db):
                if current["state"] == "cancel_pending":
                    raise TaskAlongError("cancel_pending", "Cancellation prevents new verification effects.", exit_code=6)
                current["state"] = "verifying"
                current["blocked_from"] = None
                current["blockers"] = []
                current["acceptance_id"] = None
            run = self.store.mutate(run_id, "verification.begin", operation_key, run["revision"], {}, entering, events=[("acceptance.invalidated", {"reason": "fresh_verification"})], fence=run["lease_generation"])
        # Reuse only receipts for this exact durable verification invocation.
        verification_key = "verification-claim:" + operation_key
        prior_claim = self.store.operation("verification.claim", run_id, verification_key, {})
        if prior_claim:
            raise TaskAlongError("verification_unreconciled", "An interrupted verification invocation cannot be silently repeated; inspect it and use a new explicit key.", exit_code=5, effect_outcome="uncertain")
        self.store.mutate(run_id, "verification.claim", verification_key, None, {}, lambda current, db: None, events=[("effect.prepared", {"kind": "verification"})], fence=run["lease_generation"])
        evidence_records = []
        scope_record = self._evidence_base(run, spec, attempt, candidate, check_profile or self._profile(spec), "scope", "passed")
        scope_record["artifacts"] = [self.store.put_blob(canonical_bytes(manager.snapshot(workspace, spec["scope"], expected_head=candidate["commit"])["manifest"]))]
        self._record_evidence(run_id, scope_record)
        evidence_records.append(scope_record)
        from .process import ProcessBoundaryError, collect_interrupts, run_bounded
        from .command_sandbox import command_sandbox_for
        from .evidence import acceptance_reasons
        profile = check_profile or self._profile(spec)
        launcher = command_sandbox_for(profile)
        for check in spec["checks"]:
            if check_profile is not None:
                resolve(self.store, spec)
            self.store.require_fence(self.store.run(run_id), run["lease_generation"])
            manager.assert_candidate(workspace, candidate, spec["scope"])
            sandbox = self.store.setting("command_sandbox")
            if run["qualification"] == "synthetic" and sandbox:
                executable = Path(sandbox["executable"])
                if hashlib.sha256(executable.read_bytes()).hexdigest() != sandbox["sha256"]:
                    raise TaskAlongError("sandbox_changed", "Synthetic command launcher changed after configuration.", exit_code=3)
                argv = [str(executable), "--workspace", workspace["path"], "--git-common", self.store.repository(run["repository_registration_id"])["common_dir"], "--control", str(self.store.root), "--", *check["argv"]]
            else:
                argv = launcher.prepare_check(check["argv"], workspace=workspace["path"], git_common_dir=self.store.repository(run["repository_registration_id"])["common_dir"], control_dir=str(self.store.root))
            if self.store.run(run_id)["state"] == "cancel_pending":
                return self._cancel_verification(run_id)
            started = now()
            scratch = Path(workspace["path"]) / ".taskalong-scratch"
            scratch.mkdir(mode=0o700, exist_ok=True)
            environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(scratch), "HOME": str(scratch)}
            check_cwd = Path(workspace["path"]) if check["cwd"] == "." else Path(workspace["path"]) / check["cwd"]
            with collect_interrupts() as interruption:
                capture = self._capture_prepare(run_id, "check:" + check["id"], operation_key)
                if interruption.requested:
                    self._capture_finish(run_id, capture, 0, confirmed=True)
                    self._verification_interrupted(run_id, confirmed=True)
                def before_dispatch(receipt):
                    if interruption.requested:
                        raise ProcessBoundaryError("Foreground verification stopped before dispatch.", code="verification_interrupted", effect_outcome="not_sent")
                    if check_profile is not None or spec["schema_version"] == "2.7":
                        current = self.store.run(run_id)
                        if current["state"] == "cancel_pending":
                            raise ProcessBoundaryError("Cancellation prevents verifier dispatch.", code="cancel_pending", effect_outcome="not_sent")
                        self.store.authority(current, {"verify", "commit_candidate"}, spec["digest"])
                        if spec["schema_version"] == "2.7":
                            from .steps import validate_chain
                            validate_chain(self.store, current, live=True, complete=True)
                        else:
                            resolve(self.store, spec)
                try:
                    outcome = run_bounded(argv, cwd=check_cwd, timeout_seconds=check["timeout_seconds"], max_output_bytes=capture["request"]["reserved_output_bytes"], env=environment, on_spawn=before_dispatch, cancel_requested=lambda: interruption.requested or self.store.run(run_id)["state"] == "cancel_pending")
                except ProcessBoundaryError as exc:
                    # A closed target gate says nothing about its owned
                    # wrapper's cleanup. Settle only an actual cessation
                    # receipt as well as a non-uncertain effect outcome.
                    confirmed = (exc.effect_outcome != "uncertain" and exc.process_result is not None
                                 and exc.process_result.termination_confirmed is True)
                    consumed = (0 if confirmed and exc.code == "verification_interrupted"
                                and exc.effect_outcome == "not_sent" else capture["request"]["reserved_output_bytes"])
                    self._capture_finish(run_id, capture, consumed, confirmed=confirmed)
                    if interruption.requested:
                        self._verification_interrupted(run_id, confirmed=confirmed)
                    if self.store.run(run_id)["state"] == "cancel_pending":
                        return self._cancel_verification(run_id)
                    return _block(self.store, run_id, exc.code, phase="verifying", uncertain=not confirmed)
                self._capture_finish(run_id, capture, outcome.output_bytes, confirmed=outcome.termination_confirmed)
                if interruption.requested:
                    self._verification_interrupted(run_id, confirmed=outcome.termination_confirmed)
            if not outcome.termination_confirmed:
                return _block(self.store, run_id, "cancellation_unconfirmed", phase="verifying", uncertain=True)
            if outcome.output_limited:
                return _block(self.store, run_id, "output_budget_exhausted", phase="verifying")
            if outcome.cancelled:
                return self._cancel_verification(run_id)
            try:
                manager.assert_candidate(workspace, candidate, spec["scope"])
            except TaskAlongError:
                return _block(self.store, run_id, "check_mutated_candidate", phase="verifying")
            artifact = self.store.put_blob(outcome.stdout + outcome.stderr, media_type="text/plain")
            record = self._command_evidence(run, spec, attempt, check, candidate, profile, outcome, started, artifact)
            evidence_records.append(record)
            self._record_evidence(run_id, record)
        review = self.store.setting("review")
        if review is None:
            return _block(self.store, run_id, "required_review_missing", phase="verifying")
        if check_profile is not None:
            resolve(self.store, spec)
        from .integrations.reviewsensei import ReviewSenseiAdapter
        snapshot = manager.snapshot(workspace, spec["scope"], expected_head=candidate["commit"])
        # Diff is base..candidate, not the now-clean index/worktree.
        diff_bytes = manager.diff_bytes(workspace, candidate)
        invocation_dir = self.store.root / "review" / identifier()
        invocation_dir.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        with collect_interrupts() as interruption:
            capture = self._capture_prepare(run_id, "review", operation_key)
            if interruption.requested:
                self._capture_finish(run_id, capture, 0, confirmed=True)
                self._verification_interrupted(run_id, confirmed=True)
            try:
                def review_gate():
                    current = self.store.run(run_id)
                    if current["state"] == "cancel_pending":
                        raise TaskAlongError("cancel_pending", "Cancellation prevents review dispatch.", exit_code=6)
                    self.store.authority(current, {"verify", "commit_candidate"}, spec["digest"])
                    if spec["schema_version"] == "2.7":
                        from .steps import validate_chain
                        validate_chain(self.store, current, live=True, complete=True)
                    else:
                        resolve(self.store, spec)
                receipt = ReviewSenseiAdapter(review["executable"], python_executable=review["python_executable"], expected_executable_sha256=review["executable_sha256"], interrupt_requested=lambda: interruption.requested, pre_dispatch=review_gate if check_profile or spec["schema_version"] == "2.7" else None).review(diff_bytes, {"base_commit": candidate["base_commit"], "candidate_commit": candidate["commit"], "candidate_tree": candidate["tree"], "diff_sha256": candidate["diff_sha256"]}, config_path=review["config_path"], qualification=run["qualification"], invocation_dir=invocation_dir, expected_config_digest=spec["review"]["config_digest"], fixture_response=review["fixture_response"], max_output_bytes=capture["request"]["reserved_output_bytes"], cancel_requested=lambda: interruption.requested or self.store.run(run_id)["state"] == "cancel_pending")
                self._capture_finish(run_id, capture, receipt.output_bytes, confirmed=True)
                if interruption.requested:
                    self._verification_interrupted(run_id, confirmed=True)
                manager.assert_candidate(workspace, candidate, spec["scope"])
                record = self._review_evidence(run, spec, attempt, candidate, profile, receipt.to_dict())
                record["artifacts"].extend([self.store.put_blob(canonical_bytes(receipt.result)), self.store.put_blob(canonical_bytes(receipt.outcome))])
                evidence_records.append(record)
                self._record_evidence(run_id, record)
            except TaskAlongError as exc:
                if exc.code == "verification_interrupted":
                    raise
                # A failed external capture consumes its reserved bound conservatively.
                if self.store.detail("effects", capture["effect_id"])["phase"] != "observed":
                    reported = getattr(exc, "output_bytes", None)
                    reserved = capture["request"]["reserved_output_bytes"]
                    consumed = reported if exc.effect_outcome != "uncertain" and type(reported) is int and 0 <= reported <= reserved else reserved
                    self._capture_finish(run_id, capture, consumed, confirmed=exc.effect_outcome != "uncertain")
                if interruption.requested:
                    self._verification_interrupted(run_id, confirmed=exc.effect_outcome != "uncertain")
                if self.store.run(run_id)["state"] == "cancel_pending":
                    return self._cancel_verification(run_id)
                return _block(self.store, run_id, exc.code, phase="verifying", uncertain=exc.effect_outcome == "uncertain")
            if interruption.requested:
                self._verification_interrupted(run_id, confirmed=True)
        # Re-read immutable records and artifact bytes, never trust a worker-supplied verifier field.
        current = self.store.run(run_id)
        for evidence in evidence_records:
            for artifact in evidence["artifacts"]:
                self.store.get_blob(artifact["sha256"])
        manager.assert_candidate(workspace, candidate, spec["scope"])
        validate_completed_run(self.store, current)
        reasons = acceptance_reasons(spec, current, evidence_records, workspace_quiescent=True, current_subject=candidate, packet_digest=attempt["packet"]["digest"], lease_generation=run["lease_generation"], owned_invocation_ids={e["producer"]["invocation_id"] for e in evidence_records}, verification_profile_digest=check_profile["digest"] if check_profile else None)
        decision = "accepted" if not reasons else "blocked"
        acceptance = {"kind": "acceptance", "schema_version": "1.0", "acceptance_id": identifier(), "run_id": run_id, "spec_digest": spec["digest"], "candidate": candidate, "policy_digest": digest(spec["review"]), "evidence_ids": sorted(e["evidence_id"] for e in evidence_records), "evidence_set_digest": digest(sorted(e["evidence_id"] for e in evidence_records)), "verifier": {"version": "0.1.0a1", "identity": "owned-independent-verifier"}, "decision": decision, "reasons": reasons, "at": now(), "qualification": run["qualification"], "extensions": {}}
        if spec["schema_version"] == "2.7":
            from .steps import validate_chain
            acceptance["extensions"]["taskalong:execution_chain_digest"] = validate_chain(self.store, current, live=True, complete=True)
        acceptance = seal("acceptance", acceptance)
        def accept(updated, db):
            self.store.require_fence(updated, run["lease_generation"], db=db)
            validate_completed_run(self.store, updated)
            if spec["schema_version"] == "2.7":
                if validate_chain(self.store, updated, live=True, complete=True) != acceptance["extensions"]["taskalong:execution_chain_digest"]:
                    raise TaskAlongError("step_chain_changed", "The ordered results changed before final acceptance.", exit_code=3)
            if updated["state"] != "verifying":
                raise TaskAlongError("verification_state_changed", "Cancellation or recovery changed the run before acceptance.", exit_code=6)
            db.execute("INSERT INTO acceptances VALUES (?,?,?)", (acceptance["acceptance_id"], run_id, encode(acceptance)))
            updated["acceptance_id"] = acceptance["acceptance_id"]
            updated["state"] = "accepted" if decision == "accepted" else "blocked"
            updated["blocked_from"] = None if decision == "accepted" else "verifying"
            updated["blockers"] = [] if decision == "accepted" else [{"code": r["code"], "message": r["message"], "recovery": []} for r in reasons]
        return self.store.mutate(run_id, "verify", operation_key, None, request, accept, events=[("acceptance.recorded", {"acceptance_id": acceptance["acceptance_id"], "decision": decision})], actor="verifier", fence=run["lease_generation"])

    def _verification_interrupted(self, run_id, *, confirmed):
        outcome = "known" if confirmed else "uncertain"
        if self.store.run(run_id)["state"] == "cancel_pending":
            self._cancel_verification(run_id)
        else:
            _block(self.store, run_id, "verification_interrupted", phase="verifying", effect_outcome=outcome)
        raise TaskAlongError("verification_interrupted", "Foreground verification was interrupted; inspect the retained run before continuing.",
                           exit_code=130, effect_outcome=outcome,
                           recovery=[{"action": "inspect_and_reconcile" if not confirmed else "inspect_and_verify_with_fresh_key"}])

    def _capture_prepare(self, run_id, label, key):
        run = self.store.run(run_id)
        spec = self.store.spec(run)
        remaining = spec["budget"]["max_output_bytes"] - run["budget_consumed"]["output_bytes"]
        if spec["schema_version"] == "2.7":
            # Each no-refund pass owns its own captured-output allowance.
            consumed = 0
            for row in self.store.db.execute("SELECT document FROM effects WHERE run_id=? AND kind='verifier.capture'", (run_id,)):
                from .validation import loads
                prior = loads(row[0])
                if prior["request"].get("verification_key") == key:
                    consumed += (prior.get("response") or {}).get("output_bytes", prior["request"]["reserved_output_bytes"])
            remaining = spec["final_verification"]["max_output_bytes"] - consumed
        if remaining <= 0:
            raise TaskAlongError("output_budget_exhausted", "The persisted aggregate output budget is exhausted.", exit_code=3)
        selected = {}
        def prepare(current, db):
            if current["state"] != "verifying":
                raise TaskAlongError("verification_state_changed", "Cancellation prevents a new verifier invocation.", exit_code=6)
            item = _effect(db, current, "verifier.capture", _internal_key(label, key), {"label": label, "reserved_output_bytes": remaining})
            if spec["schema_version"] == "2.7":
                item["request"]["verification_key"] = key
                item["request_digest"] = digest(item["request"])
                db.execute("UPDATE effects SET request_digest=?,document=? WHERE effect_id=?", (item["request_digest"], encode(item), item["effect_id"]))
            selected.update(item)
        self.store.mutate(run_id, "capture.prepare", _internal_key(label, key), None, {"label": label}, prepare, events=[("effect.prepared", {"kind": "verifier.capture", "label": label})], fence=run["lease_generation"])
        return selected

    def _capture_finish(self, run_id, capture, observed_bytes, *, confirmed):
        def observed(run, db):
            effect = self.store.detail("effects", capture["effect_id"])
            effect.update(phase="observed" if confirmed else "unknown", response={"output_bytes": observed_bytes, "termination_confirmed": confirmed})
            db.execute("UPDATE effects SET phase=?,document=? WHERE effect_id=?", (effect["phase"], encode(effect), effect["effect_id"]))
            run["budget_consumed"]["output_bytes"] += observed_bytes if confirmed else capture["request"]["reserved_output_bytes"]
            if confirmed:
                run["pending_effect_ids"] = [eid for eid in run["pending_effect_ids"] if eid != effect["effect_id"]]
        return self.store.mutate(run_id, "capture.observed", capture["effect_id"], None, {"bytes": observed_bytes, "confirmed": confirmed}, observed, events=[("effect.observed" if confirmed else "effect.unknown", {"kind": "verifier.capture"})])

    def _candidate_observed(self, run_id, effect_id, candidate):
        def frozen(current, db):
            effect = self.store.detail("effects", effect_id)
            effect.update(phase="observed", response=candidate)
            db.execute("UPDATE effects SET phase='observed',document=? WHERE effect_id=?", (encode(effect), effect_id))
            current["pending_effect_ids"] = [item for item in current["pending_effect_ids"] if item != effect_id]
            current["candidate"] = candidate
            if current["state"] != "cancel_pending":
                current["state"] = "verifying"
        run = self.store.run(run_id)
        return self.store.mutate(run_id, "candidate.observed", effect_id, None, {"candidate": candidate}, frozen, events=[("candidate.frozen", candidate), ("effect.observed", {"effect_id": effect_id})], fence=run["lease_generation"])

    def publish_intent(self, run_id):
        self._refuse_trial_run(run_id)
        if self.store.spec(self.store.run(run_id))["schema_version"] == "2.7":
            raise TaskAlongError("ordered_publication_unsupported", "M10 cannot publish a branch or pull request.", exit_code=3)
        from .integrations.github import build_publish_intent
        run = self.store.run(run_id)
        from .executors.observed_capture import validate_completed_run
        validate_completed_run(self.store, run)
        spec = self.store.spec(run)
        if not run["acceptance_id"]:
            raise TaskAlongError("publication_not_ready", "Publication requires independent acceptance of the exact candidate.", exit_code=3)
        acceptance = validate("acceptance", self.store.detail("acceptances", run["acceptance_id"]))
        if run["active_attempt_id"] is not None:
            raise TaskAlongError("workspace_not_quiescent", "Publication cannot run while an executor owns the workspace.", exit_code=3)
        self.store.require_fence(run, run["lease_generation"])
        self._manager(run).assert_candidate(self.store.lease(run)["workspace"], run["candidate"], spec["scope"])
        for evidence_id in acceptance["evidence_ids"]:
            evidence = self.store.detail("evidence", evidence_id)
            for artifact in evidence["artifacts"]:
                self.store.get_blob(artifact["sha256"])
        return build_publish_intent(run, spec, acceptance)

    def publish(self, run_id, *, intent_digest, operation_key, expected_revision):
        self._refuse_trial_run(run_id)
        if self.store.spec(self.store.run(run_id))["schema_version"] == "2.7":
            raise TaskAlongError("ordered_publication_unsupported", "M10 cannot publish a branch or pull request.", exit_code=3)
        with self.store.guard(run_id, "publish"):
            request = {"intent_digest": intent_digest}
            prior = self.store.operation("publish", run_id, operation_key, request)
            if prior:
                return self.store.run(run_id)
            run = self.store.run(run_id)
            if run["revision"] != expected_revision:
                raise TaskAlongError("revision_conflict", "Inspect the exact accepted candidate before publication.", exit_code=4)
            if run["state"] != "accepted" or run["pending_effect_ids"]:
                raise TaskAlongError("publication_not_ready", "Publication requires accepted state and no unresolved effect.", exit_code=3)
            intent = self.publish_intent(run_id)
            if intent["digest"] != intent_digest:
                raise TaskAlongError("publication_intent_changed", "Publication inputs differ from the explicitly supplied intent digest.", exit_code=3)
            # This method is an OS-operator control-plane invocation over exact bytes.
            # It does not claim a human was authenticated from worker text.
            self.authorize(run_id, decision_digest=intent_digest, scope=["push_branch", "create_draft_pr"])
            self.store.authority(run, {"push_branch", "create_draft_pr"}, intent_digest)
            def prepare(current, db):
                current["state"] = "publishing"
            self.store.mutate(run_id, "publish", operation_key, expected_revision, request, prepare, events=[("effect.prepared", {"kind": "publication", "intent_digest": intent_digest})], actor="operator", fence=run["lease_generation"])
            return self._publish_effects(run_id, intent, reconcile_only=False)

    def _publish_effects(self, run_id, intent, *, reconcile_only):
        from .integrations.github import GitHubPublisher
        run = self.store.run(run_id)
        transport = self.store.setting("publication_transport")
        if not transport or transport["qualification"] != run["qualification"]:
            return _block(self.store, run_id, "publication_transport_unqualified", phase="publishing")
        if hashlib.sha256(Path(transport["gh_path"]).read_bytes()).hexdigest() != transport["gh_sha256"]:
            return _block(self.store, run_id, "publication_transport_changed", phase="publishing")
        workspace = self.store.lease(run)["workspace"]
        effects = {}
        for row in self.store.db.execute("SELECT document FROM effects WHERE run_id=? AND kind IN ('push_branch','create_draft_pr')", (run_id,)):
            from .validation import loads
            item = loads(row[0])
            effects[item["kind"]] = item
        def record(kind, phase, data):
            def change(current, db):
                self.store.require_fence(current, run["lease_generation"], db=db)
                prior_effect = effects.get(kind)
                if prior_effect is None:
                    item = {"effect_id": identifier(), "run_id": run_id, "operation_key": intent["digest"], "kind": kind,
                            "request_digest": data.get("request_digest", intent["digest"]), "phase": phase,
                            "request": data.get("request", {"intent_digest": intent["digest"]}), "response": None}
                    db.execute("INSERT INTO effects VALUES (?,?,?,?,?,?,?)", (item["effect_id"], run_id, item["operation_key"], kind, item["request_digest"], phase, encode(item)))
                else:
                    item = dict(prior_effect)
                    item["phase"] = phase
                    if phase == "observed": item["response"] = data
                    db.execute("UPDATE effects SET phase=?,document=? WHERE effect_id=?", (phase, encode(item), item["effect_id"]))
                if phase == "observed":
                    current["pending_effect_ids"] = [eid for eid in current["pending_effect_ids"] if eid != item["effect_id"]]
                elif item["effect_id"] not in current["pending_effect_ids"]:
                    current["pending_effect_ids"].append(item["effect_id"])
                effects[kind] = item
            event = "effect.observed" if phase == "observed" else ("effect.unknown" if phase == "unknown" else "effect.prepared")
            self.store.mutate(run_id, "publication.journal", identifier(), None, {"kind": kind, "phase": phase, "data": data}, change, events=[(event, {"kind": kind, "phase": phase})], actor="publisher", fence=run["lease_generation"])
        try:
            receipt = GitHubPublisher(transport["gh_path"], git_remote=transport["git_remote"], qualification=transport["qualification"]).publish(intent, workspace=workspace["path"], effects=effects, record=record, reconcile_only=reconcile_only)
            self._manager(run).assert_candidate(workspace, run["candidate"], self.store.spec(run)["scope"])
        except TaskAlongError as exc:
            return _block(self.store, run_id, exc.code, phase="publishing", uncertain=exc.effect_outcome == "uncertain")
        def published(current, db):
            current["state"] = "draft_published"
            current["publication"] = receipt
            current["blocked_from"] = None
            current["blockers"] = []
        return self.store.mutate(run_id, "publication.observed", intent["digest"], None, receipt, published, events=[("draft.published", receipt)], actor="publisher", fence=run["lease_generation"])

    def _confirm_cancel(self, run, db):
        if run["state"] != "cancel_pending":
            raise TaskAlongError("cancellation_state_changed", "Cancellation no longer owns this transition.", exit_code=4)
        if (run["active_attempt_id"] or run["pending_effect_ids"]
                or any(not self.store.detail("attempts", item["attempt_id"]).get("termination_confirmed") for item in run["attempts"])):
            raise TaskAlongError("cancellation_unconfirmed", "An owned invocation or effect remains unreconciled.", exit_code=5, effect_outcome="uncertain")
        run["state"] = "cancelled"
        run["blockers"] = []
        run["blocked_from"] = None

    def _cancel_verification(self, run_id):
        run = self.store.run(run_id)
        if run["active_attempt_id"] or run["pending_effect_ids"]:
            return _block(self.store, run_id, "cancellation_unconfirmed", phase="verifying", uncertain=True)
        return self.store.mutate(run_id, "verification.cancel", identifier(), None, {}, self._confirm_cancel, events=[("cancel.confirmed", {"local_cessation": True})])

    def _record_evidence(self, run_id, record):
        record = validate("evidence", record)
        canonical_ref = None
        attempt = self.store.detail("attempts", record["attempt_id"])
        if attempt.get("canonical_packet") and attempt["canonical_packet"]["schema_version"] != "2.9":
            from .validation import seal_versioned
            canonical = seal_versioned("evidence", {"run_id":run_id, "attempt_id":record["attempt_id"],
                "spec_digest":record["spec_digest"], "binding_digest":attempt["admission"]["binding"]["digest"],
                "admission_digest":attempt["dispatch_admission"]["digest"],
                "canonical_packet_digest":attempt["canonical_packet"]["digest"], "wire_packet_digest":record["packet_digest"],
                "legacy_evidence_digest":digest(record), "legacy_evidence_id":record["evidence_id"],
                "role":"independent_verifier", "result":record["result"], "qualification":record["qualification"]}, version="2.2")
            canonical_ref = self.store.put_blob(canonical_bytes(canonical))
        def change(run, db):
            db.execute("INSERT INTO evidence VALUES (?,?,?)", (record["evidence_id"], run_id, encode(record)))
            run["evidence_ids"].append(record["evidence_id"])
            if canonical_ref is not None:
                item = self.store.detail("attempts", record["attempt_id"])
                item.setdefault("canonical_evidence_refs", []).append(canonical_ref)
                db.execute("UPDATE attempts SET document=? WHERE attempt_id=?", (encode(item), item["attempt_id"]))
        self.store.mutate(run_id, "evidence.record", record["evidence_id"], None, {"evidence_id": record["evidence_id"]}, change, events=[("evidence.recorded", {"evidence_id": record["evidence_id"]})], actor="verifier", fence=record["lease_generation"])

    def _evidence_base(self, run, spec, attempt, candidate, profile, type_, result):
        return {"kind": "evidence", "schema_version": "1.0", "evidence_id": identifier(), "run_id": run["run_id"], "task_revision": run["task_revision"], "spec_digest": run["spec_digest"], "attempt_id": attempt["attempt_id"], "packet_digest": attempt["packet"]["digest"], "lease_generation": run["lease_generation"], "producer": {"role": "verifier", "invocation_id": identifier(), "tool": "taskalong", "version": "0.1.0a1", "executable_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()}, "type": type_, "criterion_ids": [], "subject": {"base_commit": candidate["base_commit"], "candidate_commit": candidate["commit"], "candidate_tree": candidate["tree"], "diff_sha256": candidate["diff_sha256"]}, "inputs": {"check_digest": None, "review_config_digest": None, "runtime_profile_digest": profile["digest"]}, "result": result, "started_at": now(), "finished_at": now(), "duration_ms": 0, "artifacts": [], "command": None, "qualification": run["qualification"], "extensions": {}}

    def _command_evidence(self, run, spec, attempt, check, candidate, profile, outcome, started, artifact):
        record = self._evidence_base(run, spec, attempt, candidate, profile, "command", "passed" if outcome.exit_code == check["expected_exit_code"] and not (outcome.timed_out or outcome.cancelled or outcome.output_limited) else "failed")
        record.update(criterion_ids=check["criterion_ids"], started_at=started, finished_at=now(), duration_ms=outcome.duration_ms, artifacts=[artifact], command={"argv_digest": digest(check["argv"]), "cwd_relative": check["cwd"], "exit_code": outcome.exit_code, "timed_out": outcome.timed_out})
        record["inputs"]["check_digest"] = digest(check)
        record["producer"]["invocation_id"] = outcome.receipt.invocation_id
        record["producer"]["executable_sha256"] = outcome.receipt.executable_sha256
        return record

    def _review_evidence(self, run, spec, attempt, candidate, profile, receipt):
        record = self._evidence_base(run, spec, attempt, candidate, profile, "review", "passed")
        record["inputs"]["review_config_digest"] = spec["review"]["config_digest"]
        record["producer"]["tool"] = "review-sensei"
        record["producer"]["version"] = "0.8.8"
        record["producer"]["invocation_id"] = receipt["invocation_id"]
        record["producer"]["executable_sha256"] = receipt["executable_sha256"]
        record["duration_ms"] = receipt["duration_ms"]
        record["artifacts"] = [self.store.put_blob(canonical_bytes(receipt))]
        record["extensions"]["taskalong:review"] = receipt
        return record


def drive_run(state_dir, run_id, attempt_id):
    """Called only by the guarded per-run supervisor, never by a worker."""
    with Store(state_dir) as store:
        workflow = Workflow(store)
        run = store.run(run_id)
        attempt = store.detail("attempts", attempt_id)
        if run["active_attempt_id"] != attempt_id or attempt["spawn_phase"] != "not_dispatched":
            return
        spec = store.spec(run)
        if spec["schema_version"] == "2.8":
            raise TaskAlongError("trial_runtime_unqualified", "The E1 trial runtime is not qualified or enabled.", exit_code=3)
        profile = workflow._profile(spec)
        workspace = attempt["workspace"]
        manager = workflow._manager(run)
        manager.validate(workspace, run["lease_generation"])
        if run["state"] == "cancel_pending":
            _finish_attempt(store, run_id, attempt_id, {"state": "cancelled", "thread_id": None, "process": {"termination_confirmed": True, "duration_ms": 0}, "usage": {}}, None)
            return
        seconds_remaining = int((datetime.fromisoformat(attempt["deadline"].replace("Z", "+00:00")) - datetime.now(timezone.utc)).total_seconds())
        if seconds_remaining <= 0:
            _finish_attempt(store, run_id, attempt_id, {"state": "failed", "error": "attempt_deadline_exhausted", "thread_id": None, "process": {"termination_confirmed": True, "duration_ms": 0, "output_bytes": 0}, "usage": {}}, None)
            return
        if spec["schema_version"] in {"2.2", "2.3", "2.4", "2.5", "2.6", "2.9"}:
            try:
                from .admission import resolve
                authority = store.authority(run, {"execute", "verify", "commit_candidate"}, spec["digest"], attempt["admission"]["authority_id"])
                admission, profile, _ = resolve(store, spec, mode=attempt["mode"], authority_id=authority["authority_id"])
                if admission["projection"] != attempt["admission"]["projection"]:
                    raise TaskAlongError("admission_changed", "The prepared execution context changed before dispatch.", exit_code=3)
                attempt["dispatch_admission"] = admission
            except TaskAlongError as exc:
                _finish_attempt(store, run_id, attempt_id, {"state": "failed", "error": exc.code, "thread_id": None,
                    "process": {"termination_confirmed": True, "duration_ms": 0, "output_bytes": 0}, "usage": {}}, None)
                return
        snapshot = manager.snapshot(workspace, spec["scope"], expected_head=spec["repository"]["base_commit"])
        if spec["schema_version"] == "2.7":
            from .steps import validate_chain, inputs
            validate_chain(store, run)
            inputs(spec, workspace["path"], attempt["step_index"])
        if attempt["mode"] in {"native_resume", "restart"}:
            previous = store.detail("attempts", run["attempts"][-2]["attempt_id"])
            if spec["schema_version"] in {"2.5", "2.6"} and previous["status"] == "completed":
                from .executors.observed_capture import validate_handoff
                try:
                    validate_handoff(store, run, spec, previous)
                except TaskAlongError as exc:
                    # No worker gate or executor.start effect has been created
                    # for this prepared attempt. A bad predecessor is no proof
                    # of a successful new handoff or uncertain target dispatch.
                    _finish_attempt(store, run_id, attempt_id, {"state": "failed", "error": exc.code,
                        "thread_id": None, "process": {"termination_confirmed": True,
                            "duration_ms": 0, "output_bytes": 0}, "usage": {}}, None)
                    return
            checkpoint = previous.get("checkpoint") or {}
            if (not previous.get("termination_confirmed") or checkpoint.get("content_digest") != snapshot["content_digest"]
                    or checkpoint.get("spec_digest") != spec["digest"] or checkpoint.get(_worker_identity_key(spec)) != profile["digest"]):
                _finish_attempt(store, run_id, attempt_id, {"state": "failed", "error": "checkpoint_stale", "thread_id": None,
                    "process": {"termination_confirmed": True, "duration_ms": 0, "output_bytes": 0}, "usage": {}}, None)
                return
        packet_fields = {"packet_id":identifier(), "run_id":run_id, "attempt_id":attempt_id, "spec_digest":spec["digest"],
            "goal":spec["goal"], "non_goals":spec["non_goals"], "scope":spec["scope"], "checks":spec["checks"],
            "bindings":{"base_commit":spec["repository"]["base_commit"], "initial_head":snapshot["head"],
                "initial_content_digest":snapshot["content_digest"], "workspace_id":workspace["workspace_id"],
                "lease_generation":run["lease_generation"]},
            "remaining_budget":{**spec["budget"], "attempt_seconds":min(seconds_remaining,spec["budget"]["attempt_seconds"]),
                "max_attempts":spec["budget"]["max_attempts"]-run["budget_consumed"]["attempts"]+1,
                "max_output_bytes":spec["budget"]["max_output_bytes"]-run["budget_consumed"]["output_bytes"]},
            "qualification":run["qualification"], "extensions":{}}
        if spec["schema_version"] not in {"2.3", "2.4", "2.5", "2.6", "2.9"}:
            packet_fields["bindings"]["runtime_profile_digest"] = profile["digest"]
            packet_fields["result_schema_id"] = "urn:taskalong:schema:v1:worker-result"
        if spec["schema_version"] == "2.7":
            step = spec["steps"][attempt["step_index"]]
            packet_fields["goal"], packet_fields["scope"] = step["goal"], step["scope"]
            packet_fields["remaining_budget"].pop("attempt_output_bytes", None)
            packet_fields["remaining_budget"].update(max_attempts=1, max_output_bytes=spec["budget"]["attempt_output_bytes"])
            packet_fields["extensions"]["taskalong:ordered_step"] = {"step_id": step["step_id"], "step_index":attempt["step_index"],
                "step_digest":digest(step), "predecessor_digest":run["steps"][attempt["step_index"]-1]["receipt_digest"] if attempt["step_index"] else None,
                "reservation_digest":digest(attempt["reservation"]), "inputs":step["inputs"]}
        from .admission import worker_contract
        contract, provider = worker_contract(store, spec, profile)
        canonical_packet, packet, projection = contract.compile_packet(packet_fields, attempt.get("dispatch_admission"))
        if canonical_packet is not None:
            store.put_blob(canonical_bytes(canonical_packet))
            store.put_blob(canonical_bytes(projection))
        store.put_blob(canonical_bytes(packet))
        def prepared(current, db):
            item = store.detail("attempts", attempt_id)
            if spec["schema_version"] in {"2.2", "2.3", "2.4", "2.5", "2.6", "2.9"}:
                if current["state"] == "cancel_pending":
                    raise TaskAlongError("cancel_pending", "Cancellation prevents worker dispatch.", exit_code=6)
                item.update(canonical_packet=canonical_packet, packet_projection=projection, dispatch_admission=attempt["dispatch_admission"])
                if spec["schema_version"] in {"2.3", "2.4"}:
                    item["driver_session_id"] = packet["session_id"]
            if spec["schema_version"] == "2.7":
                if current["state"] == "cancel_pending":
                    raise TaskAlongError("cancel_pending", "Cancellation prevents worker dispatch.", exit_code=6)
                item.update(starting_snapshot_digest=snapshot["content_digest"], starting_manifest=snapshot["manifest"])
            item["packet"] = packet
            item["spawn_phase"] = "dispatching"
            db.execute("UPDATE attempts SET document=? WHERE attempt_id=?", (encode(item), attempt_id))
            _effect(db, current, "executor.start", attempt_id, {"packet_digest": packet["digest"], _worker_identity_key(spec): profile["digest"]})
        try:
            store.mutate(run_id, "executor.prepare", attempt_id, None, {"packet_digest": packet["digest"]}, prepared, events=[("effect.prepared", {"kind": "executor.start"})], fence=run["lease_generation"])
        except TaskAlongError as exc:
            if (spec["schema_version"] in {"2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.9"} and exc.code == "cancel_pending"
                    and store.detail("attempts", attempt_id)["spawn_phase"] == "not_dispatched"):
                # This supervisor has not created a worker gate or sent target
                # code. The rolled-back preparation cannot leave a dispatch.
                _finish_attempt(store, run_id, attempt_id, {"state":"cancelled", "thread_id":None,
                    "process":{"termination_confirmed":True, "duration_ms":0, "output_bytes":0}, "usage":{}}, None)
                return
            raise
        def on_spawn(receipt):
            if hasattr(receipt, "to_dict"):
                receipt = receipt.to_dict()
            def spawned(current, db):
                if spec["schema_version"] == "2.7":
                    if current["state"] == "cancel_pending":
                        raise TaskAlongError("cancel_pending", "Cancellation prevents ordered worker dispatch.", exit_code=6)
                    from .steps import preflight, validate_chain, inputs
                    store.authority(current, {"execute", "verify", "commit_candidate"}, spec["digest"])
                    store.require_fence(current, attempt["lease_generation"])
                    preflight(workflow, spec)
                    validate_chain(store, current)
                    inputs(spec, workspace["path"], attempt["step_index"])
                    if manager.snapshot(workspace, spec["scope"], expected_head=spec["repository"]["base_commit"])["content_digest"] != snapshot["content_digest"]:
                        raise TaskAlongError("checkpoint_stale", "Workspace changed before dispatch.", exit_code=3)
                if spec["schema_version"] in {"2.2", "2.3", "2.4", "2.5", "2.6", "2.9"}:
                    # run_bounded invokes this callback while the owned gate is
                    # still closed. An exception prevents target execve.
                    if current["state"] == "cancel_pending":
                        raise TaskAlongError("cancel_pending", "Cancellation prevents worker dispatch.", exit_code=6)
                    if datetime.fromisoformat(attempt["deadline"].replace("Z", "+00:00")) <= datetime.now(timezone.utc):
                        raise TaskAlongError("attempt_deadline_exhausted", "The reserved attempt deadline elapsed before gate release.", exit_code=3)
                    authority = store.authority(current, {"execute", "verify", "commit_candidate"}, spec["digest"], attempt["admission"]["authority_id"])
                    from .admission import resolve
                    fresh, _, _ = resolve(store, spec, mode=attempt["mode"], authority_id=authority["authority_id"])
                    if fresh["projection"] != attempt["dispatch_admission"]["projection"] or fresh["trust_digest"] != attempt["dispatch_admission"]["trust_digest"]:
                        raise TaskAlongError("admission_changed", "The frozen dispatch context changed before gate release.", exit_code=3)
                item = store.detail("attempts", attempt_id)
                item.update(status="running", spawn_phase="spawned", process_receipt=receipt)
                db.execute("UPDATE attempts SET document=? WHERE attempt_id=?", (encode(item), attempt_id))
                if current["state"] != "cancel_pending":
                    current["state"] = "running"
                    current["blockers"] = []
                    current["blocked_from"] = None
                current["attempts"][-1]["status"] = "running"
            store.mutate(run_id, "executor.spawned", attempt_id, None, {"receipt": receipt}, spawned, events=[("executor.started", {"attempt_id": attempt_id})], fence=run["lease_generation"])
        output = store.root / "attempts" / attempt_id
        # parents=True applies mode only to the leaf, leaving a new control
        # container to the ambient umask. Never chmod an existing container.
        output.parent.mkdir(mode=0o700, exist_ok=True)
        output.mkdir(mode=0o700)
        from .executors.registry import executor_for
        try:
            result = contract.factory(profile, provider).run(packet, workspace=workspace["path"], output_dir=output, cancel_requested=lambda: store.run(run_id)["state"] == "cancel_pending", heartbeat=lambda: store.heartbeat(run_id, attempt_id), on_spawn=on_spawn, git_common_dir=store.repository(run["repository_registration_id"])["common_dir"], control_dir=str(store.root), mode="native_resume" if attempt["mode"] == "native_resume" else "start", thread_id=attempt.get("thread_id"))
            if spec["schema_version"] == "2.9":
                from .muse_handoff import retain_capture, create_handoff
                if contract.supervisor_handoff != "muse-execution-handoff/1":
                    raise TaskAlongError("adapter_unavailable", "The selected contract cannot issue a supervisor handoff.", exit_code=3)
                retain_capture(store, run_id, attempt_id, result)
                handoff = None
                if store.run(run_id)["state"] == "cancel_pending" and result["process"].get("termination_confirmed"):
                    result.update(state="cancelled", error="cancel_pending")
                elif result["state"] == "completed":
                    handoff = create_handoff(store, run_id, attempt_id, manager, workspace)
                _finish_attempt(store, run_id, attempt_id, result, None, execution_handoff=handoff)
                finished = store.run(run_id)
                if finished["state"] == "verifying":
                    workflow.verify(run_id, operation_key="supervisor-verify:" + attempt_id, expected_revision=finished["revision"])
                return
            if spec["schema_version"] in {"2.5", "2.6"}:
                from .executors.observed_capture import retain_handoff
                retain_handoff(store, run, spec, store.detail("attempts", attempt_id), result)
            worker = result.get("result")
            try:
                stopped_snapshot = manager.snapshot(workspace, spec["scope"], expected_head=spec["repository"]["base_commit"])
                result["checkpoint"] = {_worker_identity_key(spec):profile["digest"], "spec_digest":spec["digest"], "content_digest":stopped_snapshot["content_digest"]}
                if spec["schema_version"] in {"2.5", "2.6"}:
                    association = result.get(capture_for_version(spec["schema_version"]).name + "_capture")
                    result["checkpoint"].update(session_policy="fresh", requested_session_id=None,
                        observed_session_id=result.get("session_id"),
                        capture_digest=association["digest"] if association else None)
                elif spec["schema_version"] in {"2.3", "2.4"}:
                    result["checkpoint"].update(requested_session_id=packet["session_id"], observed_session_id=result.get("session_id"))
                else:
                    result["checkpoint"]["thread_id"] = result.get("thread_id")
            except TaskAlongError:
                result["checkpoint"] = None
            if spec["schema_version"] == "2.7" and result["checkpoint"] is not None:
                from .steps import delta
                try:
                    delta(snapshot["manifest"], stopped_snapshot["manifest"], spec["steps"][attempt["step_index"]]["scope"])
                except TaskAlongError:
                    # A settled failure cannot make an illegal partial edit a
                    # reusable retry checkpoint.
                    result["checkpoint"] = None
                    raise
            if result["state"] == "completed":
                if spec["schema_version"] in {"2.5", "2.6"}:
                    validate_versioned("worker-result", worker, expected_version="2.5")
                elif spec["schema_version"] in {"2.3", "2.4"}:
                    validate_versioned("worker-result", worker, expected_version="2.3")
                    expected = {key:packet["bindings"][key] for key in ("driver_config_digest", "provider_profile_digest")}
                    expected["session_id"] = packet["session_id"]
                    if any(worker[key] != value for key,value in expected.items()):
                        raise TaskAlongError("worker_binding_mismatch", "The worker result names another driver context.", exit_code=3)
                else:
                    validate("worker-result", worker)
                for name in ("run_id", "attempt_id", "spec_digest", "packet_id"):
                    if worker[name] != packet[name]:
                        raise TaskAlongError("worker_binding_mismatch", "Worker result belongs to different immutable inputs.", exit_code=3)
                if worker["packet_digest"] != packet["digest"] or worker["qualification"] != run["qualification"] or worker["status"] != "completed" or worker["blockers"] or worker["deviations"]:
                    raise TaskAlongError("worker_handoff_blocked", "Worker handoff is incomplete or disagrees with the packet.", exit_code=3)
                actual = manager.snapshot(workspace, spec["scope"], expected_head=spec["repository"]["base_commit"])
                actual_changes = actual["changed_files"]
                if spec["schema_version"] == "2.7":
                    from .steps import delta
                    actual_changes = delta(snapshot["manifest"], actual["manifest"], spec["steps"][attempt["step_index"]]["scope"])
                if sorted(worker["changed_files"], key=lambda x: x["path"]) != sorted(actual_changes, key=lambda x: x["path"]):
                    raise TaskAlongError("worker_scope_claim_mismatch", "Actual changed files disagree with the worker's claim.", exit_code=3)
            _finish_attempt(store, run_id, attempt_id, result, worker)
            finished = store.run(run_id)
            if finished["state"] == "verifying":
                workflow.verify(run_id, operation_key="supervisor-verify:" + attempt_id, expected_revision=finished["revision"])
        except TaskAlongError as exc:
            if "result" in locals() and store.run(run_id)["active_attempt_id"] == attempt_id:
                result.update(state="failed", error=exc.code)
                _finish_attempt(store, run_id, attempt_id, result, None)
                if spec["schema_version"] in {"2.5", "2.6", "2.7", "2.9"}:
                    # The fenced finish already recorded the exact failure.
                    # A later generic blocker could overwrite a new restart
                    # admitted after that durable, settled state became visible.
                    return
            if spec["schema_version"] in {"2.5", "2.6", "2.9"} and "result" in locals():
                confirmed = (result.get("process") or {}).get("termination_confirmed") is True
                _block(store, run_id, exc.code, phase="running", uncertain=not confirmed,
                       effect_outcome="known" if confirmed else "uncertain")
            else:
                _block(store, run_id, exc.code, phase="running", uncertain=exc.effect_outcome == "uncertain")
        except Exception:
            _block(store, run_id, "supervisor_internal_failure", phase="running", uncertain=True)


def _finish_attempt(store, run_id, attempt_id, result, worker, *, execution_handoff=None):
    run = store.run(run_id)
    process = result.get("process", {})
    ordered = store.spec(run)["schema_version"] == "2.7"
    receipt_digest = None
    if ordered:
        item = store.detail("attempts", attempt_id)
        if run["active_attempt_id"] != attempt_id or item["lease_generation"] != run["lease_generation"]:
            raise TaskAlongError("lease_fenced", "Only the active ordered attempt can finish.", exit_code=4)
        if result["state"] == "completed" and process.get("termination_confirmed") and run["state"] != "cancel_pending":
            from .steps import completed_receipt, validate_chain
            validate_chain(store, run)
            receipt_digest = completed_receipt(store, run, item, result, worker)
    artifact = store.put_blob(canonical_bytes(worker)) if worker else None
    capture = capture_for_version(store.spec(run)["schema_version"])
    association = result.get(capture.name + "_capture") if capture and result["state"] == "completed" else None
    request = {"state": result["state"], "artifact": artifact}
    muse = store.spec(run)["schema_version"] == "2.9"
    muse_ref = store.put_blob(canonical_bytes(execution_handoff)) if execution_handoff is not None else None
    if muse:
        request["execution_handoff"] = muse_ref
    if capture:
        request[capture.name + "_capture_digest"] = association["digest"] if association else None
    terminal_events = []
    def finish(current, db):
        item = store.detail("attempts", attempt_id)
        if ordered and (current["active_attempt_id"] != attempt_id or item["lease_generation"] != current["lease_generation"]):
            raise TaskAlongError("lease_fenced", "A stale ordered result cannot replace a newer step.", exit_code=4)
        if muse:
            if current["active_attempt_id"] != attempt_id or item["lease_generation"] != current["lease_generation"]:
                raise TaskAlongError("lease_fenced", "Only the active fenced Muse attempt may finish.", exit_code=4)
            if result["state"] == "completed":
                from .muse_handoff import validate_handoff
                validate_handoff(store, current, store.spec(current), item, Workflow(store)._manager(current),
                    store.lease(current)["workspace"], before_finish=True, handoff=execution_handoff)
            item["execution_handoff"] = muse_ref
        if capture:
            if current["active_attempt_id"] != attempt_id or item["lease_generation"] != current["lease_generation"]:
                raise TaskAlongError("lease_fenced", "Only the exact active observed-session attempt can finish.", exit_code=4)
            if result["state"] == "completed":
                if association is None or association["result_artifact"] != artifact:
                    raise TaskAlongError(capture.error_prefix + "_capture_invalid", "A completed observed-session handoff requires its exact private capture.", exit_code=70)
                session = association["observation"]["observed_session_id"]
                for prior in current["attempts"][:-1]:
                    previous = store.detail("attempts", prior["attempt_id"])
                    if (previous.get("checkpoint") or {}).get("observed_session_id") == session:
                        raise TaskAlongError(capture.error_prefix + "_session_reused", "A fresh attempt cannot reuse a known prior native session.", exit_code=3)
        confirmed = bool(process.get("termination_confirmed"))
        item.update(status=result["state"], termination_confirmed=confirmed, thread_id=result.get("thread_id"), finished_at=now(), result_artifact=artifact, process=process, checkpoint=result.get("checkpoint"), error=result.get("error"))
        if "driver_config_digest" in item:
            item["driver_report"] = {"reported_session_id":result.get("session_id"),
                "reported_usage":result.get("reported_usage"), "diagnostics":result.get("diagnostics")}
        if capture:
            item[capture.name + "_raw_capture"] = result.get(capture.name + "_raw_capture")
            item[capture.name + "_capture"] = association
        db.execute("UPDATE attempts SET active=?,document=? WHERE attempt_id=?", (0 if confirmed else 1, encode(item), attempt_id))
        current["attempts"][-1]["status"] = result["state"]
        if confirmed:
            current["active_attempt_id"] = None
        if current["state"] == "cancel_pending" and confirmed:
            current["state"] = "cancelled"
        elif result["state"] == "completed" and confirmed:
            current["state"] = "verifying"
        elif result["state"] == "cancelled" and confirmed:
            current["state"] = "cancelled"
        else:
            current["state"] = "blocked"
            current["blocked_from"] = "running"
            current["blockers"] = [{"code": result.get("error") or "executor_incomplete", "effect_outcome": "known" if confirmed else "uncertain", "message": "Inspect the stopped attempt before continuation.", "recovery": [{"action": "reconcile"}]}]
        if ordered:
            state = current["steps"][item["step_index"]]
            state["status"] = "cancelled" if current["state"] == "cancelled" else "completed" if receipt_digest else "failed"
            state["receipt_digest"] = receipt_digest
            if receipt_digest:
                current["blockers"], current["blocked_from"] = [], None
                if all(s["status"] == "completed" for s in current["steps"]):
                    current["execution_chain_digest"] = digest({"spec_digest":current["spec_digest"], "step_receipts":[s["receipt_digest"] for s in current["steps"]]})
                else:
                    current["state"] = "ready"
        for effect_id in list(current["pending_effect_ids"]):
            effect = store.detail("effects", effect_id)
            if effect["kind"] == "executor.start":
                effect.update(phase="observed" if confirmed else "unknown", response={"state": result["state"], "termination_confirmed": confirmed})
                db.execute("UPDATE effects SET phase=?,document=? WHERE effect_id=?", (effect["phase"], encode(effect), effect_id))
                if confirmed:
                    current["pending_effect_ids"].remove(effect_id)
        current["budget_consumed"]["output_bytes"] += process.get("output_bytes", 0)
        usage = result.get("usage", {})
        for name in ("input_tokens", "output_tokens"):
            value, previous = usage.get(name), current["budget_consumed"][name]
            # Null after an earlier attempt means an incomplete aggregate, not
            # zero. Never relabel a later known report as a complete run total.
            if value is None or (previous is None and len(current["attempts"]) > 1):
                current["budget_consumed"][name] = None
            else:
                total = (previous or 0) + value
                current["budget_consumed"][name] = total if total <= 9007199254740991 else None
        # The selected runtime does not report measured provider cost.
        current["budget_consumed"]["cost_usd"] = None
        event = "cancel.confirmed" if current["state"] == "cancelled" and confirmed else "executor.completed" if result["state"] == "completed" else "executor.failed"
        terminal_events.append((event, {"attempt_id": attempt_id, "termination_confirmed": confirmed,
                                      **({"local_cessation": True} if event == "cancel.confirmed" else {})}))
    return store.mutate(run_id, "executor.finish", attempt_id, None, request, finish, events=terminal_events, fence=run["lease_generation"])
