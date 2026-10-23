"""The provider-neutral local facade used by CLI and orchestrators."""
from __future__ import annotations

import os
from pathlib import Path
import shutil

from .errors import TaskAlongError
from .paths import default_state_dir
from .store import Store, identifier
from .validation import canonical_bytes
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

    def start(self, run_id, *, operation_key, expected_revision, authority_id=None):
        return self._workflow.start(run_id, operation_key=operation_key, expected_revision=expected_revision, authority_id=authority_id)

    def inspect(self, run_id):
        return self._store.run(run_id)

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
