"""Shared durable-driver contract; each driver supplies an explicit fixture.

Add future qualified driver fixture classes to this runner. Binary discovery
does not add a case or a registry entry. These cases prove synthetic protocol
behavior only, never vendor runtime isolation or provider cancellation.
"""
import unittest

from taskalong.errors import TaskAlongError
from taskalong.validation import seal_versioned
from test_execution_bindings import BindingFixture


class DurableDriverContract:
    def configured_task(self):
        self.service.configure_execution(**self.configuration)
        return self.submit(self.task)[0]

    def test_start_observe_and_result_keep_worker_and_acceptance_separate(self):
        run = self.configured_task()
        self.start(run)
        stopped = self.wait(run["run_id"])
        self.assertEqual(len(self.invocations()), 1)
        self.assertEqual(len(stopped["attempts"]), 1)
        view = self.service.result(run["run_id"])
        self.assertEqual(view["outcome"], "worker_completed")
        self.assertFalse(view["independently_accepted"])
        self.assertFalse(view["production_dispatch_allowed"])

    def test_cancel_owned_worker_prevents_acceptance(self):
        self.barrier_file.touch()
        run = self.configured_task()
        self.start(run)
        running = self.wait(run["run_id"], states=("running",))
        # A durable process receipt precedes gate release; prove the target
        # actually began before exercising cancellation of a running fixture.
        running = self.wait(run["run_id"], predicate=lambda observed: bool(self.invocations()))
        self.service.cancel(run["run_id"], operation_key="contract-cancel", expected_revision=running["revision"])
        stopped = self.wait(run["run_id"])
        self.assertEqual(stopped["state"], "cancelled")
        self.assertEqual(len(self.invocations()), 1)
        self.assertIsNone(stopped["acceptance_id"])
        self.assertEqual(stopped["evidence_ids"], [])
        self.assertEqual(self.service.result(run["run_id"])["outcome"], "cancelled")

    def test_cancel_before_owned_gate_release_is_acknowledged_without_dispatch(self):
        from test_recovery_regressions import RecoveryRegressions
        run = self.configured_task()
        environment, marker, release = RecoveryRegressions.trace_environment(self, "on_spawn", mode="pause")
        # Trusted test-only trace: retain allowlisted boundary observations
        # before an adapter can discard its exception's actual cleanup result.
        trace_path = marker.parent / "sitecustomize.py"
        boundary_receipt = marker.parent / "boundary.json"
        capture = """import json
observed_signals=[]
def capture_boundary(frame,event,arg):
    name=frame.f_code.co_name
    if not frame.f_code.co_filename.replace('\\\\','/').endswith('/taskalong/process.py'): return None
    if name=='_signal_owned' and event=='call':
        parent=frame.f_back
        start=parent.f_locals.get('started') if parent else None
        if len(observed_signals)<8:
            observed_signals.append({'signal':int(frame.f_locals['sig']),
                'elapsed_ms':int((time.monotonic()-start)*1000) if start is not None else None})
    if name=='run_bounded' and event=='exception' and getattr(arg[1],'process_result',None) is not None:
        values=frame.f_locals; result=arg[1].process_result
        tracker=values.get('tracker'); process=values.get('process'); callback=values.get('callback_error')
        known={'cancel_pending','qualification_unsatisfied','admission_changed','attempt_deadline_exhausted','authority_missing','runtime_changed'}
        code=getattr(callback,'code',None)
        document={'kind':'synthetic_owned_boundary_diagnostic','callback_code':code if code in known else 'other_or_unknown',
            'effect_outcome':getattr(arg[1],'effect_outcome',None),
            'release_attempted':values.get('gate_release_attempted'),
            'ready':getattr(tracker,'ready',None),'dispatch_state':getattr(tracker,'dispatch_state',None),
            'eof':getattr(tracker,'eof',None),'tracker_failed':getattr(tracker,'failed',None),
            'buffered_status_bytes':len(getattr(tracker,'buffer',b'')),
            'status_bytes_seen':getattr(tracker,'bytes_seen',None),'tracker_active':bool(getattr(tracker,'active',True)),
            'wrapper_returncode':getattr(process,'returncode',None),
            'root_exit_code':getattr(tracker,'root_exit_code',None),
            'signal_stage':values.get('signal_stage'),
            'forced_wrapper_stop':values.get('forced_wrapper_stop_at') is not None,
            'signals':observed_signals,'termination_confirmed':result.termination_confirmed,
            'group_termination_confirmed':result.group_termination_confirmed,
            'unaccounted_descendants':result.unaccounted_descendants}
        data=json.dumps(document).encode()
        try:
            fd=os.open(BOUNDARY_RECEIPT,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
            with os.fdopen(fd,'wb') as stream:stream.write(data)
        except OSError:pass
    return capture_boundary if name in {'run_bounded','_signal_owned'} else None
"""
        original_trace = trace_path.read_text()
        setup = "    parent=frame.f_back\n    while parent is not None:\n        if parent.f_code.co_name=='run_bounded':parent.f_trace=capture_boundary\n        parent=parent.f_back\n    sys.settrace(capture_boundary)\n    return None\n"
        original_trace = original_trace.replace("    return None\n", setup)
        header = "BOUNDARY_RECEIPT=" + repr(str(boundary_receipt)) + "\n"
        trace_path.write_text(original_trace.replace("def observe(frame,event,arg):", header + capture + "\ndef observe(frame,event,arg):"))
        client = RecoveryRegressions.cli_start(self, run, "contract-gate", environment=environment)
        self.assertEqual(client.returncode, 0, client.stderr)
        try:
            RecoveryRegressions.wait_file(self, marker)
            before = self.service.inspect(run["run_id"])
            self.service.cancel(run["run_id"], operation_key="contract-gate-cancel", expected_revision=before["revision"])
        finally:
            release.touch()
        stopped = self.wait(run["run_id"])
        attempt = self.service._store.detail("attempts", stopped["attempts"][-1]["attempt_id"])
        process = attempt.get("process") or {}
        diagnostic = {"blocker_codes":[item["code"] for item in stopped["blockers"]],
            "attempt_status":attempt["status"], "attempt_error":attempt.get("error"),
            "process":{key:process.get(key) for key in ("termination_confirmed", "group_termination_confirmed",
                       "unaccounted_descendants", "exit_code", "lifetime_backend", "protocol_error")}}
        if boundary_receipt.exists() and boundary_receipt.stat().st_size <= 16384:
            import json
            try:
                diagnostic["owned_boundary"] = json.loads(boundary_receipt.read_bytes())
            except (OSError, ValueError):
                diagnostic["owned_boundary"] = "unavailable"
        else:
            diagnostic["owned_boundary"] = "unobserved"
        self._closed_gate_diagnostic = diagnostic
        self.assertEqual(stopped["state"], "cancelled", diagnostic)
        self.assertIsInstance(diagnostic["owned_boundary"], dict, diagnostic)
        self.assertEqual(diagnostic["owned_boundary"]["callback_code"], "cancel_pending")
        self.assertFalse(diagnostic["owned_boundary"]["release_attempted"])
        self.assertTrue(diagnostic["owned_boundary"]["termination_confirmed"])
        self.assertIsNone(stopped["active_attempt_id"])
        self.assertEqual(stopped["pending_effect_ids"], [])
        self.assertEqual(self.invocations(), [])
        self.assertIsNone(stopped["acceptance_id"])
        self.assertEqual(sum(event["type"] == "cancel.confirmed" for event in self.service.events(run["run_id"])), 1)

    def test_unsupported_native_resume_never_restarts(self):
        run = self.configured_task()
        with self.assertRaises(TaskAlongError) as failure:
            self.service.resume(run["run_id"], mode="native", operation_key="contract-native", expected_revision=run["revision"])
        self.assertEqual(failure.exception.code, "native_resume_unsupported")
        self.assertEqual(self.invocations(), [])
        self.assertEqual(self.service.inspect(run["run_id"])["attempts"], [])

    def test_production_task_cannot_use_fixture_qualification(self):
        self.service.configure_execution(**self.configuration)
        task = seal_versioned("task-spec", self.task | {"qualification":"production"}, version=self.task["schema_version"])
        with self.assertRaises(TaskAlongError) as failure:
            self.service.submit(task, operation_key="contract-production")
        self.assertEqual(failure.exception.code, "execution_identity_mismatch")
        self.assertEqual(self.invocations(), [])


class CodexFixtureContractTests(DurableDriverContract, BindingFixture, unittest.TestCase):
    """Only the explicitly registered fake Codex wire protocol is admitted."""


if __name__ == "__main__":
    unittest.main()
