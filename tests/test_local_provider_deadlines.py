"""Explicit long deadlines without extending historical claims or raw budgets."""
from copy import deepcopy
from contextlib import redirect_stdout
import io
import json
import time
import unittest
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong import muse_experimental as muse
from taskalong import local_provider_runtime as owner
from taskalong.local_provider_contract import ProviderLimits
from taskalong.validation import canonical_bytes, digest
import test_muse_experimental as experimental_tests


class LongDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.fixture = experimental_tests.ExperimentalMuseTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_new_muse_profile_accepts1440_and_preserves_smaller_output_limits(self):
        f = self.fixture
        f.configure(capture_profile="implementation")
        old = f.service._store.setting("provider:muse")
        old_bytes = canonical_bytes(old)
        f.configure(capture_profile="large-task", attempt_seconds=1440,
                    max_output_bytes=1048576,max_proposal_bytes=12288,max_protocol_records=2048)
        config = f.service._store.setting("provider:muse")
        self.assertEqual(config["format"],"local-muse-provider/5")
        self.assertEqual(config["attempt_seconds"],1440)
        self.assertEqual((config["max_output_bytes"],config["max_proposal_bytes"],muse._max_records(config)),(1048576,12288,2048))
        self.assertEqual(canonical_bytes(f.service._store.setting("provider-config:"+old["digest"])),old_bytes)
        self.assertEqual(muse._checked_configuration(old),old)
        changed=deepcopy(old);changed["attempt_seconds"]=1440;changed["digest"]=digest(changed)
        with self.assertRaises(TaskAlongError):muse._checked_configuration(changed)

    def test_muse_shorter_explicit_deadline_default_and_strict_finite_ceiling(self):
        f=self.fixture
        for seconds in (1,60,720,721,1440):
            f.configure(capture_profile="large-task",attempt_seconds=seconds)
            self.assertEqual(f.service._store.setting("provider:muse")["attempt_seconds"],seconds)
        f.configure(capture_profile="large-task")
        self.assertEqual(f.service._store.setting("provider:muse")["attempt_seconds"],1440)
        f.configure()
        self.assertEqual(f.service._store.setting("provider:muse")["attempt_seconds"],20)
        for seconds in (0,True,1441,1440.0,float("inf")):
            with self.subTest(seconds=seconds),self.assertRaises(TaskAlongError):
                f.configure(capture_profile="large-task",attempt_seconds=seconds)
        for key,value in (("max_output_bytes",4194305),("max_proposal_bytes",65537),("max_protocol_records",8193)):
            with self.subTest(key=key),self.assertRaises(TaskAlongError):
                f.configure(capture_profile="large-task",**{key:value})

    def test_legacy_profiles_and_fixed_implementation_cohort_do_not_grow(self):
        f=self.fixture
        for profile in (None,"implementation"):
            with self.assertRaises(TaskAlongError):
                f.configure(attempt_seconds=1440,**({"capture_profile":profile} if profile else {}))
        self.assertEqual(ProviderLimits().attempt_seconds,720)
        self.assertEqual(ProviderLimits(attempt_seconds=1440).max_output_bytes,4194304)
        with self.assertRaises(TaskAlongError):ProviderLimits(attempt_seconds=1441)

    def test_long_muse_cancel_remains_one_claim_and_never_restarts(self):
        f=self.fixture
        f.configure(capture_profile="large-task",attempt_seconds=1440,
                    max_output_bytes=1048576,max_proposal_bytes=12288,max_protocol_records=2048)
        original=f.process
        def cancelled(argv,**options):
            result=original(argv,**options)
            options["_on_output_chunk"]("stdout",result.stdout)
            result.cancelled=True
            summary=result.to_dict() | {"cancelled":True}
            result.to_dict=lambda:summary
            self.assertEqual(options["timeout_seconds"],1440)
            return result
        with patch.object(muse.sys,"platform","darwin"),patch.object(muse,"_preflight",return_value={}), \
             patch.object(muse,"run_foreground_experiment",side_effect=cancelled):
            record=f.service.run_provider("muse",bundle=str(f.bundle),output=str(f.root/"long"))
        self.assertEqual(record["state"],"failed")
        before=canonical_bytes(record)
        with patch.object(muse.sys,"platform","darwin"),patch.object(muse,"run_foreground_experiment") as dispatch:
            with self.assertRaises(TaskAlongError):
                f.service.run_provider("muse",bundle=str(f.bundle),output=str(f.root/"do-not-restart"))
            dispatch.assert_not_called()
        self.assertEqual(canonical_bytes(f.service.result(record["run_id"])),before)
        self.assertEqual(record["controller_submissions"],1)
        self.assertEqual(record["remote_usage"],"unknown")
        self.assertEqual(record["process"]["protocol_record_limit"],2048)

    def test_shared_owner_consumes1440_and_expired_deadline_never_launches(self):
        limits=ProviderLimits(attempt_seconds=1440).to_dict()
        prepared={"remaining_budget":limits,"absolute_deadline":int(time.time()*1000)+1440000,"workspace":"/synthetic/work"}
        invocation={"argv":["/synthetic/native"],"stdin":b"public","env_overrides":{}}
        from types import SimpleNamespace
        result=SimpleNamespace(output_bytes=0,to_dict=lambda:{"root_exit_code":0,"stdout":"","stderr":"","tracking_errors":(),"boundary_failures":()})
        with patch.object(owner.sys,"platform","darwin"),patch("taskalong.experimental_process.run_foreground_experiment",return_value=result) as run:
            owner._process({},prepared,invocation,output_chunk=lambda *_:None,cancelled=lambda:False,spawned=lambda _:None)
            self.assertGreater(run.call_args.kwargs["timeout_seconds"],1439)
            self.assertLessEqual(run.call_args.kwargs["timeout_seconds"],1440)
        prepared["absolute_deadline"]=int(time.time()*1000)-1
        with patch("taskalong.experimental_process.run_foreground_experiment") as run:
            with self.assertRaises(TaskAlongError):
                owner._process({},prepared,invocation,output_chunk=lambda *_:None,cancelled=lambda:False,spawned=lambda _:None)
            run.assert_not_called()

    def test_cli_budget_reports1440_and_preserved_caps_without_native_call(self):
        from taskalong.cli import main
        f=self.fixture
        f.configure(capture_profile="large-task",attempt_seconds=1440,
                    max_output_bytes=1048576,max_proposal_bytes=12288,max_protocol_records=2048)
        request=f.root/"request.json"
        request.write_text(json.dumps(f.manifest["request"]))
        output=io.StringIO()
        with patch.object(muse,"run_foreground_experiment") as native,redirect_stdout(output):
            code=main(["--state-dir",str(f.root/"state"),"--json","provider-budget","muse","--request",str(request)])
        self.assertEqual(code,0)
        data=json.loads(output.getvalue())["data"]
        self.assertEqual((data["attempt_seconds"],data["max_output_bytes"],data["max_proposal_bytes"],data["max_protocol_records"]),
                         (1440,1048576,12288,2048))
        self.assertEqual(data["controller_submissions"],0)
        native.assert_not_called()
