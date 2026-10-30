"""Model-free probe contract tests; mocked frames never qualify a provider."""
import contextlib
import copy
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
from taskalong import muse_mac_probe as probe
from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes


def frame(home='/isolated/data/muse',**changes):
    result={'serverInfo':{'name':'muse','version':'1.4.10'},'platformFamily':'unix','platformOs':'macos',
        'schema':{'version':1,'fingerprint':probe.SCHEMA_FINGERPRINT},'grantedCapabilities':[],
        'experimentalApi':False,'museHome':home,'sandboxAvailability':'available',**changes}
    return canonical_bytes({'jsonrpc':'2.0','id':1,'result':result})+b'\n'


class MuseMacProbeTests(unittest.TestCase):
    def test_fixed_request_and_argv_have_no_sessions_turns_or_grants(self):
        self.assertEqual(probe.ARGV,('serve','--provider','echo','--disable-write','--disable-shell'))
        self.assertEqual(probe.REQUEST['method'],'initialize')
        self.assertEqual(probe.REQUEST['params']['capabilities']['requestedCapabilities'],[])

    def test_available_unavailable_are_observations_never_enforcement_or_admission(self):
        for status in ('available','unavailable'):
            v=probe.decode(frame(sandboxAvailability=status))
            self.assertEqual(v['host_reports_sandbox'],status)
            for key in ('production_dispatch_allowed','acceptance_allowed','shell_write_network_enforcement_demonstrated'):
                self.assertFalse(v[key])

    def test_grants_identity_unknown_states_and_numeric_flags_refuse(self):
        cases=[{'grantedCapabilities':['userShell']},{'experimentalApi':0},{'platformOs':'linux'},
            {'schema':{'version':True,'fingerprint':probe.SCHEMA_FINGERPRINT}},
            {'serverInfo':{'name':'muse','version':'other'}},{'sandboxAvailability':'maybe'}]
        for changed in cases:
            with self.subTest(changed=changed),self.assertRaises(TaskAlongError):probe.decode(frame(**changed))

    def test_empty_duplicate_extra_and_malformed_frames_refuse(self):
        for raw in (b'',b'[]',b'{"id":1,"id":1}',frame()+frame(),b'x'*131073):
            with self.assertRaises(TaskAlongError):probe.decode(raw)

    def setUp(self):
        self.temporary=self.enterContext(tempfile.TemporaryDirectory());self.root=Path(self.temporary).resolve()/'evidence'
        self.identity={'path':'/fixed/native','sha256':probe.BINARY_SHA256,'bytes':1,'mode':448}

    def result(self,home=None,**changed):
        raw=frame(home=str(self.root/'data/muse') if home is None else home)
        payload={'stdout':'original mocked public metadata','stderr':'','fork_observed':True,
            'termination_confirmed':False,'descendant_cessation':'unknown','tracking_errors':(),'boundary_failures':(),'root_exit_observed':True,'group_termination_confirmed':True}
        return SimpleNamespace(stdout=raw,stderr=b'',root_exit_code=0,timed_out=False,
            output_limited=False,failure_code=None,to_dict=lambda:dict(payload),**changed)

    def invoke(self,result):
        with patch.object(probe.sys,'platform','darwin'),patch.object(probe,'_observe_file',return_value=self.identity),\
             patch.object(probe,'run_foreground_experiment',return_value=result) as run:
            report=probe.probe(executable='/fixed/native',evidence_dir=str(self.root))
        return report,run

    def test_fresh_evidence_context_and_fixed_transport_are_retained(self):
        report,run=self.invoke(self.result());args,kwargs=run.call_args
        self.assertEqual(args[0],['/fixed/native',*probe.ARGV])
        self.assertEqual(json.loads(kwargs['stdin']),probe.REQUEST)
        self.assertEqual(kwargs['timeout_seconds'],5);self.assertEqual(kwargs['max_output_bytes'],131072)
        self.assertEqual(kwargs['env']['HOME'],str(self.root/'home'))
        self.assertNotIn('META_API_KEY',kwargs['env']);self.assertFalse(report['production_dispatch_allowed'])
        self.assertEqual(report['process']['descendant_cessation'],'unknown')
        self.assertEqual(report['process']['tracking_errors'],[]);self.assertEqual(report['process']['boundary_failures'],[])
        for name in ('stdout.bin','stderr.bin','process.json','report.json'):
            self.assertEqual((self.root/name).stat().st_mode&0o777,0o600)

    def test_existing_directory_binary_and_platform_refuse_before_launch(self):
        self.root.mkdir(mode=0o700)
        with patch.object(probe.sys,'platform','darwin'),patch.object(probe,'_observe_file',return_value=self.identity),\
             patch.object(probe,'run_foreground_experiment') as run:
            with self.assertRaises(TaskAlongError) as e:probe.probe(executable='/fixed/native',evidence_dir=str(self.root))
            self.assertEqual(e.exception.code,'muse_probe_evidence_exists');run.assert_not_called()
        with patch.object(probe.sys,'platform','win32'),patch.object(probe,'_observe_file') as observe:
            with self.assertRaises(TaskAlongError):probe.probe(executable='/fixed/native',evidence_dir=str(self.root))
            observe.assert_not_called()
        with patch.object(probe.sys,'platform','darwin'),patch.object(probe,'_observe_file',return_value=self.identity|{'sha256':'a'*64}),\
             patch.object(probe,'run_foreground_experiment') as run:
            with self.assertRaises(TaskAlongError):probe.probe(executable='/fixed/native',evidence_dir=str(self.root))
            run.assert_not_called()

    def test_unknown_group_or_tracking_failure_refuses_and_retains_capture(self):
        for index,change in enumerate(({'group_termination_confirmed':False},{'tracking_errors':('kernel_event',)})):
            self.root=Path(self.temporary).resolve()/('incomplete-'+str(index))
            result=self.result();payload=result.to_dict();payload.update(change);result.to_dict=lambda:dict(payload)
            with self.subTest(change=change),self.assertRaises(TaskAlongError) as e:self.invoke(result)
            self.assertEqual(e.exception.code,'muse_probe_incomplete');self.assertEqual(e.exception.effect_outcome,'uncertain')
            self.assertTrue((self.root/'process.json').exists());self.assertFalse((self.root/'report.json').exists())

    def test_context_drift_retains_original_process_and_refuses_without_retry(self):
        with self.assertRaises(TaskAlongError) as e:self.invoke(self.result(home='/foreign/context'))
        self.assertEqual(e.exception.code,'muse_probe_context_changed');self.assertEqual(e.exception.effect_outcome,'uncertain')
        self.assertTrue((self.root/'process.json').exists());self.assertFalse((self.root/'report.json').exists())

    def test_io_failure_after_observation_never_claims_durable_success(self):
        original=probe._write
        def fail(root,name,raw):
            if name=='report.json':raise OSError('original test persistence fault')
            return original(root,name,raw)
        with patch.object(probe,'_write',side_effect=fail),self.assertRaises(TaskAlongError) as e:self.invoke(self.result())
        self.assertEqual(e.exception.effect_outcome,'uncertain');self.assertFalse((self.root/'report.json').exists())

    def test_cli_diagnostic_opens_no_store(self):
        from taskalong.cli import main
        with patch.object(probe,'probe',return_value={'production_dispatch_allowed':False}),\
             patch('taskalong.api.RunService',side_effect=AssertionError('must not open Store')),\
             contextlib.redirect_stdout(io.StringIO()) as out:
            code=main(['--json','muse-mac-probe','--executable','/fixed/native','--evidence-dir',str(self.root)])
        self.assertEqual(code,0);self.assertFalse(json.loads(out.getvalue())['data']['production_dispatch_allowed'])
