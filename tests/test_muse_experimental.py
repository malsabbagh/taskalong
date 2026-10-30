"""Configured provider integration with synthetic process fixtures; no inference."""
import contextlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from taskalong.api import RunService
from taskalong import muse_experimental as muse
from taskalong import supervised_pilot as pilot
from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes, validate


def request(model='muse-wonder-full-1.0'):
    return {'base_commit':'a'*40,'task':'Change greeting.','provider':'muse','model':model,'reasoning_effort':'high','files':{'greeting.txt':'hello\n'}}


def native_output(session,response,*,terminal='completed',run='11111111-1111-4111-8111-111111111111'):
    base={'schema_version':1,'stream':{'kind':'session','id':session}}
    rows=[base|{'sequence':1,'payload_type':'session.run.linked','payload':{'kind':'session_run_linked','run_stream':{'kind':'run','id':run}}},
          base|{'sequence':2,'payload_type':'run.terminal.'+terminal,'payload':{'kind':'run_terminal','run_stream':{'kind':'run','id':run},'terminal':terminal,'text':response}}]
    return b''.join(canonical_bytes(v)+b'\n' for v in rows)


@unittest.skipUnless(os.name=='posix','Private descriptor staging requires POSIX')
class ExperimentalMuseTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.binary=self.root/'native';self.binary.write_text('Original synthetic executable fixture.\n');self.binary.chmod(0o700)
        self.home=self.root/'home';self.home.mkdir();self.data=self.root/'data/muse';self.data.mkdir(parents=True)
        self.service=self.enterContext(RunService(self.root/'state'))
        self.bundle=self.root/'bundle';pilot.prepare(request(),output=str(self.bundle))
        _,self.manifest=pilot._bundle(str(self.bundle))
        self.calls=[]

    def configure(self,**values):
        return self.service.configure_provider('muse',{'executable':str(self.binary),'account_home':str(self.home),'muse_home':str(self.data),**values})

    def process(self,argv,**options):
        self.calls.append((argv,options))
        session=argv[argv.index('--session-id')+1]
        response={'bundle_digest':self.manifest['digest'],'changes':{'greeting.txt':'hello world\n'}}
        raw=native_output(session,json.dumps(response))
        receipt=SimpleNamespace(to_dict=lambda:{'pid':123,'executable_sha256':'fixture','invocation_id':'synthetic'})
        if options.get('on_spawn'):options['on_spawn'](receipt)
        summary={'root_exit_code':0,'root_exit_observed':True,'group_termination_confirmed':True,'fork_observed':True,
                 'descendant_cessation':'unknown','termination_confirmed':False,'tracking_errors':[],'boundary_failures':[],
                 'stdout':'fixture','stderr':'','output_bytes':len(raw),'timed_out':False,'cancelled':False,'output_limited':False}
        return SimpleNamespace(stdout=raw,stderr=b'',root_exit_code=0,timed_out=False,cancelled=False,output_limited=False,to_dict=lambda:summary)

    def run_fixture(self):
        with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'_preflight',return_value={'context':'include','catalog_entries':0}),\
             patch.object(muse,'run_foreground_experiment',side_effect=self.process),\
             patch.object(muse,'_journal',return_value=([],[{}],{'provider_id':'meta','model_id':'muse-wonder-full-1.0'})):
            return self.service.run_provider('muse',bundle=str(self.bundle),output=str(self.root/'output'))

    def test_configuration_alone_enables_normal_run_without_activation_or_qualification(self):
        config=self.configure();self.assertFalse(config['activation_required']);self.assertEqual(config['context'],'include')
        self.assertTrue(self.service.providers()['providers'][0]['configured'])
        result=self.run_fixture()
        self.assertEqual(result['state'],'proposal_ready');self.assertTrue(Path(result['proposal_path']).exists())
        self.assertFalse(result['patch_applied']);self.assertFalse(result['acceptance_allowed']);self.assertFalse(result['production_dispatch_allowed'])
        self.assertEqual(result['remote_usage'],'unknown');self.assertEqual(result['descendant_cessation'],'unknown')
        self.assertEqual(result['native_internal_retries'],'unknown');self.assertEqual(result['controller_submissions'],1)
        self.assertEqual(self.service.inspect(result['run_id']),result);self.assertEqual(self.service.result(result['run_id']),result)

    def test_live_call_has_fixed_provider_model_bounds_and_minimal_environment(self):
        self.configure();self.run_fixture();self.assertEqual(len(self.calls),1)
        argv,options=self.calls[0]
        self.assertEqual(argv[argv.index('--provider')+1],'meta');self.assertEqual(argv[argv.index('--model')+1],'muse-wonder-full-1.0')
        self.assertNotIn('--no-foreign-personal-context',argv)
        for flag in ('--disable-write','--disable-shell','--disable-web-tools','--disable-reminders','--no-parallel-tool-calls'):
            self.assertIn(flag,argv)
        self.assertEqual(options['timeout_seconds'],20);self.assertEqual(options['max_output_bytes'],65536)
        self.assertEqual(options['env']['HOME'],str(self.home));self.assertNotIn('GITHUB_TOKEN',options['env'])
        self.assertTrue((self.bundle/'provider-submission.json').exists())
        self.assertEqual((self.root/'output/prompt.txt').stat().st_mode&0o777,0o400)

    def test_repeated_bundle_refuses_without_another_provider_or_preflight_call(self):
        self.configure();self.run_fixture()
        with patch.object(muse,'_preflight') as preflight,patch.object(muse,'run_foreground_experiment') as owner,self.assertRaises(TaskAlongError) as exc:
            self.service.run_provider('muse',bundle=str(self.bundle),output=str(self.root/'second'))
        self.assertEqual(exc.exception.code,'provider_already_submitted');owner.assert_not_called();preflight.assert_not_called()
        self.assertFalse((self.root/'second').exists())

    def test_context_exclusion_is_honestly_unsupported_and_never_dispatches(self):
        self.configure(context='exclude')
        with patch.object(muse,'run_foreground_experiment') as owner,self.assertRaises(TaskAlongError) as exc:
            self.service.run_provider('muse',bundle=str(self.bundle),output=str(self.root/'output'))
        self.assertEqual(exc.exception.code,'provider_context_exclusion_unsupported');owner.assert_not_called()
        self.assertEqual(exc.exception.effect_outcome,'not_sent')

    def test_native_only_is_explicit_partial_exclusion(self):
        self.configure(context='native-only');self.run_fixture()
        self.assertIn('--no-foreign-personal-context',self.calls[0][0])

    def test_unconfigured_and_unknown_providers_fail_with_configuration_errors(self):
        with self.assertRaises(TaskAlongError) as exc:self.service.run_provider('muse',bundle=str(self.bundle))
        self.assertEqual(exc.exception.code,'provider_not_configured')
        with self.assertRaises(TaskAlongError) as exc:self.service.configure_provider('other',{})
        self.assertEqual(exc.exception.code,'provider_unavailable')

    def test_binary_or_model_changes_are_normal_validation_not_fallback(self):
        self.configure(model='another-model')
        with self.assertRaises(TaskAlongError) as exc:self.service.run_provider('muse',bundle=str(self.bundle))
        self.assertEqual(exc.exception.code,'provider_task_model_mismatch')
        self.configure();self.binary.write_text('changed fixture\n')
        with self.assertRaises(TaskAlongError) as exc:self.service.run_provider('muse',bundle=str(self.bundle))
        self.assertEqual(exc.exception.code,'provider_executable_changed')

    def test_secret_inputs_or_credential_config_fields_refuse_before_execution(self):
        with self.assertRaises(TaskAlongError):self.configure(api_key='fixture-only')
        self.configure()
        sensitive=request();sensitive['files']['greeting.txt']='password=abcdefghijk\n'
        with patch.object(muse,'run_foreground_experiment') as owner,self.assertRaises(TaskAlongError):
            self.service.run_provider('muse',request=sensitive,output=str(self.root/'output'))
        owner.assert_not_called()

    def test_failure_retains_one_use_claim_and_never_retries(self):
        self.configure()
        def failed(argv,**options):
            value=self.process(argv,**options);value.root_exit_code=1;return value
        with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'_preflight',return_value={}),patch.object(muse,'run_foreground_experiment',side_effect=failed):
            result=self.service.run_provider('muse',bundle=str(self.bundle),output=str(self.root/'output'))
        self.assertEqual(result['state'],'failed');self.assertEqual(result['remote_usage'],'unknown');self.assertEqual(len(self.calls),1)
        self.assertTrue((self.root/'output/stdout.bin').exists());self.assertTrue((self.bundle/'provider-submission.json').exists())
        with self.assertRaises(TaskAlongError):self.service.run_provider('muse',bundle=str(self.bundle),output=str(self.root/'retry'))

    def test_bad_response_is_retained_and_cannot_trigger_another_submission(self):
        self.configure()
        with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'_preflight',return_value={}),\
             patch.object(muse,'run_foreground_experiment',side_effect=self.process),patch.object(muse,'_decode',side_effect=TaskAlongError('fixture_parse','Synthetic parse failure.')):
            with self.assertRaises(TaskAlongError):self.service.run_provider('muse',bundle=str(self.bundle),output=str(self.root/'output'))
        self.assertTrue((self.root/'output/stdout.bin').exists());self.assertEqual(len(self.calls),1)
        with self.assertRaises(TaskAlongError):self.service.run_provider('muse',bundle=str(self.bundle),output=str(self.root/'retry'))

    def test_startup_context_pin_is_data_scope_not_a_production_receipt(self):
        self.configure(catalog_digest='a'*64)
        config=muse._configuration(self.service._store)
        root=self.root/'probe';root.mkdir(mode=0o700);(root/'workspace').mkdir();(root/'tmp').mkdir()
        event={'toolset':{'active_tools':[]},'reminder_roster':{'agents':[]},'run_context_messages':[]}
        with patch.object(muse,'run_foreground_experiment',side_effect=self.process),patch.object(muse,'_journal',return_value=([],[event],{})),self.assertRaises(TaskAlongError) as exc:
            muse._preflight(config,root)
        self.assertEqual(exc.exception.code,'provider_context_changed');self.assertTrue((root/'context-check/context.json').exists())
        self.assertNotIn('--no-foreign-personal-context',self.calls[0][0])

    def test_preflight_records_context_but_blocks_recognizable_secrets(self):
        self.configure();config=muse._configuration(self.service._store)
        root=self.root/'probe';root.mkdir(mode=0o700);(root/'workspace').mkdir();(root/'tmp').mkdir()
        event={'toolset':{'active_tools':[]},'reminder_roster':{'agents':[]},'run_context_messages':[{'id':'fixture','source':'fixture','text':'password=abcdefghijk'}]}
        with patch.object(muse,'run_foreground_experiment',side_effect=self.process),patch.object(muse,'_journal',return_value=([],[event],{})),self.assertRaises(TaskAlongError) as exc:muse._preflight(config,root)
        self.assertEqual(exc.exception.code,'sensitive_input');self.assertFalse((root/'context-check/context.json').exists())

    def test_public_context_snapshot_never_submits_or_claims_task(self):
        self.configure()
        event={'toolset':{'active_tools':[]},'reminder_roster':{'agents':[]},
               'run_context_messages':[{'id':'skills_catalog','source':'skills','text':'Synthetic public catalog.'}]}
        with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'run_foreground_experiment',side_effect=self.process),\
             patch.object(muse,'_journal',return_value=([],[event],{})):
            result=self.service.provider_context(output=str(self.root/'context'))
        self.assertTrue(result['model_free']);self.assertEqual(result['context'],'include')
        self.assertEqual(len(self.calls),1)
        self.assertEqual(self.calls[0][0][self.calls[0][0].index('--provider')+1],'echo')
        self.assertNotIn('--no-foreign-personal-context',self.calls[0][0])
        self.assertTrue(Path(result['review_file']).exists())
        self.assertFalse((self.bundle/'provider-submission.json').exists())
        with self.service._store.transaction() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM settings WHERE name LIKE 'provider-claim:%'").fetchone()[0],0)

    def test_conflicting_overlapping_context_pins_refuse_and_identical_pins_remain_valid(self):
        with self.assertRaises(TaskAlongError) as exc:
            self.configure(public_context_hashes={'security_mode':'a'*64},context_hashes={'security_mode':'b'*64})
        self.assertEqual(exc.exception.code,'provider_config_invalid')
        result=self.configure(public_context_hashes={'security_mode':'a'*64},context_hashes={'security_mode':'a'*64})
        self.assertTrue(result['configured'])

    def test_full_include_rules_pin_does_not_force_foreign_context_exclusion(self):
        import hashlib
        text='Synthetic public user rules.'
        self.configure(catalog_digest=hashlib.sha256(canonical_bytes([])).hexdigest(),
                       context_hashes={'rules_file':hashlib.sha256(text.encode()).hexdigest()})
        event={'toolset':{'active_tools':[]},'reminder_roster':{'agents':[]},
               'run_context_messages':[{'id':'rules_file','source':'rules_file','text':text}]}
        with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'run_foreground_experiment',side_effect=self.process),\
             patch.object(muse,'_journal',return_value=([],[event],{})):
            result=self.service.provider_context(output=str(self.root/'rules-context'))
        self.assertTrue(result['model_free']);self.assertNotIn('--no-foreign-personal-context',self.calls[0][0])
        event['run_context_messages'][0]['text']='Changed synthetic rule.'
        with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'run_foreground_experiment',side_effect=self.process),\
             patch.object(muse,'_journal',return_value=([],[event],{})),self.assertRaises(TaskAlongError) as exc:
            self.service.provider_context(output=str(self.root/'changed-context'))
        self.assertEqual(exc.exception.code,'provider_context_changed')

    def test_native_decoder_accepts_one_bound_final_json_and_fenced_json(self):
        response={'bundle_digest':self.manifest['digest'],'changes':{'greeting.txt':'new\n'}}
        for text in (json.dumps(response),'```json\n'+json.dumps(response)+'\n```'):
            value,_=muse._decode(native_output('session',text),'session');self.assertEqual(value,response)
        for raw in (native_output('foreign',json.dumps(response)),native_output('session',json.dumps(response),terminal='failed'),b'not-json'):
            with self.assertRaises(TaskAlongError):muse._decode(raw,'session')

    def test_explicit_owner_failure_blocks_preflight_and_proposal(self):
        self.configure();config=muse._configuration(self.service._store)
        root=self.root/'probe';root.mkdir(mode=0o700);(root/'workspace').mkdir();(root/'tmp').mkdir()
        def broken(argv,**options):
            value=self.process(argv,**options);value.failure_code='process_cleanup_failed';return value
        with patch.object(muse,'run_foreground_experiment',side_effect=broken),self.assertRaises(TaskAlongError) as exc:
            muse._preflight(config,root)
        self.assertEqual(exc.exception.code,'provider_context_check_failed')
        self.calls=[]
        with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'_preflight',return_value={}),patch.object(muse,'run_foreground_experiment',side_effect=broken):
            result=self.service.run_provider('muse',bundle=str(self.bundle),output=str(self.root/'output'))
        self.assertEqual(result['state'],'failed');self.assertNotIn('proposal_path',result);self.assertEqual(len(self.calls),1)

    def test_native_data_root_and_explicit_config_root_reach_child_environment(self):
        custom=self.root/'native-data/muse';custom.mkdir(parents=True)
        configroot=self.root/'custom-config';configroot.mkdir()
        self.configure(muse_home=str(custom),native_roots={'XDG_CONFIG_HOME':str(configroot)})
        self.run_fixture();env=self.calls[0][1]['env']
        self.assertEqual(env['XDG_DATA_HOME'],str(custom.parent));self.assertEqual(env['XDG_CONFIG_HOME'],str(configroot))

    def test_missing_or_duplicate_pinned_message_refuses_before_meta(self):
        self.configure(public_context_hashes={'security_mode':'a'*64});config=muse._configuration(self.service._store)
        root=self.root/'probe';root.mkdir(mode=0o700);(root/'workspace').mkdir();(root/'tmp').mkdir()
        event={'toolset':{'active_tools':[]},'reminder_roster':{'agents':[]},'run_context_messages':[]}
        with patch.object(muse,'run_foreground_experiment',side_effect=self.process),patch.object(muse,'_journal',return_value=([],[event],{})),self.assertRaises(TaskAlongError) as exc:
            muse._preflight(config,root)
        self.assertEqual(exc.exception.code,'provider_context_changed')

    def test_updater_wrappers_refuse_without_executing(self):
        self.binary.write_text('#!/bin/sh\nexit 0\n')
        with patch.object(muse,'run_foreground_experiment') as owner,self.assertRaises(TaskAlongError) as exc:self.configure()
        self.assertEqual(exc.exception.code,'provider_native_binary_required');owner.assert_not_called()

    def test_cli_configure_and_run_use_same_normal_service(self):
        from taskalong.cli import main
        config=self.root/'config.json';config.write_bytes(canonical_bytes({'executable':str(self.binary),'account_home':str(self.home),'muse_home':str(self.data)}))
        def cli(args):
            output=io.StringIO()
            with contextlib.redirect_stdout(output):code=main(['--json','--state-dir',str(self.root/'state'),*args])
            value=json.loads(output.getvalue());validate('command-result',value);return code,value
        code,value=cli(['configure-provider','muse','--config',str(config)]);self.assertEqual(code,0);self.assertFalse(value['data']['activation_required'])
        with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'_preflight',return_value={}),patch.object(muse,'run_foreground_experiment',side_effect=self.process),patch.object(muse,'_journal',return_value=([],[{}],{'provider_id':'meta','model_id':'muse-wonder-full-1.0'})):
            code,value=cli(['run','--provider','muse','--bundle',str(self.bundle),'--output',str(self.root/'output')])
        self.assertEqual(code,0);self.assertEqual(value['data']['state'],'proposal_ready')
        code,value=cli(['status',value['data']['run_id']]);self.assertEqual(code,0);self.assertEqual(value['data']['state'],'proposal_ready')
