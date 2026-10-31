"""Synthetic public successor journeys. No Muse executable or inference runs."""
import contextlib
import concurrent.futures
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

from taskalong.api import RunService
from taskalong import muse_experimental as muse
from taskalong import muse_successor as successor
from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes,digest,validate


@unittest.skipUnless(os.name=='posix','Private local artifacts require POSIX')
class SuccessorTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.binary=self.root/'native';self.binary.write_text('Synthetic native fixture, never executed.\n');self.binary.chmod(0o700)
        self.home=self.root/'home';self.home.mkdir();self.data=self.root/'data/muse';self.data.mkdir(parents=True)
        self.service=self.enterContext(RunService(self.root/'state'))
        self.request={'base_commit':'a'*40,'task':'Propose a small source change.','provider':'muse','model':'muse-wonder-full-1.0',
                      'reasoning_effort':'high','files':{'source.py':'original\n'}}
        self.calls=[];self.journals=[];self.mode='timeout';self.flags={};self.tail=[]
        self.enterContext(patch.object(muse.sys,'platform','darwin'))
        self.enterContext(patch.object(muse,'_preflight',return_value={}))
        self.enterContext(patch.object(muse,'run_foreground_experiment',side_effect=self.owner))
        self.configure(20,legacy=True)
        self.original=self.service.run_provider(request=self.request,output=str(self.root/'original'))
        self.original_bytes={p.relative_to(self.root/'original').as_posix():p.read_bytes()
                             for p in (self.root/'original').rglob('*') if p.is_file()}
        self.original_record=canonical_bytes(self.original)
        self.original_claim=canonical_bytes(self.service._store.setting('provider-claim:muse:'+self.original['bundle_digest']))
        self.original_native=self.journals[0].read_bytes()
        self.original_journal=self.journals[0]

    def configure(self,seconds,*,legacy=False,**overrides):
        self.service.configure_provider('muse',{'executable':str(self.binary),'account_home':str(self.home),'muse_home':str(self.data),
            'attempt_seconds':seconds,'max_output_bytes':1048576,'max_proposal_bytes':12288,**overrides})
        if legacy:
            config=self.service._store.setting('provider:muse');config['format']='local-muse-provider/2';config['digest']=digest(config)
            self.service._store.set_setting('provider-config:'+config['digest'],config)
            self.service._store.set_setting('provider:muse',config)

    def owner(self,argv,**options):
        self.calls.append((argv,options))
        session=argv[argv.index('--session-id')+1];native_run=str(uuid.uuid4())
        root=Path(argv[argv.index('--workspace')+1]).parent
        manifest=json.loads((root/'bundle/bundle.json').read_bytes())
        stamp=int(datetime.datetime.now(datetime.timezone.utc).timestamp()*1000)
        receipt={'pid':1234,'pgid':1234,'supervisor_pid':1233,'invocation_id':str(uuid.uuid4()),
                 'started_unix_ms':stamp,'executable_sha256':hashlib.sha256(self.binary.read_bytes()).hexdigest()}
        rows=[{'schema_version':1,'stream':{'kind':'session','id':session},'sequence':1,'payload_type':'session.run.linked',
               'payload':{'kind':'session_run_linked','run_stream':{'kind':'run','id':native_run}}}]
        terminal='cancelled'
        if self.mode=='success':
            rows.append({'schema_version':1,'stream':{'kind':'session','id':session},'sequence':2,'payload_type':'run.terminal.completed',
                         'payload':{'kind':'run_terminal','run_stream':{'kind':'run','id':native_run},'terminal':'completed',
                                    'text':json.dumps({'bundle_digest':manifest['digest'],'changes':{'source.py':'replacement\n'}})}})
            terminal='completed'
        for row in self.tail:
            rows.append({'schema_version':1,'stream':{'kind':'session','id':session},'sequence':len(rows)+1,
                         'payload_type':row[0],'payload':{'kind':row[1],'run_stream':{'kind':'run','id':native_run},**row[2]}})
        stdout=b''.join(canonical_bytes(r)+b'\n' for r in rows)
        journal=[{'payload':{'kind':'metadata','record':{'provider_id':'meta','model_id':'muse-wonder-full-1.0'}}},
                 {'payload':{'kind':'run','run_id':native_run,'event':{'kind':'model_request_configured','toolset':{'active_tools':[]},'reminder_roster':{'agents':[]}}}},
                 {'payload':{'kind':'run','run_id':native_run,'event':{'kind':'terminal','terminal':terminal,'reason':'cancelled during model step'}}}]
        day=datetime.datetime.now().astimezone().strftime('%Y/%m/%d')
        path=self.data/'sessions'/day/session/'session.jsonl';path.parent.mkdir(parents=True,mode=0o700)
        path.write_bytes(b''.join(canonical_bytes(r)+b'\n' for r in journal));path.chmod(0o600)
        self.journals.append(path)
        if options.get('on_spawn'):options['on_spawn'](SimpleNamespace(to_dict=lambda:receipt))
        summary={'root_exit_code':0 if self.mode=='success' else 130,'root_exit_observed':True,'group_termination_confirmed':True,
                 'fork_observed':True,'descendant_cessation':'unknown','termination_confirmed':False,'tracking_errors':[],
                 'boundary_failures':[],'failure_code':None,'protocol_error':None,'mode':'darwin-foreground-experiment/1',
                 'stdout':'fixture','stderr':'','output_bytes':len(stdout),'timed_out':self.mode!='success','cancelled':False,
                 'output_limited':False,'receipt':receipt,'duration_ms':options['timeout_seconds']*1000,**self.flags}
        return SimpleNamespace(stdout=stdout,stderr=b'',root_exit_code=summary['root_exit_code'],timed_out=summary['timed_out'],
            cancelled=summary['cancelled'],output_limited=summary['output_limited'],failure_code=summary['failure_code'],to_dict=lambda:summary)

    def plan(self,record=None):
        return self.service.provider_successor_plan(predecessor=(record or self.original)['run_id'])

    def execute(self,record=None,*,key='next',output=None,plan=None):
        record=record or self.original;proof=plan or self.plan(record)
        return self.service.provider_successor(predecessor=record['run_id'],key=key,plan_digest=proof['digest'],
            output=str(output or self.root/key))

    def assert_original(self):
        self.assertEqual(canonical_bytes(self.service.result(self.original['run_id'])),self.original_record)
        self.assertEqual(canonical_bytes(self.service._store.setting('provider-claim:muse:'+self.original['bundle_digest'])),self.original_claim)
        original_root=Path(self.original['output'])
        current={p.relative_to(original_root).as_posix():p.read_bytes() for p in original_root.rglob('*') if p.is_file()}
        self.assertEqual(current,self.original_bytes)
        self.assertEqual(self.original_journal.read_bytes(),self.original_native)

    def original_at(self,seconds,**options):
        self.configure(seconds,**options)
        request={**self.request,'task':f'Independent original {seconds}-second synthetic intent.',
                 'reasoning_effort':options.get('reasoning_effort','high')}
        self.original=self.service.run_provider(request=request,output=str(self.root/f'original-{seconds}'))
        self.original_bytes={p.relative_to(Path(self.original['output'])).as_posix():p.read_bytes()
                             for p in Path(self.original['output']).rglob('*') if p.is_file()}
        self.original_record=canonical_bytes(self.original)
        self.original_claim=canonical_bytes(self.service._store.setting('provider-claim:muse:'+self.original['bundle_digest']))
        self.original_journal=self.journals[-1];self.original_native=self.original_journal.read_bytes()

    def replace_record(self,record,**updates):
        value={**record,**updates};value['digest']=digest(value)
        root=Path(value['output']);p=root/f"events/{value['revision']:04d}.json";p.chmod(0o600);p.write_bytes(canonical_bytes(value));p.chmod(0o400)
        if 'process' in updates:
            p=root/'process.json';p.chmod(0o600);p.write_bytes(canonical_bytes(value['process']));p.chmod(0o400)
        self.service._store.set_setting('provider-run:'+value['run_id'],value)
        return value

    def test_two_explicit_timeouts_use_360_then_720_and_preserve_history(self):
        self.configure(360);proof=self.plan();self.assertEqual(proof['remaining_controller_slots_including_this'],2)
        self.assertEqual(proof['remaining_local_meta_seconds_including_this'],1080)
        self.assertFalse(proof['remote_usage_settled']);self.assertFalse(proof['complete_descendant_cessation_proven'])
        self.assertEqual(len(self.calls),1) # Planning never starts a process.
        first=self.execute(plan=proof);self.assertEqual(first['state'],'failed');self.assertEqual(first['manual_successor']['ordinal'],1)
        self.configure(720);last=self.execute(first,key='last');self.assertEqual(last['manual_successor']['ordinal'],2)
        self.assertEqual([x[1]['timeout_seconds'] for x in self.calls],[20,360,720])
        self.assertEqual(first['bundle_digest'],self.original['bundle_digest']);self.assertEqual(last['bundle_digest'],self.original['bundle_digest'])
        self.assertEqual(first['manual_successor']['history'][0]['remote_usage'],'unknown')
        with self.assertRaises(TaskAlongError) as exc:self.plan(last)
        self.assertEqual(exc.exception.code,'provider_successor_limit');self.assertEqual(len(self.calls),3);self.assert_original()

    def test_successful_next_attempt_stops_the_ladder_and_does_not_apply(self):
        self.configure(360);self.mode='success';first=self.execute();self.assertEqual(first['state'],'proposal_ready')
        self.assertFalse(first['patch_applied']);self.configure(720)
        with self.assertRaises(TaskAlongError):self.plan(first)
        self.assertEqual(len(self.calls),2);self.assert_original()

    def test_original_360_gets_only_one_explicit_720_with_same_max_scope(self):
        self.original_at(360,reasoning_effort='max');self.configure(720,reasoning_effort='max')
        before=len(self.calls);proof=self.plan()
        self.assertEqual(len(self.calls),before)
        self.assertEqual(proof['ordinal'],1);self.assertEqual(proof['attempt_seconds'],720)
        self.assertEqual(proof['remaining_controller_slots_including_this'],1)
        self.assertEqual(proof['remaining_local_meta_seconds_including_this'],720)
        self.assertEqual(proof['enrollment']['deadlines_seconds'],[720])
        self.assertEqual(proof['enrollment']['max_new_controller_submissions'],1)
        self.assertFalse(proof['remote_usage_settled']);self.assertFalse(proof['complete_descendant_cessation_proven'])
        last=self.execute(key='direct-last',plan=proof)
        self.assertEqual(last['bundle_digest'],self.original['bundle_digest'])
        self.assertEqual(last['manual_successor']['predecessor_run_id'],self.original['run_id'])
        self.assertEqual(last['manual_successor']['history'][0]['controller_submissions'],1)
        self.assertEqual(last['manual_successor']['history'][0]['remote_usage'],'unknown')
        self.assertEqual(last['manual_successor']['history'][0]['descendant_cessation'],'unknown')
        self.assertEqual([call[1]['timeout_seconds'] for call in self.calls[-2:]],[360,720])
        self.assertEqual(self.execute(key='direct-last',plan=proof),last)
        with self.assertRaises(TaskAlongError):self.execute(key='another-last',plan=proof)
        with self.assertRaises(TaskAlongError) as exc:self.plan(last)
        self.assertEqual(exc.exception.code,'provider_successor_limit')
        self.assertEqual(len(self.calls),before+1);self.assert_original()

    def test_other_long_original_deadlines_do_not_gain_a_successor(self):
        for seconds in (61,359,361,719,720):
            self.original_at(seconds);self.configure(720);before=len(self.calls)
            with self.subTest(seconds=seconds),self.assertRaises(TaskAlongError) as exc:self.plan()
            self.assertEqual(exc.exception.code,'provider_successor_limit');self.assertEqual(len(self.calls),before)
            self.assertIsNone(self.service._store.setting('provider-successor:muse:'+self.original['run_id']))
            self.assert_original()

    def test_original_360_requires_exact_720_and_unchanged_context_and_limits(self):
        self.original_at(360);self.configure(360)
        with self.assertRaises(TaskAlongError) as exc:self.plan()
        self.assertEqual(exc.exception.code,'provider_successor_deadline')
        for options in ({'context':'native-only'},{'model':'different-model'},{'reasoning_effort':'max'},
                        {'max_output_bytes':524288},{'max_proposal_bytes':8192}):
            self.configure(720,**options)
            with self.subTest(options=options),self.assertRaises(TaskAlongError) as exc:self.plan()
            self.assertEqual(exc.exception.code,'provider_successor_configuration_mismatch')
        self.assertIsNone(self.service._store.setting('provider-successor:muse:'+self.original['run_id']))
        self.assertEqual(len(self.calls),2);self.assert_original()

    def test_original_360_unknown_cleanup_or_other_failure_never_qualifies(self):
        self.original_at(360);original=self.original;self.configure(720)
        for changes in ({'root_exit_observed':False},{'group_termination_confirmed':False},
                        {'tracking_errors':['lost']},{'failure_code':'cleanup_failed'},
                        {'protocol_error':'partial'},{'output_limited':True},{'cancelled':True},{'timed_out':False}):
            changed=self.replace_record(original,process={**original['process'],**changes})
            with self.subTest(changes=changes),self.assertRaises(TaskAlongError):self.plan(changed)
        self.assertIsNone(self.service._store.setting('provider-successor:muse:'+original['run_id']))
        self.assertEqual(len(self.calls),2)

    def test_original_360_successful_720_stops_without_application(self):
        self.original_at(360);self.configure(720);self.mode='success';last=self.execute(key='success-last')
        self.assertEqual(last['state'],'proposal_ready');self.assertFalse(last['patch_applied'])
        with self.assertRaises(TaskAlongError):self.plan(last)
        self.assertEqual(len(self.calls),3);self.assert_original()

    def test_original_360_restored_state_cannot_reopen_its_single_slot(self):
        self.original_at(360);self.configure(720)
        with RunService(self.root/'long-snapshot') as snapshot:
            self.service._store.db.backup(snapshot._store.db)
            self.execute(key='one-long-slot')
            snapshot._store.db.backup(self.service._store.db)
            with self.assertRaises(TaskAlongError):self.plan()
        self.assertEqual(len(self.calls),3);self.assert_original()

    def test_original_360_rejects_an_unexpected_second_slot_file(self):
        self.original_at(360);self.configure(720);self.execute(key='one-long-slot')
        anchor=successor._anchor(self.original)
        (anchor/'slot-2.json').write_bytes(b'{}');(anchor/'slot-2.json').chmod(0o400)
        with self.assertRaises(TaskAlongError) as exc:self.plan()
        self.assertEqual(exc.exception.code,'provider_successor_history_changed')
        self.assertEqual(len(self.calls),3);self.assert_original()

    def test_repeated_same_key_only_observes_and_different_key_cannot_repeat_parent(self):
        self.configure(360);proof=self.plan();first=self.execute(plan=proof)
        self.assertEqual(self.execute(plan=proof),first);self.assertEqual(len(self.calls),2)
        with self.assertRaises(TaskAlongError):self.execute(key='another',plan=proof)
        with self.assertRaises(TaskAlongError):self.execute(plan=proof,output=self.root/'different')
        self.assertEqual(len(self.calls),2);self.assert_original()

    def test_reserved_crash_is_observable_but_never_resumes_or_frees_slot(self):
        self.configure(360);proof=self.plan()
        with patch.object(muse,'run',side_effect=OSError('fixture setup crash')):
            with self.assertRaises(OSError):self.execute(plan=proof)
        result=self.execute(plan=proof);self.assertEqual(result['state'],'reserved_incomplete')
        self.assertEqual(self.service.result(result['run_id']),result);self.assertIsNone(result['controller_submissions'])
        with self.assertRaises(TaskAlongError):self.execute(key='new-key',plan=proof)
        self.configure(720)
        with self.assertRaises(TaskAlongError):self.plan(result)
        self.assertEqual(len(self.calls),1);self.assert_original()

    def test_denied_preflight_consumes_slot_and_blocks_final_without_meta_call(self):
        self.configure(360);proof=self.plan()
        with patch.object(muse,'_preflight',side_effect=TaskAlongError('permission_denied','Synthetic denial.')):
            with self.assertRaises(TaskAlongError):self.execute(plan=proof)
        result=self.execute(plan=proof);self.assertEqual(result['state'],'blocked');self.assertEqual(result['controller_submissions'],0)
        self.configure(720)
        with self.assertRaises(TaskAlongError):self.plan(result)
        self.assertEqual(len(self.calls),1);self.assert_original()

    def test_final_refuses_every_original_ancestor_overlap_before_reservation(self):
        self.configure(360);first=self.execute();self.configure(720);proof=self.plan(first)
        for folder in (self.root/'original/new-final',Path(self.original['bundle'])/'new-final'):
            with self.subTest(folder=folder),self.assertRaises(TaskAlongError) as exc:self.execute(first,key='bad-path',output=folder,plan=proof)
            self.assertEqual(exc.exception.code,'provider_successor_output_overlap');self.assertFalse(folder.exists())
        self.assertIsNone(self.service._store.setting('provider-successor:muse:'+first['run_id']));self.assert_original()

    def test_overflow_cancel_or_unknown_cleanup_never_qualify(self):
        self.configure(360)
        original=self.original
        for changes in ({'output_limited':True},{'cancelled':True},{'root_exit_observed':False},{'group_termination_confirmed':False},
                        {'tracking_errors':['lost']},{'failure_code':'cleanup_failed'},{'boundary_failures':[['cleanup',1]]},
                        {'timed_out':False},{'protocol_error':'partial'},{'root_exit_code':None}):
            changed=self.replace_record(original,process={**original['process'],**changes})
            with self.subTest(changes=changes),self.assertRaises(TaskAlongError):self.plan(changed)
        self.assertEqual(len(self.calls),1)

    def test_inprogress_unknown_and_success_states_refuse(self):
        self.configure(360)
        for state in ('running','interrupted','blocked','proposal_ready'):
            changed=self.replace_record(self.original,state=state)
            with self.subTest(state=state),self.assertRaises(TaskAlongError):self.plan(changed)
        self.assertEqual(len(self.calls),1)

    def test_completed_invalid_or_contradictory_stdout_is_not_timeout_authority(self):
        self.configure(360)
        # New independent root intents keep their own original claims.
        for index,tail in enumerate([
            [('run.terminal.completed','run_terminal',{'terminal':'completed','text':'not-json'})],
            [('run.terminal.failed','run_terminal',{'terminal':'failed','text':''})],
            [('run.terminal.cancelled','run_terminal',{'terminal':'cancelled'}),('run.terminal.completed','run_terminal',{'terminal':'completed','text':'{}'})],
            [('run.output.delta','run_output_delta',{'text':'{}'})],
        ]):
            self.configure(20);self.tail=tail;value={**self.request,'task':'Distinct synthetic intent '+str(index)}
            record=self.service.run_provider(request=value,output=str(self.root/f'conflict-{index}'));self.configure(360)
            with self.subTest(index=index),self.assertRaises(TaskAlongError) as exc:self.plan(record)
            self.assertEqual(exc.exception.code,'provider_successor_result_exists')

    def test_changed_configuration_at_gate_stops_release(self):
        self.configure(360);proof=self.plan();original_owner=self.owner
        def change(argv,**options):
            callback=options['on_spawn']
            def gate(receipt):
                self.configure(360,context='native-only');callback(receipt)
            options['on_spawn']=gate
            return original_owner(argv,**options)
        with patch.object(muse,'run_foreground_experiment',side_effect=change),self.assertRaises(TaskAlongError) as exc:
            self.execute(plan=proof)
        self.assertEqual(exc.exception.code,'provider_successor_plan_changed');self.assert_original()

    def test_same_intent_config_and_original_state_are_required(self):
        self.configure(360,model='different-model')
        with self.assertRaises(TaskAlongError):self.plan()
        self.configure(360)
        with RunService(self.root/'fresh-state') as fresh:
            fresh.configure_provider('muse',{'executable':str(self.binary),'account_home':str(self.home),'muse_home':str(self.data),'attempt_seconds':360})
            with self.assertRaises(TaskAlongError):fresh.provider_successor_plan(predecessor=self.original['run_id'])
        with self.assertRaises(TaskAlongError):self.service.run_provider(request=self.request,output=str(self.root/'ordinary-replay'))
        self.assertEqual(len(self.calls),1);self.assert_original()

    def test_deadline_range_and_default_are_finite_and_versioned(self):
        for seconds in (1,60,360,720):
            self.configure(seconds);self.assertEqual(muse._configuration(self.service._store)['attempt_seconds'],seconds)
        for seconds in (0,721,-1,True,360.0,None):
            with self.subTest(seconds=seconds),self.assertRaises(TaskAlongError):self.configure(seconds)
        self.service.configure_provider('muse',{'executable':str(self.binary),'account_home':str(self.home),'muse_home':str(self.data)})
        config=muse._configuration(self.service._store);self.assertEqual(config['attempt_seconds'],20);self.assertEqual(config['format'],'local-muse-provider/3')
        config['format']='local-muse-provider/2';config['attempt_seconds']=360;config['digest']=digest(config)
        self.service._store.set_setting('provider:muse',config)
        with self.assertRaises(TaskAlongError):muse._configuration(self.service._store)

    def test_cli_plan_and_successor_are_same_explicit_idempotent_service(self):
        from taskalong.cli import main
        self.configure(360)
        def cli(args):
            out=io.StringIO()
            with contextlib.redirect_stdout(out):code=main(['--state-dir',str(self.root/'state'),'--json',*args])
            value=json.loads(out.getvalue());validate('command-result',value);return code,value
        code,value=cli(['provider-successor-plan','muse','--predecessor',self.original['run_id']]);self.assertEqual(code,0)
        args=['provider-successor','muse','--predecessor',self.original['run_id'],'--plan-digest',value['data']['digest'],'--key','cli-next','--output',str(self.root/'cli-next')]
        code,first=cli(args);self.assertEqual(code,0);self.assertEqual(first['data']['manual_successor']['attempt_seconds'],360)
        code,second=cli(args);self.assertEqual(code,0);self.assertEqual(first,second);self.assertEqual(len(self.calls),2)

    def test_final_can_only_follow_exact_360_timeout_with_no_proposal(self):
        self.configure(360);self.flags={'output_limited':True};first=self.execute();self.configure(720)
        with self.assertRaises(TaskAlongError):self.plan(first)
        self.assertEqual(len(self.calls),2);self.assert_original()

    def test_original_native_history_change_blocks_final_even_if_still_cancelled(self):
        self.configure(360);first=self.execute();self.configure(720)
        with self.journals[0].open('ab') as f:f.write(b'{"payload":{}}\n')
        with self.assertRaises(TaskAlongError) as exc:self.plan(first)
        self.assertEqual(exc.exception.code,'provider_successor_history_changed');self.assertEqual(len(self.calls),2)

    def test_stale_plan_capture_changes_refuse_before_reservation_or_preflight(self):
        self.configure(360);proof=self.plan();path=Path(self.original['output'])/'stdout.bin'
        raw=path.read_bytes();path.chmod(0o600);path.write_bytes(raw[:-1]+b' ');path.chmod(0o400)
        with patch.object(muse,'_preflight') as preflight,self.assertRaises(TaskAlongError) as exc:self.execute(plan=proof)
        self.assertEqual(exc.exception.code,'provider_successor_plan_changed');preflight.assert_not_called()
        self.assertIsNone(self.service._store.setting('provider-successor:muse:'+self.original['run_id']));self.assertEqual(len(self.calls),1)

    def test_copied_enrolled_state_is_not_a_fresh_retry_namespace(self):
        self.configure(360);first=self.execute();self.configure(720)
        with RunService(self.root/'copied-state') as copied:
            self.service._store.db.backup(copied._store.db)
            with self.assertRaises(TaskAlongError) as exc:copied.provider_successor_plan(predecessor=first['run_id'])
        self.assertEqual(exc.exception.code,'provider_successor_history_changed');self.assertEqual(len(self.calls),2);self.assert_original()

    def test_competing_keys_reserve_only_one_provider_submission(self):
        self.configure(360);proof=self.plan();release=threading.Event();original_owner=self.owner
        def held(argv,**options):
            if not release.wait(5):raise AssertionError('synthetic owner release missing')
            return original_owner(argv,**options)
        def invoke(key):
            with RunService(self.root/'state') as service:
                return service.provider_successor(predecessor=self.original['run_id'],key=key,plan_digest=proof['digest'],output=str(self.root/key))
        with patch.object(muse,'run_foreground_experiment',side_effect=held),concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures=[pool.submit(invoke,key) for key in ('one','two')]
            done,_=concurrent.futures.wait(futures,timeout=5,return_when=concurrent.futures.FIRST_COMPLETED)
            try:
                self.assertEqual(len(done),1)
                with self.assertRaises(TaskAlongError):next(iter(done)).result()
            finally:release.set()
            results=[]
            for future in futures:
                try:results.append(future.result(timeout=5))
                except TaskAlongError:pass
        self.assertEqual(len(results),1);self.assertEqual(len(self.calls),2);self.assert_original()

    def test_pre_enrollment_copy_and_database_restore_do_not_reopen_consumed_slots(self):
        self.configure(360)
        with RunService(self.root/'old-snapshot') as snapshot:
            self.service._store.db.backup(snapshot._store.db)
            first=self.execute()
            with self.assertRaises(TaskAlongError):snapshot.provider_successor_plan(predecessor=self.original['run_id'])
            # Restore the old database to the SAME path. The separate retained
            # control directory must still stop reinitialization.
            snapshot._store.db.backup(self.service._store.db)
            with self.assertRaises(TaskAlongError):self.plan()
        self.assertEqual(len(self.calls),2);self.assert_original()
