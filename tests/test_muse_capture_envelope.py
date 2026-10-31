"""Synthetic finite-envelope and explicit capture-successor contracts; no Muse."""
import concurrent.futures
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from taskalong.api import RunService
from taskalong import muse_experimental as muse, muse_successor as successor
from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes, digest
import test_muse_successor as fixtures


def transcript(response, count=2050):
    session='11111111-1111-4111-8111-111111111111';run='22222222-2222-4222-8222-222222222222'
    def row(seq,kind,payload):
        return canonical_bytes({'schema_version':1,'stream':{'kind':'session','id':session},'sequence':seq,
            'payload_type':kind,'payload':{'run_stream':{'kind':'run','id':run},**payload}})+b'\n'
    rows=[row(1,'session.run.linked',{'kind':'session_run_linked'})]
    rows += [row(i,'run.output.delta',{'kind':'run_output_delta','text':''}) for i in range(2,count)]
    rows += [row(count,'run.terminal.completed',{'kind':'run_terminal','terminal':'completed','text':canonical_bytes(response).decode()})]
    return session,b''.join(rows)


@unittest.skipUnless(os.name=='posix','Private local State is POSIX')
class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.native=self.root/'native';self.native.write_text('Non-executed native fixture.\n');self.native.chmod(0o700)
        self.home=self.root/'home';self.home.mkdir();self.data=self.root/'data/muse';self.data.mkdir(parents=True)
        self.service=self.enterContext(RunService(self.root/'state'))
        self.input={'executable':str(self.native),'account_home':str(self.home),'muse_home':str(self.data)}

    def test_fixed_opt_in_profile_and_typed_bounds(self):
        self.service.configure_provider('muse',{**self.input,'capture_profile':'implementation'})
        config=muse._configuration(self.service._store)
        self.assertEqual(config['format'],'local-muse-provider/4')
        self.assertEqual(tuple(config[k] for k in ('attempt_seconds','max_output_bytes','max_proposal_bytes','max_protocol_records')),muse._IMPLEMENTATION)
        self.assertEqual(muse._max_records(config),8192)
        for override in ({'attempt_seconds':360},{'max_output_bytes':1048576},{'max_output_bytes':4194305},
                         {'max_proposal_bytes':65535},{'capture_profile':True},{'capture_profile':'anything'},
                         {'attempt_seconds':True},{'max_protocol_records':8192}):
            with self.subTest(override=override),self.assertRaises(TaskAlongError):
                self.service.configure_provider('muse',{**self.input,'capture_profile':'implementation',**override})
        for field,value in (('max_protocol_records',8192.0),('attempt_seconds',720.0),('max_output_bytes',True),('max_proposal_bytes',65536.0)):
            altered={**config,field:value}
            with self.subTest(field=field),self.assertRaises(TaskAlongError):
                altered['digest']=digest(altered);muse._checked_configuration(altered)

    def test_legacy_config_bytes_and_previous_reader_refusal(self):
        roots={'XDG_CONFIG_HOME','XDG_DATA_HOME','XDG_STATE_HOME','XDG_CACHE_HOME'}
        self.enterContext(patch.dict(os.environ,{k:v for k,v in os.environ.items() if k not in roots},clear=True))
        self.service.configure_provider('muse',self.input)
        config=self.service._store.setting('provider:muse')
        expected={'format':'local-muse-provider/3','provider':'muse','experimental':True,
            'binary':muse._observe_file(str(self.native),executable=True),'account_home':str(self.home),
            'muse_home':str(self.data),'native_roots':{'XDG_DATA_HOME':str(self.data.parent)},
            'model':'muse-wonder-full-1.0','reasoning_effort':'high','context':'include','catalog_digest':None,
            'public_context_hashes':{},'context_hashes':{},'attempt_seconds':20,'max_output_bytes':65536,'max_proposal_bytes':65536}
        expected['digest']=digest(expected)
        self.assertEqual(canonical_bytes(config),canonical_bytes(expected))
        self.service.configure_provider('muse',{**self.input,'capture_profile':'implementation'})
        # /4 is deliberately outside every previous reader's accepted formats.
        self.assertNotIn(muse._configuration(self.service._store)['format'],('local-muse-provider/1','local-muse-provider/2','local-muse-provider/3'))
        self.service.configure_provider('muse',{**self.input,'attempt_seconds':720,'max_output_bytes':1048576})
        self.assertEqual(muse._max_records(muse._configuration(self.service._store)),2048)
        with self.assertRaises(TaskAlongError):self.service.configure_provider('muse',{**self.input,'max_output_bytes':4194304})

    def test_completed_larger_stream_uses_explicit_record_bound(self):
        response={'bundle_digest':'a'*64,'changes':{'s.py':'x\n'}}
        for count in (2048,2049,8192):
            session,raw=transcript(response,count)
            self.assertLess(len(raw),4194304)
            self.assertEqual(muse._decode(raw,session,max_records=8192)[0],response)
            if count>2048:
                with self.assertRaises(TaskAlongError):muse._decode(raw,session)
        session,raw=transcript(response,8193)
        with self.assertRaises(TaskAlongError):muse._decode(raw,session,max_records=8192)

    def test_proposal_utf8_canonical_bound_and_bad_streams(self):
        response={'bundle_digest':'a'*64,'changes':{'s.py':'\n'}}
        extra=65536-len(canonical_bytes(response));response['changes']['s.py']='é'*(extra//2)+'x'*(extra%2)+'\n'
        self.assertEqual(len(canonical_bytes(response)),65536)
        session,raw=transcript(response)
        self.assertEqual(muse._decode(raw,session,max_records=8192)[0],response)
        response['changes']['s.py']+='x';session,oversized=transcript(response)
        with self.assertRaises(TaskAlongError) as exc:muse._decode(oversized,session,max_records=8192)
        self.assertEqual(exc.exception.code,'provider_proposal_too_large')
        for bad in (raw[:-8],raw[:-1],b'not-json\n'+raw,raw+raw.splitlines(keepends=True)[-1],
                    raw.replace(b'"terminal":"completed"',b'"terminal":"cancelled"'),
                    raw.replace(b'"schema_version":1',b'"schema_version":1,"schema_version":1',1)):
            with self.subTest(prefix=bad[:20]),self.assertRaises(TaskAlongError):muse._decode(bad,session,max_records=8192)

    def test_record_observer_does_not_filter_and_stops_at_limit(self):
        watcher=muse._RecordBudget()
        for _ in range(8192):watcher.observe(b'{}')
        self.assertEqual(watcher.observed,8192);self.assertFalse(watcher.limited)
        with self.assertRaises(TaskAlongError) as exc:watcher.observe(b'{}')
        self.assertEqual(exc.exception.code,'provider_protocol_record_limit');self.assertTrue(watcher.limited)

    @unittest.skipUnless(sys.platform=='darwin','Real foreground owner is Darwin-only')
    def test_real_python_callback_cancellation_without_provider(self):
        from taskalong.experimental_process import run_foreground_experiment, FOREGROUND_EXPERIMENT
        watcher=muse._RecordBudget()
        result=run_foreground_experiment([sys.executable,'-I','-c','import time\nfor i in range(8193): print("{}",flush=True)\ntime.sleep(5)'],
            mode=FOREGROUND_EXPERIMENT,cwd=self.root,timeout_seconds=10,max_output_bytes=4194304,on_stdout_line=watcher.observe)
        self.assertTrue(watcher.limited);self.assertTrue(result.root_exit_observed)
        self.assertEqual(result.failure_code,'provider_protocol_record_limit')
        self.assertFalse(result.production_dispatch_allowed)

    @unittest.skipUnless(sys.platform=='darwin','Real foreground owner is Darwin-only')
    def test_four_mib_combined_bound_and_large_protocol_line(self):
        from taskalong.experimental_process import run_foreground_experiment, FOREGROUND_EXPERIMENT
        cap=4194304
        for extra in (0,1):
            lines=[]
            script='import os,time\nos.write(2,b"e"*1000000)\nos.write(1,b"x"*'+str(cap-1000000-1+extra)+')\nos.write(1,b"\\n")\n'
            if extra:script+='time.sleep(5)\n'
            result=run_foreground_experiment([sys.executable,'-I','-c',script],mode=FOREGROUND_EXPERIMENT,
                cwd=self.root,timeout_seconds=10,max_output_bytes=cap,max_line_bytes=cap,on_stdout_line=lines.append)
            self.assertLessEqual(len(result.stdout)+len(result.stderr),cap)
            self.assertGreaterEqual(result.output_bytes,cap+extra)
            if not extra:self.assertEqual(result.output_bytes,cap)
            self.assertEqual(result.output_limited,bool(extra));self.assertTrue(result.root_exit_observed)
            if not extra:
                self.assertIsNone(result.failure_code);self.assertEqual(result.root_exit_code,0)
                self.assertEqual(len(lines[0]),cap-1000000-1)



@unittest.skipUnless(os.name=='posix','Private local State is POSIX')
class CaptureSuccessorTests(unittest.TestCase):
    def setUp(self):
        self.c=fixtures.SuccessorTests('test_two_explicit_timeouts_use_360_then_720_and_preserve_history')
        self.addCleanup(self.c.doCleanups);self.c.setUp()
        self.root=self.c.root;self.service=self.c.service
        original_owner=self.c.owner
        def overflow(argv,**options):
            result=original_owner(argv,**options);info=result.to_dict();session=argv[argv.index('--session-id')+1]
            linked=json.loads(result.stdout.splitlines()[0]);run=linked['payload']['run_stream']['id']
            def row(seq,kind,payload):
                return {'schema_version':1,'stream':{'kind':'session','id':session},'sequence':seq,
                    'payload_type':kind,'payload':{'run_stream':{'kind':'run','id':run},**payload}}
            rows=[linked,row(2,'native.fixture.metadata',{'padding':''})]
            for i in range(3,1853):rows.append(row(i,'run.output.delta',{'kind':'run_output_delta','text':'{"changes":{"s.py":"' if i==3 else 'x'*28}))
            stderr=b'diagnostic\n';tail=b'{"schem'
            target=1048576-len(stderr)-len(tail)
            raw=b''.join(canonical_bytes(r)+b'\n' for r in rows)
            rows[1]['payload']['padding']='p'*(target-len(raw))
            stdout=b''.join(canonical_bytes(r)+b'\n' for r in rows)+tail
            assert len(stdout)+len(stderr)==1048576
            info.update(root_exit_code=130,timed_out=False,cancelled=False,output_limited=True,output_bytes=1048676)
            return SimpleNamespace(stdout=stdout,stderr=stderr,root_exit_code=130,timed_out=False,cancelled=False,
                output_limited=True,failure_code=None,to_dict=lambda:info)
        with patch.object(muse,'run_foreground_experiment',side_effect=overflow):self.c.original_at(720,max_proposal_bytes=65536)
        self.original=self.c.original
        self.service.configure_provider('muse',{'executable':str(self.c.binary),'account_home':str(self.c.home),
            'muse_home':str(self.c.data),'capture_profile':'implementation'})

    def plan(self,record=None,reason='capture'):
        return self.service.provider_successor_plan(predecessor=(record or self.original)['run_id'],reason=reason)

    def execute(self,*,key='capture',proof=None,record=None,output=None,reason='capture'):
        record=record or self.original;proof=proof or self.plan(record,reason)
        return self.service.provider_successor(predecessor=record['run_id'],key=key,plan_digest=proof['digest'],
            output=str(output or self.root/key),reason=reason)

    def test_original_overflow_stays_failed_and_explicit_link_is_one_shot(self):
        with self.assertRaises(TaskAlongError):self.plan(reason='timeout')
        original_stdout=(Path(self.original['output'])/'stdout.bin').read_bytes()
        session=json.loads((Path(self.original['output'])/'invocation.json').read_bytes())['session_id']
        with self.assertRaises(TaskAlongError):muse._decode(original_stdout,session)
        before=len(self.c.calls);proof=self.plan();self.assertEqual(len(self.c.calls),before)
        self.assertEqual(proof['remaining_controller_slots_including_this'],1)
        self.assertEqual(proof['max_protocol_records'],8192);self.assertEqual(proof['max_output_bytes'],4194304)
        self.assertFalse(proof['remote_usage_settled']);self.c.mode='success'
        child=self.execute(proof=proof);self.assertEqual(child['state'],'proposal_ready');self.assertFalse(child['patch_applied'])
        self.assertEqual(child['bundle_digest'],self.original['bundle_digest']);self.assertEqual(child['manual_successor']['reason'],'capture')
        self.assertEqual(self.execute(proof=proof),child)
        for reason in ('timeout','capture'):
            with self.assertRaises(TaskAlongError):self.plan(child,reason)
        with self.assertRaises(TaskAlongError):self.execute(proof=proof,key='different')
        with self.assertRaises(TaskAlongError):self.execute(proof=proof,reason='timeout')
        self.assertEqual(len(self.c.calls),before+1);self.c.assert_original()

    def test_child_timeout_cannot_open_either_schedule(self):
        child=self.execute()
        self.assertTrue(child['process']['timed_out'])
        for reason in ('capture','timeout'):
            with self.assertRaises(TaskAlongError):self.plan(child,reason)
        self.c.assert_original()

    def test_capture_scope_and_plan_are_bound_at_gate(self):
        proof=self.plan();owner=self.c.owner
        def changed(argv,**options):
            callback=options['on_spawn']
            def gate(receipt):
                self.service.configure_provider('muse',{'executable':str(self.c.binary),'account_home':str(self.c.home),
                    'muse_home':str(self.c.data),'capture_profile':'implementation','context':'native-only'})
                callback(receipt)
            options['on_spawn']=gate;return owner(argv,**options)
        with patch.object(muse,'run_foreground_experiment',side_effect=changed),self.assertRaises(TaskAlongError) as exc:self.execute(proof=proof)
        self.assertEqual(exc.exception.code,'provider_successor_plan_changed');self.c.assert_original()

    def test_unknown_cleanup_cancel_or_timeout_never_qualifies(self):
        for changes in ({'root_exit_observed':False},{'group_termination_confirmed':False},{'cancelled':True},
                        {'timed_out':True},{'output_limited':False},{'observed_output_bytes':1048576},
                        {'tracking_errors':['lost']},{'protocol_error':'bad'},{'failure_code':'cleanup_failed'}):
            altered=self.c.replace_record(self.original,process={**self.original['process'],**changes})
            with self.subTest(changes=changes),self.assertRaises(TaskAlongError):self.plan(altered)
        self.assertEqual(len(self.c.calls),2)

    def test_capture_preflight_denial_consumes_slot_without_submission(self):
        proof=self.plan()
        with patch.object(muse,'_preflight',side_effect=TaskAlongError('permission_denied','Synthetic denial.')):
            with self.assertRaises(TaskAlongError):self.execute(proof=proof)
        record=self.execute(proof=proof);self.assertEqual(record['state'],'blocked');self.assertEqual(record['controller_submissions'],0)
        with self.assertRaises(TaskAlongError):self.execute(proof=proof,key='another')
        self.assertEqual(len(self.c.calls),2);self.c.assert_original()

    def test_crash_reservation_and_restored_database_do_not_refund(self):
        proof=self.plan()
        with RunService(self.root/'snapshot') as snapshot:
            self.service._store.db.backup(snapshot._store.db)
            with patch.object(muse,'run',side_effect=OSError('synthetic crash')):
                with self.assertRaises(OSError):self.execute(proof=proof)
            record=self.execute(proof=proof);self.assertEqual(record['state'],'reserved_incomplete')
            with self.assertRaises(TaskAlongError):self.plan(record)
            snapshot._store.db.backup(self.service._store.db)
            with self.assertRaises(TaskAlongError):self.plan()
        self.assertEqual(len(self.c.calls),2);self.c.assert_original()

    def test_partial_tail_is_metadata_only_and_prefix_syntax_is_strict(self):
        session='11111111-1111-4111-8111-111111111111';native='22222222-2222-4222-8222-222222222222'
        prefix=(b'{"schema_version":1,"id":"33333333-3333-4333-8333-333333333333",'
            b'"stream":{"kind":"session","id":"'+session.encode()+b'"},"sequence":12,"recorded_at":123456789,'
            b'"record_type":"status","durability":"ephemeral","causation_id":"44444444-4444-4444-8444-444444444444",'
            b'"payload_type":"run.output.delta","payload_schema_version":1,"payload":{"kind":"run_output_delta","command_id":"'+native.encode()+b'"')
        for length in range(1,len(prefix)+1):
            self.assertTrue(successor._truncated_metadata_prefix(prefix[:length],session,native,11),length)
        for tail in (b'garbage',b'{"schema_version":1,}',b'{"schema_version":1,"x":NaN',
                     b'{"schema_version":1,"schema_version":2,',b'{"schema_version":1,"payload":{"kind":"run_terminal","terminal":"completed","value":',
                     prefix.replace(b'"sequence":12',b'"sequence":0'),prefix.replace(session.encode(),native.encode()),
                     prefix.replace(b'"payload_type":"run.output.delta"',b'"payload_type":"run.terminal.completed"'),
                     prefix.replace(b'"command_id":"'+native.encode(),b'"command_id":"'+session.encode()),
                     prefix+b',"text":"unfinished'):
            self.assertFalse(successor._truncated_metadata_prefix(tail,session,native,11),tail)

    def test_legacy_timeout_plan_contract_at_both_stages(self):
        c=self.c
        record=c.service._store.setting('provider-run:'+json.loads((self.root/'original/events/0004.json').read_bytes())['run_id'])
        c.configure(360);first_plan=successor.plan(c.service._store,predecessor=record['run_id'])
        first=c.execute(record,key='legacy-first');c.configure(720)
        second_plan=successor.plan(c.service._store,predecessor=first['run_id'])
        expected_keys={'format','provider','predecessor_run_id','predecessor_digest','root_run_id','ordinal',
            'bundle_digest','configuration_digest','attempt_seconds','max_output_bytes','max_proposal_bytes',
            'artifact_hashes','enrollment','remaining_controller_slots_including_this',
            'remaining_local_meta_seconds_including_this','history','automatic_retry_allowed','remote_usage_settled',
            'complete_descendant_cessation_proven','model_free','digest'}
        for proof,ordinal,deadline,remaining in ((first_plan,1,360,1080),(second_plan,2,720,720)):
            self.assertEqual(set(proof),expected_keys)
            self.assertEqual(proof['format'],'manual-muse-successor-plan/1')
            self.assertEqual(proof['enrollment']['format'],'manual-muse-ladder/1')
            self.assertEqual(proof['enrollment']['deadlines_seconds'],[360,720])
            self.assertEqual(proof['ordinal'],ordinal);self.assertEqual(proof['attempt_seconds'],deadline)
            self.assertEqual(proof['remaining_local_meta_seconds_including_this'],remaining)
            self.assertEqual(proof['digest'],digest(proof));self.assertNotIn('reason',proof)

    def test_cli_uses_explicit_capture_reason_and_only_observes_repetition(self):
        from taskalong.cli import main
        def cli(args):
            stream=io.StringIO()
            with contextlib.redirect_stdout(stream):code=main(['--json','--state-dir',str(self.root/'state'),*args])
            return code,json.loads(stream.getvalue())
        code,value=cli(['provider-successor-plan','muse','--reason','capture','--predecessor',self.original['run_id']])
        self.assertEqual(code,0);self.c.mode='success'
        args=['provider-successor','muse','--reason','capture','--predecessor',self.original['run_id'],
            '--plan-digest',value['data']['digest'],'--key','cli-capture','--output',str(self.root/'cli-capture')]
        code,child=cli(args);self.assertEqual(code,0);self.assertEqual(child['data']['state'],'proposal_ready')
        self.assertEqual(cli(args)[1],child);self.assertEqual(len(self.c.calls),3)

    def test_artifact_marker_and_interior_protocol_drift_refuse(self):
        root=Path(self.original['output']);proof=self.plan()
        for name in ('prompt.txt','invocation.json','stdout.bin','process.json'):
            path=root/name;old=path.read_bytes();path.chmod(0o600);path.write_bytes(old+b'!');path.chmod(0o400)
            with self.subTest(name=name),self.assertRaises(TaskAlongError):self.execute(proof=proof)
            path.chmod(0o600);path.write_bytes(old);path.chmod(0o400)
        marker=Path(self.original['bundle'])/'provider-submission.json';old=marker.read_bytes()
        marker.chmod(0o600);marker.write_bytes(canonical_bytes({'provider':'muse','run_id':'wrong','bundle_digest':self.original['bundle_digest']}));marker.chmod(0o400)
        with self.assertRaises(TaskAlongError):self.plan()
        marker.chmod(0o600);marker.write_bytes(old);marker.chmod(0o400)
        self.assertEqual(self.plan(),proof);self.assertEqual(len(self.c.calls),2)

    def test_partial_anchor_and_copied_state_refuse_without_dispatch(self):
        with RunService(self.root/'copied') as copied:
            self.service._store.db.backup(copied._store.db)
            proof=self.plan()
            # The same evidence in another State cannot consume a slot after enrollment.
            self.execute(proof=proof)
            with self.assertRaises(TaskAlongError):copied.provider_successor_plan(predecessor=self.original['run_id'],reason='capture')
        self.assertEqual(len(self.c.calls),3)

    def test_competing_keys_create_only_one_capture_child(self):
        proof=self.plan();release=threading.Event();owner=self.c.owner
        def held(argv,**options):
            if not release.wait(5):raise AssertionError('release missing')
            return owner(argv,**options)
        def invoke(key):
            with RunService(self.root/'state') as service:
                return service.provider_successor(predecessor=self.original['run_id'],key=key,plan_digest=proof['digest'],output=str(self.root/key),reason='capture')
        with patch.object(muse,'run_foreground_experiment',side_effect=held),concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures=[pool.submit(invoke,key) for key in ('one','two')]
            done,_=concurrent.futures.wait(futures,timeout=5,return_when=concurrent.futures.FIRST_COMPLETED)
            try:
                self.assertEqual(len(done),1)
                with self.assertRaises(TaskAlongError):next(iter(done)).result()
            finally:release.set()
            successes=[]
            for future in futures:
                try:successes.append(future.result(timeout=5))
                except TaskAlongError:pass
        self.assertEqual(len(successes),1);self.assertEqual(len(self.c.calls),3);self.c.assert_original()


if __name__=='__main__':unittest.main()
