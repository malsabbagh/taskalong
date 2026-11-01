"""Interrupted /6 lineage with disposable State and synthetic native evidence."""
import concurrent.futures
import copy
import errno
import json
import os
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

from taskalong.api import RunService
from taskalong import muse_experimental as muse, muse_interrupted_recovery as recovery
from taskalong import muse_successor as successor
from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes, digest
import test_muse_successor as fixtures
from test_muse_native_lifecycle import row as task_row, TASK, SECOND


@unittest.skipUnless(os.name == 'posix', 'Private local evidence requires POSIX')
class InterruptedSuccessorTests(unittest.TestCase):
    def setUp(self):
        self.c = fixtures.SuccessorTests('test_two_explicit_timeouts_use_360_then_720_and_preserve_history')
        self.c.setUp(); self.addCleanup(self.c.doCleanups)
        self.root, self.service = self.c.root, self.c.service
        self.configure()
        with patch.object(muse, 'run_foreground_experiment', side_effect=self.interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.service.run_provider(request=self.c.request | {'task': 'Independent interrupted /6 synthetic intent.'},
                    output=str(self.root/'interrupted'))
        manifest = json.loads((self.root/'interrupted/bundle/bundle.json').read_bytes())
        claim = self.service._store.setting('provider-claim:muse:'+manifest['digest'])
        self.original = self.service.result(claim['run_id'])
        self.c.original = self.original
        self.c.original_record = canonical_bytes(self.original)
        self.c.original_claim = canonical_bytes(claim)
        self.c.original_bytes = {p.relative_to(self.root/'interrupted').as_posix():p.read_bytes()
            for p in (self.root/'interrupted').rglob('*') if p.is_file()}
        self.c.original_journal = self.c.journals[-1]
        self.c.original_native = self.c.original_journal.read_bytes()
        self.absent = self.enterContext(patch.object(recovery, 'receipt_is_alive', return_value=False))

    def configure(self,**changes):
        return self.service.configure_provider('muse', {'executable':str(self.c.binary),'account_home':str(self.c.home),
            'muse_home':str(self.c.data),'attempt_seconds':1440,'capture_profile':'megabyte-proposal',
            'max_output_bytes':67108864,'max_protocol_records':131072,'max_proposal_bytes':1048576,**changes})

    def rows(self, linked, *, repeated=True):
        session, native = linked['stream']['id'], linked['payload']['run_stream']['id']
        linked = linked | {'payload_schema_version':1}
        accepted = linked | {'payload_type':'runtime.command.accepted','payload':{
            'kind':'command_accepted','client_id':'synthetic-client','command_id':native,'command_kind':'run'}}
        rows = [accepted,linked|{'sequence':2}]
        for task in ([TASK,SECOND] if repeated else [TASK]):
            for kind in ('proposed','side_effect_intent','started','timed_out' if repeated else 'completed'):
                row = task_row(len(rows)+1,kind,task)
                row['stream']['id'] = session
                row['payload']['command_id'] = native
                row['payload']['run_stream']['id'] = native
                rows.append(row)
        return rows

    def interrupt(self, argv, **options):
        result = self.c.owner(argv, **options)
        linked = json.loads(result.stdout.splitlines()[0])
        raw = b''.join(canonical_bytes(row)+b'\n' for row in self.rows(linked))
        options['_on_output_chunk']('stdout',raw)
        for line in raw.splitlines():options['on_stdout_line'](line)
        journal=self.c.journals[-1]
        rows=[json.loads(line) for line in journal.read_bytes().splitlines()]
        journal.write_bytes(b''.join(canonical_bytes(row)+b'\n' for row in rows[:-1]))
        raise KeyboardInterrupt()

    def child(self, argv, **options):
        previous=self.c.mode;self.c.mode='success'
        try:result=self.c.owner(argv, **options)
        finally:self.c.mode=previous
        linked,terminal=[json.loads(line) for line in result.stdout.splitlines()]
        rows=self.rows(linked,repeated=False)
        rows.append(terminal|{'sequence':len(rows)+1,'payload_schema_version':1})
        raw=b''.join(canonical_bytes(row)+b'\n' for row in rows)
        options['_on_output_chunk']('stdout',raw)
        for line in raw.splitlines():options['on_stdout_line'](line)
        result.stdout=b'' if options.get('_retain_output') is False else raw
        info=result.to_dict()|{'output_bytes':len(raw)}
        result.to_dict=lambda:info
        return result

    def plan(self,service=None):
        return (service or self.service).provider_successor_plan(predecessor=self.original['run_id'],reason='interrupted')

    def execute(self,proof=None,*,key='replacement',service=None):
        return (service or self.service).provider_successor(predecessor=self.original['run_id'],reason='interrupted',key=key,
            plan_digest=(proof or self.plan())['digest'],output=str(self.root/key))

    def journal(self,transform):
        path=self.c.original_journal
        rows=[json.loads(line) for line in path.read_bytes().splitlines()]
        path.write_bytes(b''.join(json.dumps(row,separators=(',',':')).encode()+b'\n' for row in transform(rows)))

    def test_plan_retains_unknowns_incomplete_capture_and_historical_starts(self):
        proof=self.plan()
        self.assertEqual(proof['format'],'manual-muse-successor-plan/4')
        self.assertEqual(proof['enrollment']['format'],'manual-muse-ladder/4')
        self.assertEqual(proof['remaining_controller_slots_including_this'],1)
        self.assertEqual(proof['native_lifecycle_policy'],recovery.POLICY)
        self.assertFalse(proof['complete_descendant_cessation_proven'])
        self.assertFalse(proof['remote_usage_settled'])
        self.assertFalse(proof['hard_native_attempt_limit_enforced'])
        self.assertFalse(proof['original_capture']['byte_closure'])
        self.assertFalse(proof['original_capture']['observed_counts_complete'])
        self.assertEqual(proof['original_capture']['native_lifecycle']['model_tasks_started'],2)
        self.assertEqual(proof['native_model_task_starts_observed_lower_bound'],2)
        self.assertEqual(self.absent.call_count,2)
        self.c.assert_original()

    def test_explicit_one_replacement_uses_existing_owner_and_is_final(self):
        proof=self.plan()
        with patch.object(muse,'run_foreground_experiment',side_effect=self.child) as calls:
            result=self.execute(proof)
            self.assertEqual(calls.call_count,1)
        self.assertEqual(result['state'],'proposal_ready')
        self.assertEqual(result['manual_successor']['format'],'manual-muse-successor/4')
        self.assertEqual(result['manual_successor']['native_lifecycle_policy'],recovery.POLICY)
        with patch.object(muse,'run_foreground_experiment',side_effect=AssertionError('no replay')):
            self.assertEqual(self.execute(proof),result)
            with self.assertRaises(TaskAlongError):self.execute(proof,key='different')
            with self.assertRaises(TaskAlongError):
                self.service.provider_successor_plan(predecessor=result['run_id'],reason='interrupted')
        self.c.assert_original()

    def test_preflight_failure_consumes_slot_without_refunding_original_claim(self):
        proof=self.plan()
        with patch.object(muse,'_preflight',side_effect=TaskAlongError('synthetic_preflight','unavailable')):
            with self.assertRaises(TaskAlongError):self.execute(proof)
        first=self.service._store.setting('provider-successor:muse:'+self.original['run_id'])
        with patch.object(muse,'_preflight',side_effect=AssertionError('no replay')):
            result=self.execute(proof)
        self.assertEqual(result['run_id'],first['run_id'])
        self.assertEqual(result['state'],'blocked')
        with self.assertRaises(TaskAlongError):self.execute(proof,key='other')
        self.c.assert_original()

    def test_finalize_failure_retains_owned_process_result_and_consumes_replacement(self):
        from taskalong.local_provider_capture import PrivateCapture
        proof=self.plan()
        with patch.object(muse,'run_foreground_experiment',side_effect=self.child) as calls, \
                patch.object(PrivateCapture,'finalize',side_effect=OSError('synthetic capture failure')):
            with self.assertRaises(TaskAlongError):self.execute(proof)
        self.assertEqual(calls.call_count,1)
        reservation=self.service._store.setting('provider-successor:muse:'+self.original['run_id'])
        result=self.service.result(reservation['run_id'])
        self.assertEqual(result['state'],'failed')
        observation=json.loads((self.root/'replacement/process-owner.json').read_bytes())
        self.assertFalse(observation['capture_finalized'])
        self.assertEqual(observation['root_exit_code'],0)
        self.assertTrue(observation['root_exit_observed'])
        self.assertTrue(observation['group_termination_confirmed'])
        self.assertTrue(observation['native_lifecycle']['protocol_valid'])
        self.assertEqual(observation['native_lifecycle']['model_tasks_started'],1)
        self.assertEqual(result['remote_usage'],'unknown')
        self.assertEqual(result['descendant_cessation'],'unknown')
        self.assertFalse((self.root/'replacement/proposal').exists())
        with patch.object(muse,'run_foreground_experiment',side_effect=AssertionError('no retry')):
            self.assertEqual(self.execute(proof),result)
            with self.assertRaises(TaskAlongError):self.execute(proof,key='again')
        self.c.assert_original()

    def test_either_current_process_probe_live_or_uncertain_refuses_before_slot(self):
        for observations in ([True],[False,True],[None]):
            with self.subTest(observations=observations),patch.object(recovery,'receipt_is_alive',side_effect=observations):
                with self.assertRaises(TaskAlongError):self.plan()
            self.assertFalse(successor._anchor(self.original).exists())

    def test_exact_configuration_scope_and_deadline_are_required(self):
        for changes in ({'attempt_seconds':720},{'reasoning_effort':'max'},{'context':'native-only'},
                        {'model':'another-model'},{'max_proposal_bytes':65536}):
            self.configure(**changes)
            with self.subTest(changes=changes),self.assertRaises(TaskAlongError):self.plan()

    def test_completed_committed_hidden_and_foreign_journal_material_refuses(self):
        original=self.c.original_journal.read_bytes()
        for extra in ({'payload':{'kind':'run','run_id':self.native_run(),'event':{'kind':'terminal','terminal':'completed'}}},
                      {'payload':{'kind':'run','run_id':self.native_run(),'event':{'kind':'assistant_message_committed','text':'{}'}}},
                      {'payload':{'kind':'metadata','record':{'kind':'run_terminal','terminal':'completed'}}},
                      {'payload':{'kind':'run','run_id':'foreign','event':{'kind':'status'}}}):
            self.c.original_journal.write_bytes(original)
            self.journal(lambda rows:rows+[extra])
            with self.subTest(extra=extra),self.assertRaises(TaskAlongError):self.plan()

    def native_run(self):
        invocation=json.loads((self.root/'interrupted/invocation.json').read_bytes())
        rows=[json.loads(line) for line in (self.root/'interrupted/capture/stdout.bin').read_bytes().splitlines()]
        first=next(row for row in rows if 'run_stream' in row['payload'])
        self.assertEqual(first['stream']['id'],invocation['session_id'])
        return first['payload']['run_stream']['id']

    def test_missing_or_wrong_tools_metadata_and_numeric_identity_refuse(self):
        original=self.c.original_journal.read_bytes()
        for transform in (lambda r:r[:1],lambda r:r[:1]+[{'payload':r[1]['payload']|{'event':{'kind':'model_request_configured','toolset':{'active_tools':['tool']},'reminder_roster':{'agents':[]}}}}],
                          lambda r:[{'payload':{'kind':'metadata','record':{'provider_id':'meta','model_id':1.5}}}]+r[1:]):
            self.c.original_journal.write_bytes(original);self.journal(transform)
            with self.assertRaises(TaskAlongError):self.plan()

    def test_torn_capture_or_invalid_row_after_old_timeout_refuses(self):
        path=self.root/'interrupted/capture/stdout.bin';original=path.read_bytes()
        for tail in (b'{',b'bad json\n',b'\xff\n'):
            path.write_bytes(original+tail)
            with self.subTest(tail=tail),self.assertRaises(TaskAlongError):self.plan()

    def test_accepted_result_or_history_mutation_refuses(self):
        output=self.root/'interrupted/response.json';output.write_bytes(b'{}')
        with self.assertRaises(TaskAlongError):self.plan()
        output.unlink()
        path=self.root/'interrupted/events/0001.json';path.chmod(0o600);path.write_bytes(path.read_bytes()+b' ');path.chmod(0o400)
        with self.assertRaises(TaskAlongError):self.plan()

    def test_changed_journal_during_final_absence_check_refuses(self):
        calls=[]
        def probe(_receipt):
            calls.append(1)
            if len(calls)==2:self.journal(lambda rows:rows+[{'payload':{'kind':'run','run_id':self.native_run(),'event':{'kind':'status'}}}])
            return False
        with patch.object(recovery,'receipt_is_alive',side_effect=probe),self.assertRaises(TaskAlongError):self.plan()
        self.assertFalse(successor._anchor(self.original).exists())

    def test_completed_or_disguised_capture_terminal_is_never_ignored(self):
        path=self.root/'interrupted/capture/stdout.bin';raw=path.read_bytes()
        first=json.loads(raw.splitlines()[0]);count=len(raw.splitlines())
        terminal=first|{'sequence':count+1,'payload_type':'run.terminal.completed','payload':{
            'kind':'run_terminal','run_stream':{'kind':'run','id':self.native_run()},'terminal':'completed','text':'{}'}}
        for row in (terminal,terminal|{'payload_type':'opaque'}):
            path.write_bytes(raw+canonical_bytes(row)+b'\n')
            with self.subTest(row=row),self.assertRaises(TaskAlongError):self.plan()

    def test_foreign_session_sequence_and_payload_version_capture_refuse(self):
        path=self.root/'interrupted/capture/stdout.bin';raw=path.read_bytes()
        rows=[json.loads(line) for line in raw.splitlines()]
        for changed in (rows[1]|{'sequence':999},rows[1]|{'stream':{'kind':'session','id':'foreign'}},
                        rows[1]|{'payload_schema_version':True},rows[1]|{'payload':rows[1]['payload']|{'command_id':'foreign'}}):
            path.write_bytes(b''.join(canonical_bytes(row)+b'\n' for row in [rows[0],changed,*rows[2:]]))
            with self.subTest(changed=changed),self.assertRaises(TaskAlongError):self.plan()

    def test_first_command_accepted_requires_later_consistent_run_binding(self):
        self.assertEqual(self.plan()['original_capture']['records_observed'],10)
        path=self.root/'interrupted/capture/stdout.bin';rows=[json.loads(line) for line in path.read_bytes().splitlines()]
        rows[0]['payload']['command_id']='00000000-0000-4000-8000-000000000000'
        path.write_bytes(b''.join(canonical_bytes(row)+b'\n' for row in rows))
        with self.assertRaises(TaskAlongError):self.plan()

    def test_cancelled_or_failed_journal_terminal_is_observation_not_required_settlement(self):
        original=self.c.original_journal.read_bytes()
        for terminal in ('cancelled','failed'):
            self.c.original_journal.write_bytes(original)
            self.journal(lambda rows:rows+[{'payload':{'kind':'run','run_id':self.native_run(),'event':{'kind':'terminal','terminal':terminal}}}])
            proof=self.plan()
            self.assertEqual(proof['native_journal']['native_terminal_observed'],terminal)
            self.assertFalse(proof['remote_usage_settled'])

    def test_terminal_cannot_hide_model_or_committed_activity(self):
        original=self.c.original_journal.read_bytes()
        for kind in ('assistant_message_committed','model_request_configured'):
            self.c.original_journal.write_bytes(original)
            self.journal(lambda rows:rows+[{'payload':{'kind':'run','run_id':self.native_run(),'event':{
                'kind':'terminal','terminal':'cancelled','hidden':{'kind':kind,'text':'hidden'}}}}])
            with self.subTest(kind=kind),self.assertRaises(TaskAlongError):self.plan()

    def test_changed_scope_between_reservation_and_preflight_is_consumed_not_rebased(self):
        proof=self.plan();real=muse.run
        def change(*args,**kwargs):
            self.configure(attempt_seconds=720)
            return real(*args,**kwargs)
        with patch.object(muse,'run',side_effect=change),self.assertRaises(TaskAlongError):self.execute(proof)
        reservation=self.service._store.setting('provider-successor:muse:'+self.original['run_id'])
        self.assertIsNotNone(reservation)
        self.configure()
        with patch.object(muse,'run',side_effect=AssertionError('no resume')):
            result=self.execute(proof)
        self.assertEqual(result['state'],'reserved_incomplete')

    def test_guard_policy_mismatch_cannot_pass_predispatch_check(self):
        proof=self.plan()
        with patch.object(muse,'run',side_effect=TaskAlongError('synthetic','stop before process')):
            with self.assertRaises(TaskAlongError):self.execute(proof)
        reservation=self.service._store.setting('provider-successor:muse:'+self.original['run_id'])
        forged=reservation|{'native_lifecycle_policy':'disabled'};forged['digest']=digest(forged)
        for name in ('provider-successor:muse:'+self.original['run_id'],'provider-successor-run:muse:'+forged['run_id'],
                     'provider-successor-key:muse:'+forged['key_digest']):self.service._store.set_setting(name,forged)
        with self.assertRaises(TaskAlongError):successor._check(self.service._store,forged,muse._configuration(self.service._store))

    def test_reused_operation_key_different_output_and_reason_refuse(self):
        proof=self.plan()
        with patch.object(muse,'_preflight',side_effect=TaskAlongError('synthetic','unavailable')):
            with self.assertRaises(TaskAlongError):self.execute(proof)
        for changes in ({'output':str(self.root/'different')},{'reason':'capture'}):
            values={'predecessor':self.original['run_id'],'key':'replacement','plan_digest':proof['digest'],
                    'output':str(self.root/'replacement'),'reason':'interrupted'}|changes
            with self.assertRaises(TaskAlongError):self.service.provider_successor(**values)

    def test_two_concurrent_requests_reserve_one_slot_before_preflight(self):
        proof=self.plan();barrier=threading.Barrier(2)
        def attempt(key):
            with RunService(self.root/'state') as service:
                barrier.wait()
                try:return self.execute(proof,key=key,service=service)
                except TaskAlongError as exc:return exc
        with patch.object(muse,'_preflight',side_effect=TaskAlongError('synthetic','unavailable')) as preflight:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(attempt,('first','second')))
        self.assertEqual(preflight.call_count,1)
        self.assertTrue(all(isinstance(result,TaskAlongError) for result in results))
        self.c.assert_original()

    def test_running_or_mismatched_receipt_history_is_not_an_interrupted_original(self):
        original=self.original
        for updates in ({'state':'running'}, {'controller_submissions':0}, {'remote_usage':'not_sent'},
                        {'process_receipt':original['process_receipt']|{'invocation_id':'00000000-0000-4000-8000-000000000000'}}):
            self.c.replace_record(original,**updates)
            with self.subTest(updates=updates),self.assertRaises(TaskAlongError):self.plan()
        self.assertFalse(successor._anchor(original).exists())

    def test_owner_event_changed_after_journal_read_refuses_before_slot(self):
        real=recovery._journal;once=[]
        def changed(*args):
            value=real(*args)
            if not once:
                once.append(1)
                path=self.root/'interrupted/events/0001.json'
                path.chmod(0o600);path.write_bytes(path.read_bytes()+b' ');path.chmod(0o400)
            return value
        with patch.object(recovery,'_journal',side_effect=changed),self.assertRaises(TaskAlongError):self.plan()
        self.assertFalse(successor._anchor(self.original).exists())

    def test_same_bytes_capture_replacement_during_absence_probe_is_a_change(self):
        calls=[]
        def probe(_receipt):
            calls.append(1)
            if len(calls)==2:
                path=self.root/'interrupted/capture/stdout.bin';raw=path.read_bytes()
                path.unlink();path.write_bytes(raw);path.chmod(0o600)
            return False
        with patch.object(recovery,'receipt_is_alive',side_effect=probe),self.assertRaises(TaskAlongError):self.plan()

    def test_journal_alias_or_torn_tail_refuses_before_slot(self):
        path=self.c.original_journal;raw=path.read_bytes()
        other=path.with_name('alias.jsonl');other.write_bytes(raw)
        path.unlink();path.symlink_to(other)
        with self.assertRaises(TaskAlongError):self.plan()
        path.unlink();path.write_bytes(raw+b'{')
        with self.assertRaises(TaskAlongError):self.plan()

    def test_noncontiguous_journal_sequences_are_allowed_with_exactly_one_configuration(self):
        self.journal(lambda rows:[rows[0]|{'sequence':2},rows[1]|{'sequence':99}])
        self.assertEqual(self.plan()['native_journal']['configured_model_requests_observed_lower_bound'],1)

    def test_zero_or_two_journal_model_configurations_refuse(self):
        original=self.c.original_journal.read_bytes();native=self.native_run()
        for transform in (lambda rows:rows[:1]+[{'payload':{'kind':'run','run_id':native,'event':{'kind':'native_run_created'}}}],
                          lambda rows:rows+[rows[1]]):
            self.c.original_journal.write_bytes(original);self.journal(transform)
            with self.assertRaises(TaskAlongError):self.plan()

    def test_foreign_identity_cannot_be_hidden_by_later_correct_metadata(self):
        self.journal(lambda rows:[{'payload':{'kind':'metadata','record':{
            'provider_id':'foreign','model_id':'muse-wonder-full-1.0'}}},*rows])
        with self.assertRaises(TaskAlongError):self.plan()

    def test_capture_changed_during_last_journal_observation_is_refenced(self):
        real=recovery._journal;calls=[]
        def changed(*args):
            result=real(*args);calls.append(1)
            if len(calls)==3:
                path=self.root/'interrupted/capture/stdout.bin'
                with path.open('ab') as target:target.write(b'bad final frame\n')
            return result
        with patch.object(recovery,'_journal',side_effect=changed),self.assertRaises(TaskAlongError):self.plan()

    def test_original_new_guard_failure_cannot_be_used_as_another_original(self):
        proof=self.plan()
        with patch.object(muse,'_preflight',side_effect=TaskAlongError('synthetic','unavailable')):
            with self.assertRaises(TaskAlongError):self.execute(proof)
        reservation=self.service._store.setting('provider-successor:muse:'+self.original['run_id'])
        with self.assertRaises(TaskAlongError):
            self.service.provider_successor_plan(predecessor=reservation['run_id'],reason='interrupted')

    def test_recursive_journal_run_session_and_command_bindings(self):
        original=self.c.original_journal.read_bytes();native=self.native_run()
        session=json.loads((self.root/'interrupted/invocation.json').read_bytes())['session_id']
        locations=('top','payload','event','record','nested','list')
        values={'run_id':native,'session_id':session,'command_id':native,
                'run_stream':{'kind':'run','id':native},'session_stream':{'kind':'session','id':session}}
        for location in locations:
            for key,valid in values.items():
                variants=[valid,'foreign',None,False,17]
                if type(valid) is dict:variants += [valid|{'id':'foreign'},valid|{'kind':'wrong'},valid|{'extra':1}]
                for value in variants:
                    self.c.original_journal.write_bytes(original)
                    def changed(rows):
                        row=copy.deepcopy(rows[1])
                        part=row if location=='top' else row['payload'] if location=='payload' else row['payload']['event'] if location=='event' else row['payload'].setdefault('record',{}) if location=='record' else row['payload']['event'].setdefault('details',{}) if location=='nested' else row['payload']['event'].setdefault('details',[{}])[0]
                        part[key]=value
                        return [rows[0],row]
                    self.journal(changed)
                    with self.subTest(location=location,key=key,value=value):
                        if value==valid:self.assertEqual(self.plan()['format'],'manual-muse-successor-plan/4')
                        else:
                            with self.assertRaises(TaskAlongError):self.plan()

    def test_recursive_task_references_are_local_to_declared_lifecycle_row(self):
        original=self.c.original_journal.read_bytes();native=self.native_run()
        for payload in ({'kind':'task_lifecycle','run_id':native,'task_id':TASK,'task_stream':{'kind':'task','id':TASK},
                         'event':{'kind':'status','task_id':TASK,'details':{'task_id':TASK,'task_stream':{'kind':'task','id':TASK}}}},
                        {'kind':'metadata','record':{'first':{'task_id':TASK,'task_stream':{'kind':'task','id':TASK}},
                                                    'second':{'task_id':SECOND,'task_stream':{'kind':'task','id':SECOND}}}}):
            self.c.original_journal.write_bytes(original);self.journal(lambda rows:rows+[{'payload':payload}])
            self.assertEqual(self.plan()['format'],'manual-muse-successor-plan/4')
        base={'kind':'task_lifecycle','run_id':native,'task_id':TASK,'event':{'kind':'status','task_id':TASK}}
        for details in ({'task_id':SECOND},{'task_stream':{'kind':'task','id':SECOND}},
                        {'task_id':TASK,'task_stream':{'kind':'task','id':SECOND}},
                        {'task_stream':{'kind':'session','id':TASK}},{'task_id':False}):
            self.c.original_journal.write_bytes(original)
            self.journal(lambda rows:rows+[{'payload':base|{'event':base['event']|{'details':details}}}])
            with self.subTest(details=details),self.assertRaises(TaskAlongError):self.plan()

    def test_literal_json_text_does_not_create_structured_bindings_or_hidden_result(self):
        self.journal(lambda rows:rows+[{'payload':{'kind':'run','run_id':self.native_run(),'event':{
            'kind':'status','message':'{"run_id":"foreign","session_id":"foreign","command_id":"foreign","response":{}}'}}}])
        self.assertEqual(self.plan()['format'],'manual-muse-successor-plan/4')

    def test_owner_artifacts_and_result_absence_refenced_after_last_capture_reader(self):
        real=recovery._capture;calls=[]
        def changed(*args):
            result=real(*args);calls.append(1)
            if len(calls)==3:
                path=self.root/'interrupted/events/0001.json'
                path.chmod(0o600);path.write_bytes(path.read_bytes()+b' ');path.chmod(0o400)
            return result
        with patch.object(recovery,'_capture',side_effect=changed),self.assertRaises(TaskAlongError):self.plan()
        self.assertFalse(successor._anchor(self.original).exists())

    def test_new_result_path_during_last_capture_reader_refuses_before_reservation(self):
        real=recovery._capture;calls=[]
        def changed(*args):
            result=real(*args);calls.append(1)
            if len(calls)==3:(self.root/'interrupted/response.json').write_bytes(b'{}')
            return result
        with patch.object(recovery,'_capture',side_effect=changed),self.assertRaises(TaskAlongError):self.plan()
        self.assertFalse(successor._anchor(self.original).exists())

    def test_manifest_prompt_invocation_and_marker_refenced_after_last_reader(self):
        real=recovery._capture
        for relative in ('bundle/bundle.json','prompt.txt','invocation.json','bundle/provider-submission.json'):
            path=self.root/'interrupted'/relative;raw=path.read_bytes();calls=[]
            def changed(*args):
                result=real(*args);calls.append(1)
                if len(calls)==3:
                    path.chmod(0o600);path.write_bytes(raw+b' ');path.chmod(0o400)
                return result
            with self.subTest(relative=relative),patch.object(recovery,'_capture',side_effect=changed),self.assertRaises(TaskAlongError):self.plan()
            path.chmod(0o600);path.write_bytes(raw);path.chmod(0o400)

    def test_original_observation_open_failure_closes_all_owned_descriptors(self):
        first=recovery._original(self.service._store,self.original['run_id'],muse._configuration(self.service._store))
        real=recovery.os.open;opened=[]
        def fail(name,*args,**kwargs):
            if name=='invocation.json':raise OSError(errno.EMFILE,'synthetic descriptor refusal')
            fd=real(name,*args,**kwargs);opened.append(fd);return fd
        with patch.object(recovery.os,'open',side_effect=fail),self.assertRaises(OSError):
            with recovery._original_observation(first):self.fail('failed cohort must not become usable')
        self.assertTrue(opened)
        for fd in opened:
            with self.assertRaises(OSError) as caught:os.fstat(fd)
            self.assertEqual(caught.exception.errno,errno.EBADF)

    def test_copied_and_restored_state_cannot_reopen_the_single_anchor(self):
        proof=self.plan()
        with RunService(self.root/'copy') as copied:
            self.service._store.db.backup(copied._store.db)
            with patch.object(muse,'_preflight',side_effect=TaskAlongError('synthetic','unavailable')):
                with self.assertRaises(TaskAlongError):self.execute(proof)
            with self.assertRaises(TaskAlongError):self.plan(copied)
            copied._store.db.backup(self.service._store.db)
            with self.assertRaises(TaskAlongError):self.execute(proof)


if __name__=='__main__':unittest.main()
