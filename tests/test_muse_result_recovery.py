"""Model-free complete-result reconciliation using disposable local evidence."""
import contextlib
import hashlib
import io
import json
import os
import concurrent.futures
import threading
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from taskalong import muse_experimental as muse, muse_result_recovery as recovery
from taskalong.api import RunService
from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes
from test_muse_capture_recovery import torn_record
import test_muse_successor as fixtures


@unittest.skipUnless(os.name == 'posix', 'Private local artifacts are POSIX')
class CompleteResultTests(unittest.TestCase):
    def setUp(self):
        self.c = fixtures.SuccessorTests('test_two_explicit_timeouts_use_360_then_720_and_preserve_history')
        self.c.setUp()
        self.addCleanup(self.c.doCleanups)
        self.root, self.service = self.c.root, self.c.service
        with patch.object(muse, 'run_foreground_experiment', side_effect=self.overflow):
            self.c.original_at(1440, capture_profile='large-task', max_proposal_bytes=65536, max_protocol_records=2048)
        self.original = self.c.original
        self.enterContext(patch.object(muse, 'run_foreground_experiment', side_effect=AssertionError('no native call')))
        self.enterContext(patch.object(muse, '_preflight', side_effect=AssertionError('no preflight')))

    def overflow(self, argv, **options):
        result = self.c.owner(argv, **options)
        linked = json.loads(result.stdout.splitlines()[0])
        session = linked['stream']['id']
        self.native_run = native_run = linked['payload']['run_stream']['id']
        root = Path(argv[argv.index('--workspace') + 1]).parent
        manifest = json.loads((root/'bundle/bundle.json').read_bytes())
        self.response = {'bundle_digest': manifest['digest'], 'changes': {'source.py': 'x' * 51800 + '\n'}}
        self.committed = response = canonical_bytes(self.response).decode()
        rows = [linked, linked | {'sequence': 2, 'payload_type': 'fixture.padding', 'payload': {'padding': ''}}]
        for offset in range(0, len(response), 1400):
            rows.append(linked | {'sequence': len(rows)+1, 'payload_type': 'run.output.delta',
                'payload': {'kind': 'run_output_delta', 'command_id': native_run,
                            'run_stream': {'kind': 'run', 'id': native_run}, 'text': response[offset:offset+1400]}})
        tail = torn_record(session, native_run, len(rows)+1, terminal=True, text=response[:30000])
        initial = b''.join(canonical_bytes(row)+b'\n' for row in rows)
        rows[1]['payload']['padding'] = 'z' * (1048576-len(initial)-len(tail))
        retained = b''.join(canonical_bytes(row)+b'\n' for row in rows)+tail
        self.assertEqual(len(retained), 1048576)
        full = retained+b' discarded suffix"}}\n'
        options['_on_output_chunk']('stdout', full)
        for line in full.splitlines():
            options['on_stdout_line'](line)
        journal = self.c.journals[-1]
        rows = [json.loads(line) for line in journal.read_bytes().splitlines()]
        rows[-1]['payload']['event'].update(terminal='completed', reason=None)
        rows.insert(-1, {'payload': {'kind': 'run', 'run_id': native_run,
            'event': {'kind': 'assistant_message_committed', 'text': response}}})
        journal.write_bytes(b''.join(canonical_bytes(row)+b'\n' for row in rows))
        info = result.to_dict() | {'root_exit_code': 130, 'timed_out': False, 'cancelled': False,
                                   'output_limited': True, 'output_bytes': len(full)}
        return SimpleNamespace(stdout=retained, stderr=b'', root_exit_code=130, timed_out=False,
            cancelled=False, output_limited=True, failure_code=None, to_dict=lambda: info)

    def plan(self, service=None):
        return (service or self.service).provider_result_recovery_plan(run_id=self.original['run_id'])

    def execute(self, proof=None, *, key='reconcile', output=None, service=None):
        return (service or self.service).recover_provider_result(run_id=self.original['run_id'], key=key,
            plan_digest=(proof or self.plan())['digest'], output=str(output or self.root/'recovered'))

    def journal(self, transform):
        path = self.c.original_journal
        rows = [json.loads(line) for line in path.read_bytes().splitlines()]
        path.write_bytes(b''.join(json.dumps(row, ensure_ascii=False, separators=(',', ':')).encode()+b'\n' for row in transform(rows)))

    def test_full_journal_and_terminal_prefix_stage_without_native_or_original_changes(self):
        proof = self.plan()
        self.assertTrue(proof['model_free'])
        self.assertEqual(proof['requested_effort'],'high')
        self.assertIsNone(proof['journal']['reported_effort'])
        self.assertEqual(proof['response_bytes'], len(self.committed.encode()))
        self.assertEqual(proof['response_sha256'], hashlib.sha256(self.committed.encode()).hexdigest())
        self.assertNotIn(self.committed, json.dumps(proof))
        result = self.execute(proof)
        self.assertEqual(result['state'], 'recovered_proposal_ready')
        self.assertEqual(result['new_controller_submissions'], 0)
        self.assertEqual((self.root/'recovered/proposal/response.json').read_bytes(), canonical_bytes(self.response))
        self.assertEqual((self.root/'recovered/snapshot-bundle/provider-submission.json').read_bytes(),
                         (Path(self.original['bundle'])/'provider-submission.json').read_bytes())
        self.c.assert_original()

    def test_same_key_observes_only_even_if_journal_disappears(self):
        proof = self.plan(); result = self.execute(proof)
        self.c.original_journal.unlink()
        with patch.object(recovery, '_material', side_effect=AssertionError('no replay')):
            self.assertEqual(self.execute(proof), result)

    def test_changed_key_output_and_plan_cannot_restage(self):
        proof = self.plan(); self.execute(proof)
        for changes in ({'key': 'other'}, {'output': self.root/'other'}, {'proof': {'digest': '0'*64}}):
            with self.subTest(changes=changes), self.assertRaises(TaskAlongError):
                self.execute(**({'proof': proof} | changes))

    def test_inactive_configuration_and_missing_binary_do_not_trigger_native_probes(self):
        self.service._store.set_setting('provider:muse', {'disabled': True})
        self.c.binary.unlink()
        self.assertTrue(self.plan()['model_free'])

    def test_journal_order_duplicate_and_conflicting_outcomes_refuse(self):
        original = self.c.original_journal.read_bytes()
        variants = [lambda r: [r[0], r[2], r[1], r[3]], lambda r: r+[r[3]],
                    lambda r: r[:2]+[r[2], r[2], r[3]], lambda r: r[:2]+[r[3]],
                    lambda r: r[:3]+[{'payload': {'kind': 'run', 'run_id': self.native_run,
                        'event': {'kind': 'terminal', 'terminal': 'cancelled'}}}],
                    lambda r: r+[r[1]], lambda r: r+[r[2]]]
        for transform in variants:
            self.c.original_journal.write_bytes(original)
            self.journal(transform)
            with self.subTest(transform=transform), self.assertRaises(TaskAlongError): self.plan()

    def test_foreign_bindings_identity_types_and_tools_refuse(self):
        original = self.c.original_journal.read_bytes()
        for index, update in ((1, {'run_id': 'foreign'}), (2, {'run_id': False}),
                              (0, {'record': {'provider_id': 'meta', 'model_id': 1.5}}),
                              (1, {'event': {'kind': 'model_request_configured', 'toolset': {'active_tools': ['tool']}, 'reminder_roster': {'agents': []}}})):
            self.c.original_journal.write_bytes(original)
            self.journal(lambda rows: [row if n != index else {'payload': row['payload'] | update} for n,row in enumerate(rows)])
            with self.subTest(update=update), self.assertRaises(TaskAlongError): self.plan()

    def test_torn_missing_and_disguised_terminal_journal_refuse(self):
        original = self.c.original_journal.read_bytes()
        for raw in (original[:-1], original+b'{', original.replace(b'"terminal":"completed"', b'"terminal":"failed"'),
                    original+b'{"payload":{"kind":"metadata","record":{"kind":"run_terminal","terminal":"completed"}}}\n'):
            self.c.original_journal.write_bytes(raw)
            with self.subTest(raw=raw[-80:]), self.assertRaises(TaskAlongError): self.plan()

    def test_bound_harmless_trailing_metadata_and_irrelevant_decimals_are_accepted(self):
        self.journal(lambda rows: rows+[{'payload': {'kind': 'metadata', 'run_id': self.native_run,
            'record': {'provider_id': 'meta', 'model_id': 'muse-wonder-full-1.0', 'duration': 1.5}}}])
        self.assertEqual(self.plan()['journal']['records'], 5)

    def session_end(self, **changes):
        invocation = json.loads((Path(self.original['output'])/'invocation.json').read_bytes())
        return {'schema_version':1, 'payload_schema_version':1, 'sequence':64,
                'stream':{'kind':'session','id':invocation['session_id']},
                'record_type':'event', 'durability':'durable', 'payload_type':'session.end',
                'payload':{'kind':'session_end','record':{'session_id':invocation['session_id'],
                            'reason':'normal', **changes}}}

    def test_bound_durable_session_end_after_completion_supports_local_recovery(self):
        self.journal(lambda rows: rows+[self.session_end()])
        # This completes the disposable input evidence before recovery observes it.
        self.c.original_native = self.c.original_journal.read_bytes()
        proof = self.plan()
        self.assertEqual(proof['journal']['records'], 5)
        self.assertEqual(proof['response_sha256'], hashlib.sha256(self.committed.encode()).hexdigest())
        result = self.execute(proof)
        self.assertEqual(result['state'], 'recovered_proposal_ready')
        self.assertEqual(result['new_controller_submissions'], 0)
        self.c.assert_original()

    def test_session_end_requires_exact_wrapper_binding_and_durable_event(self):
        original = self.c.original_journal.read_bytes()
        good = self.session_end()
        variants = [good|{'durability':'ephemeral'}, good|{'record_type':'status'},
                    good|{'payload_type':'session.metadata'}, good|{'payload_schema_version':True},
                    good|{'stream':{'kind':'session','id':'foreign'}},
                    good|{'payload':good['payload']|{'event':{}}},
                    good|{'payload':{'kind':'session_end','record':[]}},
                    self.session_end(session_id='foreign'), self.session_end(run_id='foreign'),
                    self.session_end(command_id='foreign'), self.session_end(provider_id='other'),
                    self.session_end(model_id='other')]
        for value in variants:
            self.c.original_journal.write_bytes(original)
            self.journal(lambda rows: rows+[value])
            with self.subTest(value=value), self.assertRaises(TaskAlongError):
                self.plan()

    def test_session_end_cannot_hide_post_terminal_activity_or_results(self):
        original = self.c.original_journal.read_bytes()
        values = [{'kind':'model_request_configured'}, {'kind':'assistant_message_committed'},
                  {'kind':'run_output_delta'}, {'kind':'task_lifecycle'},
                  {'task_kind':'model.meta.response'}, {'operation':'model.meta.response'},
                  {'payload_type':'run.model.configured'}, {'text':'unsealed'},
                  {'result':{}}, {'response':{}}, {'changes':{}},
                  {'event':{'kind':'started'}}, {'run_id':'foreign'}, {'session_id':'foreign'},
                  {'stream':{'kind':'session','id':'foreign'}}, {'stream':{'kind':'run','id':'foreign'}},
                  {'stream':{'kind':'task','id':'foreign'}}, {'stream':None},
                  {'stream':{'kind':'run','id':self.native_run,'extra':True}},
                  {'kind':'session','id':'foreign'}, {'kind':'run','id':'foreign'}]
        for value in values:
            self.c.original_journal.write_bytes(original)
            end = self.session_end(details=[value])
            self.journal(lambda rows: rows+[end])
            with self.subTest(value=value), self.assertRaises(TaskAlongError):
                self.plan()
        self.c.original_journal.write_bytes(original)
        end = self.session_end()|{'hidden':{'kind':'task_lifecycle','operation':'model.meta.response'}}
        self.journal(lambda rows:rows+[end])
        with self.assertRaises(TaskAlongError):self.plan()

    def test_session_end_matching_nested_references_are_passive_metadata(self):
        session = self.session_end()['stream']['id']
        end = self.session_end(details=[{'stream':{'kind':'session','id':session}},
            {'stream':{'kind':'run','id':self.native_run}}, {'kind':'run','id':self.native_run}])
        self.journal(lambda rows:rows+[end])
        self.assertEqual(self.plan()['journal']['records'],5)

    def test_session_end_is_optional_once_and_final_after_completed_terminal(self):
        original = self.c.original_journal.read_bytes()
        good = self.session_end()
        variants = [lambda rows:rows[:-1]+[good]+rows[-1:],
                    lambda rows:rows+[good,good|{'sequence':65}],
                    lambda rows:rows+[good,{'payload':{'kind':'metadata','record':{'duration':1}}}],
                    lambda rows:rows+[good,{'payload':{'kind':'run','run_id':self.native_run,
                       'event':{'kind':'model_request_configured'}}}]]
        for number, transform in enumerate(variants):
            self.c.original_journal.write_bytes(original)
            self.journal(transform)
            with self.subTest(variant=number), self.assertRaises(TaskAlongError):self.plan()

    def test_committed_response_must_match_all_deltas(self):
        self.journal(lambda rows: [row if n != 2 else {'payload': row['payload'] | {'event': row['payload']['event'] | {'text': self.committed.replace('xxxx', 'yyyy', 1)}}} for n,row in enumerate(rows)])
        with self.assertRaises(TaskAlongError): self.plan()

    def test_original_result_or_successor_activity_blocks(self):
        for name in ('response.json', 'proposal'):
            path = Path(self.original['output'])/name
            path.write_bytes(b'{}')
            with self.assertRaises(TaskAlongError): self.plan()
            path.unlink()
        self.service._store.set_setting('provider-successor:muse:'+self.original['run_id'], {'existing': True})
        with self.assertRaises(TaskAlongError): self.plan()

    def test_stage_failure_consumes_local_slot_without_replay(self):
        proof = self.plan()
        with patch.object(recovery.pilot, 'stage', side_effect=OSError('injected')):
            with self.assertRaises(TaskAlongError) as exc: self.execute(proof)
        self.assertEqual(exc.exception.effect_outcome, 'uncertain')
        self.assertEqual(self.execute(proof)['state'], 'recovery_incomplete')
        with self.assertRaises(TaskAlongError): self.execute(proof, key='other')
        self.c.assert_original()

    def test_anchor_fsync_failure_leaves_consumed_partial_anchor_no_db_or_output(self):
        proof = self.plan()
        with patch.object(recovery.os, 'fsync', side_effect=OSError('injected')):
            with self.assertRaises(TaskAlongError): self.execute(proof)
        self.assertTrue(recovery._anchor(self.original).is_dir())
        self.assertIsNone(self.service._store.setting('provider-result-recovery:muse:'+self.original['run_id']))
        self.assertFalse((self.root/'recovered').exists())
        with self.assertRaises(TaskAlongError): self.execute(proof)

    def test_copied_state_cannot_reserve_or_adopt_original_anchor(self):
        proof = self.plan()
        with RunService(self.root/'copied-state') as copy:
            self.service._store.db.backup(copy._store.db)
            self.execute(proof)
            with self.assertRaises(TaskAlongError): self.execute(proof, service=copy)

    def test_plan_change_before_reservation_has_no_output_or_anchor(self):
        proof = self.plan()
        self.journal(lambda rows: rows+[{'payload': {'kind': 'metadata', 'record': rows[0]['payload']['record']}}])
        with self.assertRaises(TaskAlongError): self.execute(proof)
        self.assertFalse(recovery._anchor(self.original).exists())
        self.assertFalse((self.root/'recovered').exists())

    def test_recovered_bundle_has_original_dispatch_fence_before_valid_manifest(self):
        proof = self.plan(); writes=[]; real=recovery.pilot._write
        def record(root,name,data):
            if Path(root).name == 'snapshot-bundle': writes.append(name)
            return real(root,name,data)
        with patch.object(recovery.pilot, '_write', side_effect=record): self.execute(proof)
        self.assertEqual(writes[:3], ['provider-submission.json', 'prompt.txt', 'bundle.json'])
        with RunService(self.root/'fresh-state') as fresh:
            config=self.service._store.setting('provider-config:'+self.original['configuration_digest'])
            fresh._store.set_setting('provider:muse',config)
            fresh._store.set_setting('provider-config:'+config['digest'],config)
            with self.assertRaises(TaskAlongError) as exc:
                fresh.run_provider(bundle=str(self.root/'recovered/snapshot-bundle'), output=str(self.root/'must-not-run'))
            self.assertEqual(exc.exception.code, 'provider_already_submitted')

    def test_bound_lifecycle_statistics_between_commit_and_terminal_do_not_require_adjacency(self):
        self.journal(lambda rows: rows[:3]+[{'payload':{'kind':'run','run_id':self.native_run,
            'event':{'kind':'task_lifecycle_observed','elapsed':1.5}}}]+rows[3:])
        self.assertEqual(self.plan()['journal']['records'],5)

    def test_known_output_after_commit_or_hidden_native_model_activity_refuses(self):
        original=self.c.original_journal.read_bytes()
        for extra in ({'payload':{'kind':'run','run_id':self.native_run,'event':{'kind':'output','text':'later'}}},
                      {'payload_type':'run.model.progress','payload':{'kind':'run','run_id':self.native_run}},
                      {'payload':{'kind':'metadata','record':{'kind':'assistant_message_committed','text':'hidden'}}}):
            self.c.original_journal.write_bytes(original)
            self.journal(lambda rows: rows[:3]+[extra]+rows[3:])
            with self.subTest(extra=extra),self.assertRaises(TaskAlongError):self.plan()

    def test_prefix_terminal_text_binding_order_and_escaping_must_agree(self):
        material=recovery._original(self.service._store,self.original['run_id'])
        raw=material['stdout']; head,_,tail=raw.rpartition(b'\n')
        variants=[head+b'\n'+tail.replace(b'"terminal":"completed"',b'"terminal":"failed"'),
                  head+b'\n'+tail.replace(self.native_run.encode(),b'00000000-0000-4000-8000-000000000000'),
                  head+b'\n'+tail+b'\\', head+b'\n'+tail+b'\xff',
                  head+b'\n'+tail.replace(b'"text":"{',b'"text":"['),
                  raw.replace(b'"payload_type":"run.output.delta"',b'"payload_type":"fixture.hidden"',1)]
        for value in variants:
            with self.subTest(tail=value[-20:]), self.assertRaises((TaskAlongError,ValueError,UnicodeError)):
                recovery._prefix(material|{'stdout':value},self.native_run,self.committed)

    def test_native_completed_full_terminal_and_harmless_bound_trailer_are_supported(self):
        material=recovery._original(self.service._store,self.original['run_id'])
        head,_,_=material['stdout'].rpartition(b'\n')
        linked=json.loads(head.splitlines()[0]); count=len(head.splitlines())
        terminal=linked|{'sequence':count+1,'payload_type':'run.terminal.completed','payload':{
            'kind':'run_terminal','command_id':self.native_run,'run_stream':{'kind':'run','id':self.native_run},
            'terminal':'completed','text':self.committed}}
        trailer=linked|{'sequence':count+2,'payload_type':'session.metadata','payload':{
            'kind':'metadata','run_id':self.native_run,'record':{'duration':3}}}
        full=head+b'\n'+canonical_bytes(terminal)+b'\n'+canonical_bytes(trailer)+b'\n'
        recovery._prefix(material|{'stdout':full},self.native_run,self.committed)
        for later in (terminal|{'sequence':count+2}, linked|{'sequence':count+2,'payload_type':'run.output.delta',
                'payload':{'kind':'run_output_delta','command_id':self.native_run,'text':'later'}}):
            with self.assertRaises(TaskAlongError):
                recovery._prefix(material|{'stdout':head+b'\n'+canonical_bytes(terminal)+b'\n'+canonical_bytes(later)+b'\n'},self.native_run,self.committed)

    def test_hidden_commit_or_configuration_cannot_supply_an_extra_result(self):
        original=self.c.original_journal.read_bytes()
        for kind in ('assistant_message_committed','model_request_configured','run_output_delta'):
            self.c.original_journal.write_bytes(original)
            self.journal(lambda rows: rows[:1]+[{'payload':{'kind':'metadata','record':{'kind':kind,'text':'hidden'}}}]+rows[1:])
            with self.subTest(kind=kind),self.assertRaises(TaskAlongError):self.plan()

    def test_journal_path_alias_and_bound_overflow_refuse(self):
        path=self.c.original_journal; original=path.read_bytes()
        other=path.with_name('alias.jsonl'); other.write_bytes(original)
        path.unlink();path.symlink_to(other)
        with self.assertRaises(TaskAlongError):self.plan()
        path.unlink();path.write_bytes(original)
        with path.open('r+b') as stream:stream.truncate(67108865)
        with self.assertRaises(TaskAlongError):self.plan()

    def test_changed_journal_between_observations_refuses_before_slot(self):
        real=recovery._journal; calls=[]
        def changed(*args):
            result=real(*args);calls.append(1)
            if len(calls)==1:
                self.journal(lambda rows: rows+[{'payload':{'kind':'metadata','record':rows[0]['payload']['record']}}])
            return result
        with patch.object(recovery,'_journal',side_effect=changed),self.assertRaises(TaskAlongError):self.plan()
        self.assertFalse(recovery._anchor(self.original).exists())

    def test_changed_owner_history_during_journal_observation_refuses_before_slot(self):
        real=recovery._journal;calls=[]
        def changed(*args):
            result=real(*args);calls.append(1)
            if len(calls)==1:
                path=Path(self.original['output'])/'events/0001.json'
                raw=path.read_bytes();path.chmod(0o600);path.write_bytes(raw+b' ');path.chmod(0o400)
            return result
        with patch.object(recovery,'_journal',side_effect=changed),self.assertRaises(TaskAlongError):self.plan()
        self.assertFalse(recovery._anchor(self.original).exists())

    def test_cleanup_or_capture_record_count_uncertainty_refuses_without_reservation(self):
        original=self.original
        for change in ({'group_termination_confirmed':False},{'root_exit_observed':False},
                       {'protocol_records_observed':False},{'protocol_records_observed':1},
                       {'protocol_record_limited':True},{'tracking_errors':['lost']}):
            self.c.replace_record(original,process=original['process']|change)
            with self.subTest(change=change),self.assertRaises(TaskAlongError):self.plan()
            self.assertFalse(recovery._anchor(original).exists())

    def test_journal_same_content_replacement_during_read_refuses(self):
        material=recovery._original(self.service._store,self.original['run_id'])
        path=self.c.original_journal;real=recovery.os.read;once=[]
        def replace(fd,count):
            result=real(fd,count)
            if not once:
                once.append(1);raw=path.read_bytes();path.unlink();path.write_bytes(raw)
            return result
        with patch.object(recovery.os,'read',side_effect=replace),self.assertRaises(TaskAlongError):
            recovery._journal(material,self.native_run)

    def test_failure_after_copied_marker_never_creates_replayable_manifest(self):
        proof=self.plan();real=recovery.pilot._write
        def stop(root,name,data):
            if Path(root).name=='snapshot-bundle' and name=='prompt.txt':raise OSError('injected')
            return real(root,name,data)
        with patch.object(recovery.pilot,'_write',side_effect=stop),self.assertRaises(TaskAlongError):self.execute(proof)
        copied=self.root/'recovered/snapshot-bundle'
        self.assertTrue((copied/'provider-submission.json').is_file())
        self.assertFalse((copied/'bundle.json').exists())
        self.assertEqual(self.execute(proof)['state'],'recovery_incomplete')

    def test_no_local_recovery_operation_creates_another_provider_submission_claim(self):
        before=self.service._store.db.execute("SELECT name,document FROM settings WHERE name LIKE 'provider-claim:%' ORDER BY name").fetchall()
        self.execute()
        after=self.service._store.db.execute("SELECT name,document FROM settings WHERE name LIKE 'provider-claim:%' ORDER BY name").fetchall()
        self.assertEqual(before,after)

    def test_original_proposal_bound_is_enforced_independently_of_stage_default(self):
        material=recovery._original(self.service._store,self.original['run_id'])
        with patch.object(recovery,'_original',return_value=material|{'config':material['config']|{'max_proposal_bytes':1024}}):
            with self.assertRaises(TaskAlongError) as exc:self.plan()
        self.assertEqual(exc.exception.code,'provider_result_recovery_response_limit')

    def test_original_capture_tamper_is_not_replaced_by_a_valid_journal(self):
        path=Path(self.original['output'])/'capture/stdout.bin'
        raw=path.read_bytes();path.write_bytes(raw[:-1]+b'X')
        with self.assertRaises(TaskAlongError):self.plan()
        self.assertFalse(recovery._anchor(self.original).exists())

    def test_recovered_artifact_tamper_cannot_be_reported_ready(self):
        proof=self.plan();self.execute(proof)
        path=self.root/'recovered/proposal/response.json';path.chmod(0o600);path.write_bytes(b'{}');path.chmod(0o400)
        with self.assertRaises(TaskAlongError):self.execute(proof)

    def tamper_during_stage(self, relative):
        proof=self.plan();real=recovery.pilot.stage
        def changed(**kwargs):
            report=real(**kwargs)
            path=self.root/'recovered'/relative
            path.chmod(0o600);path.write_bytes(b'{}');path.chmod(0o400)
            return report
        with patch.object(recovery.pilot,'stage',side_effect=changed),self.assertRaises(TaskAlongError):self.execute(proof)
        self.assertEqual(self.execute(proof)['state'],'recovery_incomplete')

    def test_response_changed_before_receipt_is_not_blessed_as_ready(self):
        self.tamper_during_stage('proposal/response.json')

    def test_patch_changed_before_receipt_is_not_blessed_as_ready(self):
        self.tamper_during_stage('proposal/proposed.patch')

    def test_review_changed_before_receipt_is_not_blessed_as_ready(self):
        self.tamper_during_stage('proposal/review.json')

    def test_snapshot_dispatch_marker_changed_before_receipt_is_not_blessed(self):
        self.tamper_during_stage('snapshot-bundle/provider-submission.json')

    def test_snapshot_manifest_changed_before_receipt_is_not_blessed(self):
        self.tamper_during_stage('snapshot-bundle/bundle.json')

    def test_snapshot_claim_changed_before_receipt_is_not_blessed(self):
        self.tamper_during_stage('snapshot-bundle/response-claim.json')

    def test_artifact_changed_while_receipt_is_written_does_not_return_ready(self):
        proof=self.plan();real=recovery.pilot._write
        def changed(root,name,data):
            result=real(root,name,data)
            if name=='receipt.json':
                path=self.root/'recovered/proposal/response.json'
                path.chmod(0o600);path.write_bytes(b'{}');path.chmod(0o400)
            return result
        with patch.object(recovery.pilot,'_write',side_effect=changed),self.assertRaises(TaskAlongError):self.execute(proof)
        with self.assertRaises(TaskAlongError):self.execute(proof)

    def test_observation_rejects_rehashed_response_that_disagrees_with_pinned_plan(self):
        proof=self.plan();result=self.execute(proof)
        path=self.root/'recovered/proposal/response.json';path.chmod(0o600);path.write_bytes(b'{}');path.chmod(0o400)
        artifacts=result['artifacts']|{'proposal/response.json':{'sha256':hashlib.sha256(b'{}').hexdigest(),'bytes':2}}
        forged=result|{'artifacts':artifacts};forged['digest']=recovery.digest(forged)
        reservation=self.service._store.setting('provider-result-recovery:muse:'+self.original['run_id'])
        receipt=recovery._anchor(self.original)/'receipt.json'
        receipt.chmod(0o600);receipt.write_bytes(canonical_bytes(forged));receipt.chmod(0o400)
        self.service._store.set_setting('provider-result-recovery-receipt:muse:'+reservation['recovery_id'],forged)
        with self.assertRaises(TaskAlongError):self.execute(proof)

    def test_final_output_fence_rejects_earlier_file_replaced_during_last_file_read(self):
        proof=self.plan();self.execute(proof)
        reservation=self.service._store.setting('provider-result-recovery:muse:'+self.original['run_id'])
        _,manifest=recovery.pilot._bundle(str(self.root/'recovered/snapshot-bundle'))
        expected,_=recovery._expected_output(proof,manifest,self.response,reservation)
        first=self.root/'recovered/observation.json'
        last=self.root/'recovered/snapshot-bundle/response-claim.json'
        last_identity=(last.stat().st_dev,last.stat().st_ino);real=recovery.os.read;once=[]
        def changed(fd,count):
            value=real(fd,count);info=os.fstat(fd)
            if not once and (info.st_dev,info.st_ino)==last_identity:
                once.append(1);raw=first.read_bytes();first.unlink();first.write_bytes(raw);first.chmod(0o400)
            return value
        with patch.object(recovery.os,'read',side_effect=changed),self.assertRaises(TaskAlongError):
            recovery._check_output(self.root/'recovered',expected)

    def test_terminal_cannot_hide_recognized_model_or_result_activity(self):
        original=self.c.original_journal.read_bytes()
        for kind in ('assistant_message_committed','model_request_configured','run_output_delta'):
            self.c.original_journal.write_bytes(original)
            self.journal(lambda rows: rows[:-1]+[{'payload':rows[-1]['payload']|{'event':rows[-1]['payload']['event']|{
                'hidden':{'kind':kind,'run_id':'foreign','text':'another result'}}}}])
            with self.subTest(kind=kind),self.assertRaises(TaskAlongError):self.plan()

    def test_restart_observation_and_restored_preoperation_database_do_not_restage(self):
        proof=self.plan()
        with RunService(self.root/'backup') as backup:
            self.service._store.db.backup(backup._store.db)
            result=self.execute(proof)
            with RunService(self.root/'state') as restarted:
                self.assertEqual(self.execute(proof,service=restarted),result)
            backup._store.db.backup(self.service._store.db)
            self.assertEqual(self.execute(proof)['state'],'recovery_incomplete')
            with self.assertRaises(TaskAlongError):self.execute(proof,key='new')

    def test_concurrent_local_recoveries_have_one_slot_and_no_native_calls(self):
        proof=self.plan();barrier=threading.Barrier(2)
        def attempt(key):
            with RunService(self.root/'state') as service:
                barrier.wait()
                try:return self.execute(proof,key=key,service=service)
                except TaskAlongError as exc:return exc
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(attempt,('first','second')))
        self.assertEqual(sum(isinstance(x,dict) and x['state']=='recovered_proposal_ready' for x in results),1)
        self.assertEqual(sum(isinstance(x,TaskAlongError) for x in results),1)
        self.c.assert_original()

    def test_cli_facade_plan_and_recover(self):
        from taskalong.cli import main
        common=['--state-dir',str(self.root/'state'),'--json']
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream):
            code=main(common+['provider-result-recovery-plan','muse','--run-id',self.original['run_id']])
        self.assertEqual(code,0); proof=json.loads(stream.getvalue())['data']
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream):
            code=main(common+['provider-result-recover','muse','--run-id',self.original['run_id'],'--key','cli',
                '--plan-digest',proof['digest'],'--output',str(self.root/'cli-result')])
        self.assertEqual(code,0);self.assertEqual(json.loads(stream.getvalue())['data']['state'],'recovered_proposal_ready')


if __name__ == '__main__': unittest.main()
