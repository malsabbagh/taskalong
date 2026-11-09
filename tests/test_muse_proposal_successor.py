"""One explicit cap amendment, with no salvage or automatic redispatch."""
import copy
import json
import os
from pathlib import Path
import shutil
import sqlite3
import unittest
from unittest.mock import patch

from taskalong import muse_experimental as muse, muse_successor as successor
from taskalong import muse_malformed_successor as completed, muse_response_schema as schema
from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes, digest
import test_muse_malformed_successor as fixtures


def fixture(*, size=33000, mutation=None, response=None):
    class Fixture(fixtures.MalformedSuccessorTests):
        def make_original(self):
            self.service.configure_provider('muse', {'executable':str(self.fixture.binary),
                'account_home':str(self.fixture.home),'muse_home':str(self.fixture.data),
                'capture_profile':'megabyte-proposal','attempt_seconds':1440,'max_proposal_bytes':32768,
                'response_contract':schema.CONTRACT})
            self.config = self.store.setting('provider:muse')
            self.text = response or json.dumps({'bundle_digest':'DIGEST','changes':[{'path':'source.py','content':'x'*size+'\n'}]}, separators=(',',':'))
            self.mutation = mutation
            request = {**self.fixture.request,'reasoning_effort':'high','task':'Independent oversized proposal.'}
            with patch.object(muse,'run_foreground_experiment',side_effect=self.owner):
                try:
                    result=self.service.run_provider(request=request,output=str(self.root/'malformed'))
                except TaskAlongError as exc:
                    self.assertEqual(exc.code,'provider_proposal_too_large')
                else:
                    self.assertEqual(result.get('error'),'provider_native_lifecycle_stop')
            self.original = next(value for row in self.store.db.execute('SELECT document FROM settings WHERE name LIKE ?',('provider-run:%',))
                if (value := json.loads(row[0])).get('output') == str(self.root/'malformed'))
            self.original_files = self.helper.files(self.root/'malformed')
            self.journal = self.helper.high_journal
            self.journal_bytes = self.journal.read_bytes()
            self.claim = self.store.setting('provider-claim:muse:'+self.original['bundle_digest'])

        def plan(self):
            return self.service.provider_successor_plan(predecessor=self.original['run_id'],reason='proposal-limit')

        def execute(self, proof, key='larger-proposal'):
            return self.service.provider_successor(predecessor=self.original['run_id'],reason='proposal-limit',
                key=key,plan_digest=proof['digest'],output=str(self.root/key))
    value=Fixture();value.setUp()
    return value


@unittest.skipUnless(os.name == 'posix', 'Private local evidence requires POSIX')
class ProposalSuccessorTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(); self.addCleanup(self.f.doCleanups)

    def test_model_free_plan_only_amends_cap_and_preserves_every_original_byte(self):
        f=self.f
        with patch.object(muse,'run_foreground_experiment',side_effect=AssertionError('no process')), patch.object(muse,'_preflight',side_effect=AssertionError('no preflight')):
            proof=f.plan()
        self.assertEqual(proof['format'],'manual-muse-successor-plan/7')
        self.assertEqual(proof['reason'],'proposal-limit')
        self.assertEqual(proof['max_proposal_bytes'],131072)
        self.assertEqual((proof['attempt_seconds'],proof['max_output_bytes'],proof['max_protocol_records']), (1440,67108864,131072))
        self.assertEqual(proof['proposal_amendment']['previous_max_proposal_bytes'],32768)
        self.assertGreater(proof['proposal_amendment']['canonical_bytes'],32768)
        self.assertEqual(proof['remaining_controller_slots_including_this'],1)
        self.assertFalse(proof['remote_usage_settled']); self.assertFalse(proof['complete_descendant_cessation_proven'])
        derived=completed.derive_proposal(f.config)
        self.assertEqual({k for k in derived if derived[k]!=f.config[k]}, {'digest','max_proposal_bytes'})
        self.assertIsNone(f.store.setting('provider-config:'+derived['digest']))
        self.assertIsNone(f.store.setting('provider-successor:muse:'+f.original['run_id']))
        f.assert_original()

    def test_one_linked_larger_response_and_repeat_only_observes(self):
        f=self.f; proof=f.plan()
        f.text=json.dumps({'bundle_digest':'DIGEST','changes':[{'path':'source.py','content':'y'*45000+'\n'}]},separators=(',',':'))
        with patch.object(muse,'run_foreground_experiment',side_effect=f.owner) as owner:
            result=f.execute(proof)
            self.assertEqual(result['state'],'proposal_ready')
            self.assertEqual(result['manual_successor']['format'],'manual-muse-successor/7')
            self.assertEqual(result['bundle_digest'],f.original['bundle_digest'])
            self.assertEqual(f.execute(proof),result);self.assertEqual(owner.call_count,1)
        root=Path(result['output']);response=json.loads((root/'response.json').read_bytes())
        self.assertEqual(response['changes'],{'source.py':'y'*45000+'\n'})
        document=json.loads((root/'output-schema.json').read_bytes())
        self.assertEqual(document['properties']['changes']['items']['properties']['content']['maxLength'],131072)
        self.assertEqual(result['capture_budget']['max_proposal_bytes'],131072)
        self.assertEqual(result['capture_budget']['max_output_bytes'],67108864)
        with self.assertRaises(TaskAlongError): f.plan()
        with self.assertRaises(TaskAlongError): f.execute(proof,key='another')
        with patch.object(muse,'run_foreground_experiment',side_effect=AssertionError('no replay')), self.assertRaises(TaskAlongError):
            f.service.run_provider(request=json.loads((root/'bundle/bundle.json').read_bytes())['request'],output=str(f.root/'ordinary'))
        with self.assertRaises(TaskAlongError):
            f.service.provider_successor_plan(predecessor=result['run_id'],reason='proposal-limit')
        f.assert_original()

    def test_cap_is_fixed_and_other_configuration_cannot_change(self):
        f=self.f
        for field,value in (('reasoning_effort','max'),('attempt_seconds',720),('context','native-only'),('max_proposal_bytes',131072),('max_output_bytes',4194304),('response_contract',None)):
            changed=f.config|{field:value};changed['digest']=digest(changed)
            f.store.set_setting('provider:muse',changed)
            with self.subTest(field=field),self.assertRaises(TaskAlongError):f.plan()
            f.store.set_setting('provider:muse',f.config)
        for value in (1024,32767,32769,65536,131072,True):
            with self.subTest(cap=value),self.assertRaises(TaskAlongError):completed.derive_proposal(f.config|{'max_proposal_bytes':value})
        f.assert_original()

    def test_same_key_crash_observes_and_restored_state_is_fenced(self):
        f=self.f;proof=f.plan();snapshot=f.root/'saved.sqlite3'
        target=sqlite3.connect(snapshot);f.store.db.backup(target);target.close()
        def denied(config,root, *, connectivity=False):
            self.assertTrue(connectivity)
            self.assertEqual(config['max_proposal_bytes'],131072)
            self.assertEqual(f.store.setting('provider-config:'+config['digest']),config)
            raise TaskAlongError('preflight_denied','synthetic')
        with patch.object(muse,'_preflight',side_effect=denied),patch.object(muse,'run_foreground_experiment',side_effect=AssertionError('no process')),self.assertRaises(TaskAlongError):f.execute(proof)
        reservation=f.store.setting('provider-successor:muse:'+f.original['run_id'])
        self.assertIsNotNone(reservation)
        with patch.object(muse,'_preflight',side_effect=AssertionError('no retry')):
            self.assertEqual(f.execute(proof)['run_id'],reservation['run_id'])
            with self.assertRaises(TaskAlongError):f.execute(proof,key='another')
        from taskalong.api import RunService
        copied=f.root/'copy';copied.mkdir(mode=0o700);shutil.copyfile(snapshot,copied/'state.sqlite3');(copied/'state.sqlite3').chmod(0o600)
        with RunService(copied) as service,self.assertRaises(TaskAlongError):
            service.provider_successor_plan(predecessor=f.original['run_id'],reason='proposal-limit')
        f.assert_original()

    def test_overlap_or_stale_plan_refuses_before_reservation(self):
        f=self.f;proof=f.plan()
        with self.assertRaises(TaskAlongError):f.execute(proof|{'digest':'0'*64})
        for output in (f.original['output'],f.original['bundle'],str(Path(f.original['output'])/'nested')):
            with self.subTest(output=output),self.assertRaises(TaskAlongError):
                f.service.provider_successor(predecessor=f.original['run_id'],reason='proposal-limit',key='overlap',plan_digest=proof['digest'],output=output)
        self.assertIsNone(f.store.setting('provider-successor:muse:'+f.original['run_id']))
        f.assert_original()

    def test_forged_state_cleanup_or_extra_lineage_refuses(self):
        f=self.f
        for update in ({'state':'running'},{'state':'proposal_ready'},{'error':'provider_local_failure'},
                       {'manual_successor':{'format':'manual-muse-successor/6'}},{'remote_usage':'not_sent'},
                       {'controller_submissions':2},{'process':{'root_exit_observed':False}}):
            changed=f.original|update;changed['digest']=digest(changed)
            event=Path(f.original['output'])/'events/0004.json';event.chmod(0o600);event.write_bytes(canonical_bytes(changed));event.chmod(0o400)
            f.store.set_setting('provider-run:'+f.original['run_id'],changed)
            with self.subTest(update=update),self.assertRaises(TaskAlongError):f.plan()
            event.chmod(0o600);event.write_bytes(canonical_bytes(f.original));event.chmod(0o400)
            f.store.set_setting('provider-run:'+f.original['run_id'],f.original)
        f.assert_original()

    def test_larger_than_target_and_invalid_scope_refuse_without_salvage(self):
        cases=[{'size':131073}, {'response':json.dumps({'bundle_digest':'DIGEST','changes':[{'path':'elsewhere.py','content':'x'*33000}]} )},
               {'response':json.dumps({'bundle_digest':'bad','changes':[{'path':'source.py','content':'x'*33000}]})}]
        for options in cases:
            f=fixture(**options);self.addCleanup(f.doCleanups)
            with self.subTest(options=list(options)),self.assertRaises(TaskAlongError):f.plan()
            self.assertIsNone(f.store.setting('provider-successor:muse:'+f.original['run_id']));f.assert_original()

    def test_retrying_and_conflicting_delta_refuse(self):
        def second(rows):
            for row in rows:
                if row['payload_type']=='task.lifecycle.status':row['payload']['event']['details']['facets'][0]['attempt']=2
        def conflicting(rows):
            for row in rows:
                if row['payload_type']=='run.output.delta':row['payload']['text']='conflict';break
        for mutation in (second,conflicting):
            f=fixture(mutation=mutation);self.addCleanup(f.doCleanups)
            with self.assertRaises(TaskAlongError):f.plan()
            f.assert_original()

    def test_changed_schema_journal_or_existing_artifact_refuses(self):
        f=self.f
        for path in (Path(f.original['output'])/'output-schema.json',f.journal):
            before=path.read_bytes();mode=path.stat().st_mode&0o777
            path.chmod(0o600);path.write_bytes(b'{}\n');path.chmod(mode)
            with self.subTest(name=path.name),self.assertRaises(TaskAlongError):f.plan()
            path.chmod(0o600);path.write_bytes(before);path.chmod(mode)
        (Path(f.original['output'])/'response.json').write_text('{}')
        with self.assertRaises(TaskAlongError):f.plan()
        self.assertIsNone(f.store.setting('provider-successor:muse:'+f.original['run_id']))

    def test_torn_anchor_never_reopens_slot(self):
        f=self.f;proof=f.plan();anchor=successor._anchor(f.original)
        anchor.mkdir(mode=0o700)
        with patch.object(muse,'_preflight',side_effect=AssertionError('no preflight')),self.assertRaises(TaskAlongError):f.execute(proof)
        self.assertIsNone(f.store.setting('provider-successor:muse:'+f.original['run_id']))
        f.assert_original()

    def test_old_malformed_mode_never_accepts_size_failure(self):
        f=self.f
        with self.assertRaises(TaskAlongError):f.service.provider_successor_plan(predecessor=f.original['run_id'],reason='malformed-response')
        f.assert_original()

    def test_exact_target_boundary_is_eligible_but_one_byte_over_refuses(self):
        base={'bundle_digest':'0'*64,'changes':[{'path':'source.py','content':'\n'}]}
        overhead=len(json.dumps(base,separators=(',',':')).encode())
        for limit,allowed in ((131072,True),(131073,False)):
            f=fixture(size=limit-overhead);self.addCleanup(f.doCleanups)
            if allowed:
                self.assertEqual(f.plan()['proposal_amendment']['canonical_bytes'],limit)
            else:
                with self.assertRaises(TaskAlongError):f.plan()
            f.assert_original()

    def test_unknown_local_cleanup_refuses_even_with_consistent_run_record(self):
        f=self.f;path=Path(f.original['output'])/'process.json';before=path.read_bytes()
        process=json.loads(before)
        for change in ({'root_exit_observed':False},{'group_termination_confirmed':False},
                       {'root_exit_code':130},{'process_stream_complete':False},
                       {'tracking_errors':['unknown']},{'timed_out':True}):
            path.chmod(0o600);path.write_bytes(canonical_bytes(process|change));path.chmod(0o400)
            with self.subTest(change=change),self.assertRaises(TaskAlongError):f.plan()
        path.chmod(0o600);path.write_bytes(before);path.chmod(0o400)
        f.assert_original()

    def test_anchor_write_crash_consumes_slot_without_dispatch(self):
        from taskalong import supervised_pilot as pilot
        f=self.f;proof=f.plan();writing=pilot._write
        def broken(root,name,data):
            if name=='slot-1.json':raise OSError('synthetic disk failure')
            return writing(root,name,data)
        with patch.object(pilot,'_write',side_effect=broken),patch.object(muse,'_preflight',side_effect=AssertionError('no preflight')),self.assertRaises(OSError):
            f.execute(proof)
        self.assertIsNone(f.store.setting('provider-successor:muse:'+f.original['run_id']))
        with self.assertRaises(TaskAlongError):f.plan()
        with self.assertRaises(TaskAlongError):f.execute(proof)
        f.assert_original()
