"""Malformed completed responses: offline lineage, schema and immutable history."""
import copy
import json
import os
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

from taskalong import muse_experimental as muse, muse_successor as successor
from taskalong import muse_response_schema as schema
from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes, digest
import test_muse_high_result_recovery as helpers


@unittest.skipUnless(os.name == 'posix', 'Private retained evidence requires POSIX')
class MalformedSuccessorTests(unittest.TestCase):
    def setUp(self):
        self.helper = helpers.HighCompleteResultTests()
        self.helper.setUp(); self.addCleanup(self.helper.doCleanups)
        self.fixture = self.helper.fixture.c
        self.root, self.service = self.helper.root, self.helper.service
        self.store = self.service._store
        self.service.configure_provider('muse', {'executable':str(self.fixture.binary),
            'account_home':str(self.fixture.home),'muse_home':str(self.fixture.data),
            'capture_profile':'megabyte-proposal','attempt_seconds':1440,'max_proposal_bytes':32768})
        self.config = self.store.setting('provider:muse')
        self.text = getattr(self, 'case_text', '{"bundle_digest":"DIGEST","changes":{"source.py":"bad \\x01"}}')
        self.mutation = getattr(self, 'case_mutation', None)
        self.make_original()

    def owner(self, argv, **options):
        dump = json.dumps
        def encode(value, *args, **kwargs):
            if value is getattr(self.helper, 'response', None):
                if self.text is None:
                    return dump({'bundle_digest':value['bundle_digest'], 'changes':[
                        {'path':key,'content':content} for key,content in value['changes'].items()]}, *args, **kwargs)
                return self.text.replace('DIGEST',value['bundle_digest'])
            return dump(value,*args,**kwargs)
        self.helper.over_limit = False; self.helper.mutate = self.mutation; self.helper.replacement = 'Synthetic schema replacement.\n'
        with patch.object(helpers.json, 'dumps', side_effect=encode):
            result = self.helper.completed_owner(argv,**options)
        result.cancelled = False
        summary = result.to_dict() | {'cancelled':False}
        result.to_dict = lambda:summary
        return result

    def make_original(self):
        request = {**self.fixture.request,'reasoning_effort':'high','task':'Independent malformed complete response.'}
        with patch.object(muse,'run_foreground_experiment',side_effect=self.owner), self.assertRaises(TaskAlongError) as caught:
            self.service.run_provider(request=request,output=str(self.root/'malformed'))
        self.assertEqual(caught.exception.code,'provider_response_unrecognized')
        self.original = next(value for row in self.store.db.execute('SELECT document FROM settings WHERE name LIKE ?',('provider-run:%',))
            if (value := json.loads(row[0])).get('output') == str(self.root/'malformed'))
        self.original_files = helpers.HighCompleteResultTests.files(self.root/'malformed')
        self.journal = self.helper.high_journal
        self.journal_bytes = self.journal.read_bytes()
        self.claim = self.store.setting('provider-claim:muse:'+self.original['bundle_digest'])

    def plan(self):
        return self.service.provider_successor_plan(predecessor=self.original['run_id'],reason='malformed-response')

    def execute(self, proof, key='schema-replacement'):
        return self.service.provider_successor(predecessor=self.original['run_id'],reason='malformed-response',
            key=key,plan_digest=proof['digest'],output=str(self.root/key))

    def assert_original(self):
        self.assertEqual(self.store.setting('provider-run:'+self.original['run_id']),self.original)
        self.assertEqual(helpers.HighCompleteResultTests.files(self.root/'malformed'),self.original_files)
        self.assertEqual(self.journal.read_bytes(),self.journal_bytes)
        self.assertEqual(self.store.setting('provider-claim:muse:'+self.original['bundle_digest']),self.claim)
        self.assertEqual(self.store.setting('provider:muse'),self.config)

    def test_model_free_plan_preserves_every_original_byte_and_bounds(self):
        with patch.object(muse,'run_foreground_experiment',side_effect=AssertionError('no process')):
            proof = self.plan()
        self.assertEqual(proof['format'],'manual-muse-successor-plan/6')
        self.assertEqual(proof['malformed_response']['kind'],'invalid_escape')
        self.assertEqual(proof['remaining_controller_slots_including_this'],1)
        self.assertEqual(proof['attempt_seconds'],1440)
        self.assertEqual((proof['max_proposal_bytes'],proof['max_output_bytes'],proof['max_protocol_records']), (32768,67108864,131072))
        self.assertFalse(proof['remote_usage_settled'])
        self.assertFalse(proof['complete_descendant_cessation_proven'])
        self.assert_original()

    def test_one_linked_schema_response_and_repeated_command_only_observes(self):
        proof = self.plan(); self.text = None
        with patch.object(muse,'run_foreground_experiment',side_effect=self.owner) as owner:
            result = self.execute(proof)
            self.assertEqual(result['state'],'proposal_ready')
            self.assertEqual(result['manual_successor']['format'],'manual-muse-successor/6')
            self.assertEqual(result['bundle_digest'],self.original['bundle_digest'])
            self.assertEqual(self.execute(proof),result)
            self.assertEqual(owner.call_count,1)
        root = Path(result['output']); invocation = json.loads((root/'invocation.json').read_bytes())
        self.assertIn('--output-schema',invocation['argv'])
        self.assertEqual(invocation['response_transport'],result['response_transport'])
        self.assertEqual((root/'output-schema.json').stat().st_mode & 0o777,0o400)
        response = json.loads((root/'response.json').read_bytes())
        self.assertEqual(response['changes'],{'source.py':'Synthetic schema replacement.\n'})
        with self.assertRaises(TaskAlongError): self.plan()
        with self.assertRaises(TaskAlongError): self.execute(proof,key='different')
        self.assert_original()

    def test_configuration_changes_or_result_artifacts_refuse_before_reservation(self):
        for field,value in (('reasoning_effort','max'),('attempt_seconds',720),('context','native-only')):
            changed = self.config | {field:value}; changed['digest']=digest(changed)
            self.store.set_setting('provider:muse',changed)
            with self.subTest(field=field), self.assertRaises(TaskAlongError): self.plan()
            self.store.set_setting('provider:muse',self.config)
        (self.root/'malformed/response.json').write_text('{}')
        with self.assertRaises(TaskAlongError) as caught: self.plan()
        self.assertEqual(caught.exception.code,'provider_successor_result_exists')
        self.assertIsNone(self.store.setting('provider-successor:muse:'+self.original['run_id']))

    def test_retained_anchor_blocks_restored_database_after_failed_preflight(self):
        proof=self.plan()
        snapshot = self.root/'saved.sqlite3'
        import sqlite3
        target=sqlite3.connect(snapshot); self.store.db.backup(target); target.close()
        with patch.object(muse,'_preflight',side_effect=TaskAlongError('preflight_denied','synthetic')), self.assertRaises(TaskAlongError):
            self.execute(proof)
        with self.assertRaises(TaskAlongError): self.execute(proof,key='another')
        # A database restored from before enrollment is fenced by the retained
        # original-run sibling anchor, without deleting or repairing history.
        from taskalong.api import RunService
        copied=self.root/'copied-state';copied.mkdir(mode=0o700)
        shutil.copyfile(snapshot,copied/'state.sqlite3'); (copied/'state.sqlite3').chmod(0o600)
        with RunService(copied) as service, self.assertRaises(TaskAlongError):
            service.provider_successor_plan(predecessor=self.original['run_id'],reason='malformed-response')
        self.assert_original()

    def case(self, *, text=None, mutation=None):
        fixture = MalformedSuccessorTests()
        if text is not None: fixture.case_text = text
        fixture.case_mutation = mutation
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        return fixture

    def test_literal_control_character_is_eligible_without_decoding_or_repair(self):
        fixture = self.case(text='{"bundle_digest":"DIGEST","changes":{"source.py":"bad ' + chr(1) + '"}}')
        self.assertEqual(fixture.plan()['malformed_response']['kind'],'unescaped_control_character')
        fixture.assert_original()

    def test_truncated_inner_json_after_invalid_escape_is_not_eligible(self):
        fixture = self.case(text='{"bundle_digest":"DIGEST","changes":{"source.py":"bad \\x01')
        with self.assertRaises(TaskAlongError): fixture.plan()
        fixture.assert_original()

    def test_observed_second_native_attempt_refuses(self):
        def mutate(rows):
            for row in rows:
                if row['payload_type'] == 'task.lifecycle.status':
                    row['payload']['event']['details']['facets'][0]['attempt'] = 2
        fixture = self.case(mutation=mutate)
        with self.assertRaises(TaskAlongError): fixture.plan()
        fixture.assert_original()

    def test_conflicting_usable_delta_text_refuses(self):
        def mutate(rows):
            first = True
            for row in rows:
                if row['payload_type'] == 'run.output.delta':
                    row['payload']['text'] = '{"bundle_digest":"valid","changes":{"source.py":"usable"}}' if first else ''
                    first = False
        fixture = self.case(mutation=mutate)
        with self.assertRaises(TaskAlongError): fixture.plan()
        fixture.assert_original()

    def test_hidden_committed_output_refuses(self):
        def mutate(rows):
            rows[0]['payload']['hidden'] = {'kind':'assistant_message_committed','text':'conflicting'}
        fixture = self.case(mutation=mutate)
        with self.assertRaises(TaskAlongError): fixture.plan()
        fixture.assert_original()

    def test_explicit_retrying_status_refuses(self):
        from test_muse_native_lifecycle import status_details
        def mutate(rows):
            for row in rows:
                if row['payload_type'] == 'task.lifecycle.status':
                    row['payload']['event']['details'] = status_details('retrying')
        fixture = self.case(mutation=mutate)
        with self.assertRaises(TaskAlongError): fixture.plan()
        fixture.assert_original()

    def test_ordinary_schema_run_is_opt_in_and_model_free_budget_uses_projected_prompt(self):
        self.service.configure_provider('muse', {'executable':str(self.fixture.binary),
            'account_home':str(self.fixture.home),'muse_home':str(self.fixture.data),
            'capture_profile':'megabyte-proposal','attempt_seconds':1440,'max_proposal_bytes':32768,
            'response_contract':schema.CONTRACT})
        config = muse._configuration(self.store)
        self.assertEqual(config['format'],schema.FORMAT)
        request={**self.fixture.request,'reasoning_effort':'high','task':'Independent opt-in schema task.'}
        # _manifest returns (manifest,prompt); budget measures actual transport prompt.
        from taskalong import supervised_pilot as pilot
        manifest,_=pilot._manifest(request)
        measured=self.service.provider_budget(request=request)
        self.assertEqual(measured['prompt_bytes'],len(muse._prompt(config,manifest)))
        self.text=None
        with patch.object(muse,'run_foreground_experiment',side_effect=self.owner):
            result=self.service.run_provider(request=request,output=str(self.root/'ordinary-schema'))
        self.assertEqual(result['state'],'proposal_ready')
        self.assertEqual(result['response_transport']['contract'],schema.CONTRACT)

    def test_schema_change_before_gate_or_after_process_never_accepts_output(self):
        proof=self.plan();self.text=None
        def owner(argv,**options):
            result=self.owner(argv,**options)
            path=Path(argv[argv.index('--output-schema')+1])
            path.chmod(0o600);path.write_bytes(b'{}');path.chmod(0o400)
            return result
        with patch.object(muse,'run_foreground_experiment',side_effect=owner), self.assertRaises(TaskAlongError):
            self.execute(proof)
        child=self.store.setting('provider-successor:muse:'+self.original['run_id'])
        self.assertIsNotNone(child)
        self.assertFalse((Path(child['output'])/'response.json').exists())
        self.assert_original()
