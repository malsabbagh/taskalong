"""Preparation-only campaign inputs: all route evidence here is synthetic."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
from importlib import resources
import io
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from taskalong.qualification import TrustPolicy
from taskalong.validation import canonical_bytes, seal_versioned
from test_contracts import example_spec
from test_qualification import NOW, policy_for, reference

SPEC = importlib.util.spec_from_file_location('handoff_campaign_tool', Path(__file__).resolve().parents[1]/'tools/qualify_handoff.py')
campaign = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(campaign)


def fixture():
    """Generate bounded public data; no repo, process, login or State setup."""
    documents = resources.files('taskalong.resources').joinpath('examples/v2')
    installation = json.loads(documents.joinpath('harness-installation.json').read_bytes())
    provider = json.loads(documents.joinpath('provider-profile.json').read_bytes())
    binding = json.loads(documents.joinpath('execution-binding.json').read_bytes())
    artifacts, blobs = [], {}
    def artifact(path, data, media='application/json'):
        ref = reference(data, media) | {'path': path}
        if ref['sha256'] not in blobs:
            artifacts.append(ref); blobs[ref['sha256']] = data
        return ref
    generated = artifact('fixture.json', canonical_bytes({'files':{'arithmetic.py':'def value(): return 1\n'}}))
    handoff = artifact('artifacts/plan.txt', b'Public synthetic plan.\n', 'text/plain')
    routes = []
    for name, harness in [('a','codex'),('b','claude-code')]:
        i = seal_versioned('harness-installation', installation | {'installation_id':'synthetic-'+name,'harness':harness}, version='2.0')
        profile = provider | {'profile_id':'synthetic-'+name,'harness':harness}
        if harness == 'codex':
            profile.update(provider='openai-account',endpoint='https://synthetic.invalid',
                           auth={'mode':'account','credential_ref':'synthetic-account'},allowed_disclosure='provider-only')
        p = seal_versioned('provider-profile', profile, version='2.0')
        b = seal_versioned('execution-binding', binding | {'installation_digest':i['digest'],'provider_profile_digest':p['digest'],'required_capabilities':['start']}, version='2.0')
        context = {'artifact_digest':'a'*64,'host_digest':'b'*64,'effective_context_digest':'c'*64,
                   'test_inputs_digest':generated['sha256'],'session_digest':None,'prior_invocation_digest':None}
        subject = {key:b[key] for key in ('installation_digest','provider_profile_digest','instruction_bundle_digest','tool_policy_digest','worker_sandbox_digest','check_binding_digest')}
        subject.update(binding_digest=b['digest'],runtime_closure_digest=i['runtime_closure_digest'],backend_id=i['platform']['backend_id'],provider=p['provider'],model_digest=p['model']['resolved_digest'],native_resume_compatibility_digest=None,**context)
        receipts = []
        for mode in campaign.MODES:
            raw = canonical_bytes({'synthetic':True,'mode':mode,'route':name})
            ref = artifact('evidence/'+name+'-'+mode+'.json', raw)
            ref = {key:value for key,value in ref.items() if key!='path'}
            receipts.append(seal_versioned('qualification-receipt',{
                'receipt_id':name+'-'+mode,'producer_id':'synthetic-qa','subject':subject,'mode':mode,
                'evidence_level':'offline_fixture','valid_from':'2026-01-01T00:00:00Z','valid_until':'2027-01-01T00:00:00Z',
                'results':[{'capability':'start','outcome':'supported','evidence_refs':[ref]}],
                'usage':{'input_tokens':None,'output_tokens':None,'cost_micro_usd':None},
                'limitations':['Synthetic data is not actual provider evidence.']}, version='2.1'))
        routes.append({'route_id':name,'installation':i,'provider_profile':p,'binding':b,
                       'configuration_digest':name*64,'context':context,'receipts':receipts})
    refs = [{'route_id':r['route_id'],'binding_digest':r['binding']['digest'],
             'configuration_digest':r['configuration_digest'],'disclosure_destination_id':'destination-'+r['route_id']} for r in routes]
    task = example_spec()
    task.update(schema_version='2.10',scope={'files':['arithmetic.py','plan.txt'],'operations':['add','modify']},
                execution={'routes':refs,'check_route_id':'a'},
                final_verification={'max_passes':1,'total_active_seconds':120,'max_output_bytes':65536})
    task['permissions'].pop('inference_destination_id')
    task['permissions']['disclosure_destination_ids']=['destination-a','destination-b']
    task['budget'].update(max_attempts=4,attempt_output_bytes=65536,total_active_seconds=240)
    task['steps']=[
        {'step_id':'plan','goal':'Write a generated plan.','scope':{'files':['plan.txt'],'operations':['add']},'required':True,'route_id':'a',
         'inputs':[],'outputs':[{'output_id':'plan','artifact_kind':'utf8_text','path':'plan.txt','max_bytes':1024,'classification':'synthetic_fixture',
                                'allowed_target_binding_digests':[routes[1]['binding']['digest']],'allowed_disclosure_destination_ids':['destination-b']}],
         'import_scope':{'files':[],'operations':['modify']}},
        {'step_id':'edit','goal':'Read that exact plan and propose one edit.','scope':{'files':['arithmetic.py'],'operations':['modify']},'required':True,'route_id':'b',
         'inputs':[{'kind':'step_output','from_step_id':'plan','output_id':'plan','expected_kind':'utf8_text','max_bytes':1024}],
         'outputs':[],'import_scope':{'files':[],'operations':['modify']}}]
    task = seal_versioned('task-spec',task,version='2.10')
    return {'kind':'handoff_campaign_preparation','schema_version':'1.0','campaign_id':'generated-campaign',
            'source':{'commit':'e'*40,'wheel_sha256':'a'*64,'sdist_sha256':'b'*64,'dependency_lock_sha256':'c'*64},
            'task_spec':task,'routes':routes,'fixture':generated,'artifacts':artifacts,'handoff_artifact':handoff,
            'limits':{'provider_submissions':4,'wall_seconds':1440,'capture_bytes':1048576,'artifact_bytes':1048576},
            'cleanup':{'local_cessation':'required','unknown_effects':'block','native_resume':'unsupported','cross_harness_resume':'unsupported'}}, blobs


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.blobs = fixture()

    def report(self, document=None, **options):
        return campaign.prepare(document or self.manifest, blobs=options.pop('blobs',self.blobs), now=NOW,
                                approved_destinations=options.pop('approved_destinations',frozenset({'destination-a','destination-b'})), **options)

    @staticmethod
    def codes(report):
        return {item['code'] for item in report['issues']}

    def test_valid_declarations_are_not_live_admission(self):
        before = canonical_bytes(self.manifest)
        self.assertEqual(campaign.validate_manifest(self.manifest), self.manifest)
        result = self.report()
        self.assertIn('proof_not_actual_provider', self.codes(result))
        self.assertIn('operator_trust_missing', self.codes(result))
        self.assertFalse(result['execution_admitted'])
        self.assertFalse(result['producer_association_verified'])
        self.assertEqual(result['controller_submissions'], 0)
        self.assertFalse(result['state_mutated'])
        self.assertEqual(canonical_bytes(self.manifest), before)

    def test_unknown_fields_and_embedded_self_trust_are_rejected(self):
        for key in ['unexpected','trust','approved_destinations','execute']:
            with self.subTest(key=key), self.assertRaises(campaign.CampaignError):
                campaign.validate_manifest(self.manifest | {key:True})

    def test_missing_and_unauthorized_mode_destinations(self):
        self.manifest['routes'][0]['receipts']=[]
        result=self.report(approved_destinations=frozenset())
        missing=[i for i in result['issues'] if i['code']=='mode_receipt_missing']
        self.assertEqual({i['mode'] for i in missing},set(campaign.MODES))
        self.assertIn('destination_not_authorized',self.codes(result))
        self.assertNotEqual(result['operator_inputs_digest'], self.report()['operator_inputs_digest'])

    def test_stale_and_mismatched_receipt_report_exact_reasons(self):
        for kind,code in [('stale','proof_not_current'),('mismatched','proof_subject_mismatch')]:
            with self.subTest(kind=kind):
                document=copy.deepcopy(self.manifest);receipt=document['routes'][0]['receipts'][0]
                if kind=='stale':receipt.update(valid_from='2025-01-01T00:00:00Z',valid_until='2025-02-01T00:00:00Z')
                else:receipt['subject']['host_digest']='d'*64
                document['routes'][0]['receipts'][0]=seal_versioned('qualification-receipt',receipt,version='2.1')
                self.assertIn(code,self.codes(self.report(document)))

    def test_tampered_and_missing_artifacts_never_become_trusted(self):
        sha=self.manifest['handoff_artifact']['sha256']
        changed=dict(self.blobs);changed[sha]=b'changed'
        self.assertIn('artifact_tampered',self.codes(self.report(blobs=changed)))
        changed.pop(sha)
        self.assertIn('artifact_missing',self.codes(self.report(blobs=changed)))

    def test_invalid_budget_types_and_ceilings_refuse(self):
        for key in self.manifest['limits']:
            for value in [None,True,0,-1,1.5,2**53]:
                with self.subTest(key=key,value=value),self.assertRaises(campaign.CampaignError):
                    document=copy.deepcopy(self.manifest);document['limits'][key]=value
                    campaign.validate_manifest(document)

    def test_campaign_wall_budget_does_not_double_count_final_verification(self):
        self.manifest['limits']['wall_seconds'] = self.manifest['task_spec']['budget']['total_active_seconds']
        campaign.validate_manifest(self.manifest)
        self.manifest['limits']['wall_seconds'] -= 1
        with self.assertRaises(campaign.CampaignError) as failure:
            campaign.validate_manifest(self.manifest)
        self.assertEqual(failure.exception.field, 'limits.wall_seconds')

    def test_aggregate_route_attempts_must_fit_campaign(self):
        document = copy.deepcopy(self.manifest)
        for route, declared in zip(document['routes'], document['task_spec']['execution']['routes']):
            binding = route['binding']
            binding['budget']['max_attempts'] = 3
            route['binding'] = seal_versioned('execution-binding', binding, version='2.0')
            declared['binding_digest'] = route['binding']['digest']
        document['task_spec']['steps'][0]['outputs'][0]['allowed_target_binding_digests'] = [document['routes'][1]['binding']['digest']]
        document['task_spec'] = seal_versioned('task-spec', document['task_spec'], version='2.10')
        with self.assertRaises(campaign.CampaignError) as failure:
            campaign.validate_manifest(document)
        self.assertEqual(failure.exception.field, 'routes.total_attempts')

    def test_two_routes_cannot_substitute_one_harness_or_binding(self):
        for change in ('harness', 'binding', 'configuration', 'context', 'session'):
            document = copy.deepcopy(self.manifest)
            route = document['routes'][1]
            if change == 'harness':
                route['installation'] = document['routes'][0]['installation']
                route['provider_profile'] = document['routes'][0]['provider_profile']
            elif change == 'binding':
                route['binding'] = document['routes'][0]['binding']
            elif change == 'configuration':
                route['configuration_digest'] = 'd' * 64
            elif change == 'context':
                route['context']['artifact_digest'] = 'd' * 64
            else:
                route['context']['session_digest'] = 'd' * 64
            with self.subTest(change=change), self.assertRaises(campaign.CampaignError):
                campaign.validate_manifest(document)

    def test_artifact_reference_paths_types_and_totals_are_closed(self):
        for change in ('escape', 'duplicate', 'media', 'private', 'too_many', 'total'):
            document = copy.deepcopy(self.manifest)
            ref = document['artifacts'][-1]
            if change == 'escape': ref['path'] = '../outside.txt'
            elif change == 'duplicate': document['artifacts'].append(copy.deepcopy(ref))
            elif change == 'media': ref['media_type'] = 'application/octet-stream'
            elif change == 'private': ref['classification'] = 'private'
            elif change == 'too_many': document['artifacts'] *= 13
            else:
                for n in range(17):
                    document['artifacts'].append({'path': f'extra-{n}.txt', 'sha256': f'{n:064x}',
                        'size_bytes': campaign.MAX_ARTIFACT, 'media_type': 'text/plain', 'classification': 'public'})
            with self.subTest(change=change), self.assertRaises(campaign.CampaignError):
                campaign.validate_manifest(document)

    def test_missing_producer_artifact_and_empty_text_remain_nonadmitting(self):
        self.manifest['handoff_artifact'] = None
        self.assertIn('producer_artifact_missing', self.codes(self.report()))
        document, blobs = fixture()
        old = document['handoff_artifact']
        empty = reference(b'', 'text/plain') | {'path': old['path']}
        document['artifacts'][document['artifacts'].index(old)] = empty
        document['handoff_artifact'] = empty
        blobs.pop(old['sha256'])
        blobs[empty['sha256']] = b''
        result = self.report(document, blobs=blobs)
        self.assertNotIn('artifact_tampered', self.codes(result))
        self.assertFalse(result['execution_admitted'])

    def test_invalid_generated_fixture_is_not_accepted_as_public_test_input(self):
        for payload in ({'files': {'../escape.py': 'x'}}, {'files': {'safe.py': 'x' * 65537}}, {'files': {}}):
            document, blobs = fixture()
            old = document['fixture']
            data = canonical_bytes(payload)
            ref = reference(data) | {'path': old['path']}
            document['artifacts'][document['artifacts'].index(old)] = ref
            document['fixture'] = ref
            blobs.pop(old['sha256'])
            blobs[ref['sha256']] = data
            for route in document['routes']:
                route['context']['test_inputs_digest'] = ref['sha256']
            with self.subTest(payload=payload):
                self.assertIn('fixture_invalid', self.codes(self.report(document, blobs=blobs)))

    def test_missing_evidence_diagnostic_names_its_exact_digest(self):
        sha = self.manifest['handoff_artifact']['sha256']
        blobs = dict(self.blobs)
        blobs.pop(sha)
        self.assertIn({'code': 'artifact_missing', 'artifact_digest': sha}, self.report(blobs=blobs)['issues'])

    def test_operator_policy_is_separate_and_synthetic_never_qualifies_actual(self):
        policy=TrustPolicy.from_dict(policy_for(self.manifest['routes'][0]['receipts'][0]))
        result=self.report(trust=policy)
        self.assertIn('proof_not_actual_provider',self.codes(result))
        self.assertIn('m9_evidence_level_insufficient',self.codes(result))
        self.assertFalse(result['execution_admitted'])
        with self.assertRaises(campaign.CampaignError):self.report(trust=policy.to_dict())

    def test_even_operator_approved_actual_level_claims_never_admit_execution(self):
        # Generated claims exercise the offline evaluator, not actual evidence.
        # No fixture-produced policy or receipt is persisted or registered.
        policy = {'producers': [{'producer_id': 'synthetic-qa', 'allowed_evidence_levels': ['actual_provider']}],
                  'approvals': [], 'revoked_receipt_digests': [],
                  'revoked_approval_digests': [], 'revoked_evidence_digests': []}
        facts = {'start': ('start', {'dispatch_observed': True, 'subject_matched': True}),
                 'observe': ('observe', {'invocation_matched': True, 'observation_complete': True}),
                 'cancel': ('local_cessation', {'root_stopped': True, 'owned_descendants_stopped': True}),
                 'result': ('structured_result', {'schema_valid': True, 'packet_matched': True, 'session_matched': True})}
        for route in self.manifest['routes']:
            for index, original in enumerate(route['receipts']):
                results = []
                for capability, observed in [facts['start']] + ([] if original['mode'] == 'start' else [facts[original['mode']]]):
                    raw = canonical_bytes({'kind': 'qualification_observation', 'schema_version': '2.1',
                        'producer_id': 'synthetic-qa', 'subject': original['subject'], 'mode': original['mode'],
                        'evidence_level': 'actual_provider', 'capability': capability, 'criterion_id': 'synthetic-criterion',
                        'expected_outcome': 'supported', 'observations': observed,
                        'capture_refs': [reference(b'synthetic capture', 'text/plain')]})
                    for data, media in [(raw, 'application/json'), (b'synthetic capture', 'text/plain')]:
                        sha = hashlib.sha256(data).hexdigest()
                        if sha not in self.blobs:
                            self.blobs[sha] = data
                            self.manifest['artifacts'].append(reference(data, media) | {'path': 'evidence/' + sha + '.txt'})
                    results.append({'capability': capability, 'outcome': 'supported', 'evidence_refs': [reference(raw)]})
                receipt = seal_versioned('qualification-receipt', original | {'evidence_level': 'actual_provider', 'results': results}, version='2.1')
                route['receipts'][index] = receipt
                policy['approvals'] += policy_for(receipt)['approvals']
        result = self.report(trust=TrustPolicy.from_dict(policy))
        self.assertTrue(result['preparation_checks_passed'])
        self.assertEqual(result['status'], 'preparation_valid')
        self.assertFalse(result['execution_admitted'])
        self.assertFalse(result['production_dispatch_allowed'])
        self.assertFalse(result['source_identity_verified'])
        self.assertFalse(result['producer_association_verified'])
        self.assertEqual(result['controller_submissions'], 0)
        # Exact external revocation defeats the same otherwise valid snapshot.
        policy['revoked_receipt_digests'].append(self.manifest['routes'][0]['receipts'][0]['digest'])
        self.assertIn('m9_receipt_revoked', self.codes(self.report(trust=TrustPolicy.from_dict(policy))))

    def test_pure_api_never_spawns_connects_or_opens_state(self):
        from taskalong.store import Store
        with patch.object(subprocess,'Popen',side_effect=AssertionError('spawn')), patch.object(socket,'socket',side_effect=AssertionError('network')), patch.object(Store,'__init__',side_effect=AssertionError('state')):
            self.assertEqual(self.report()['controller_submissions'],0)

    def test_cli_reports_blocked_without_spawning_or_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'campaign.json').write_bytes(canonical_bytes(self.manifest))
            for ref in self.manifest['artifacts']:
                target=root/ref['path'];target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(self.blobs[ref['sha256']])
            before={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
            output=io.StringIO()
            with patch.object(subprocess,'Popen',side_effect=AssertionError('spawn')),patch.object(socket,'socket',side_effect=AssertionError('network')),redirect_stdout(output):
                code=campaign.main(['--manifest',str(root/'campaign.json'),'--dry-run'])
            self.assertEqual(code,3)
            result=json.loads(output.getvalue());self.assertFalse(result['execution_admitted'])
            self.assertIn('destination_not_authorized',self.codes(result))
            self.assertEqual(before,{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()})

    def test_cli_rejects_malformed_duplicate_utf8_and_oversized_manifests(self):
        for raw in (b'{', b'{"kind":1,"kind":2}', b'\xff', b' ' * (campaign.MAX_MANIFEST + 1)):
            with self.subTest(size=len(raw)), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'campaign.json'
                path.write_bytes(raw)
                output = io.StringIO()
                with redirect_stdout(output):
                    code = campaign.main(['--manifest', str(path), '--dry-run'])
                self.assertEqual(code, 2)
                result = json.loads(output.getvalue())
                self.assertFalse(result['execution_admitted'])
                self.assertEqual(result['controller_submissions'], 0)
                self.assertNotIn(str(path), output.getvalue())

    def test_cli_does_not_follow_evidence_symlink_or_read_beyond_declared_size(self):
        for change in ('symlink', 'oversize'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest_path = root / 'campaign.json'
                manifest_path.write_bytes(canonical_bytes(self.manifest))
                for ref in self.manifest['artifacts']:
                    target = root / ref['path']
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(self.blobs[ref['sha256']])
                ref = self.manifest['handoff_artifact']
                target = root / ref['path']
                if change == 'symlink':
                    original = root / 'original.txt'
                    target.rename(original)
                    try:
                        target.symlink_to(original)
                    except (OSError, NotImplementedError):
                        self.skipTest('OS does not permit creating a test symlink')
                else:
                    target.write_bytes(b'x' * (ref['size_bytes'] + 1))
                output = io.StringIO()
                with redirect_stdout(output):
                    code = campaign.main(['--manifest', str(manifest_path), '--dry-run'])
                self.assertEqual(code, 3)
                self.assertIn({'code': 'artifact_unavailable', 'artifact_digest': ref['sha256']}, json.loads(output.getvalue())['issues'])

    def test_help_never_loads_contracts_or_dispatches(self):
        with patch.object(campaign, '_models', side_effect=AssertionError('contracts')), redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as exit:
            campaign.main(['--help'])
        self.assertEqual(exit.exception.code, 0)
