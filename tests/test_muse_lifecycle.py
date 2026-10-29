"""Production lifecycle contract checks; never a production qualification fixture."""
import copy
import hashlib
import importlib.util
from importlib import resources
import json
import os
import subprocess
import sys
from pathlib import Path
import unittest
from uuid import uuid4
from unittest.mock import patch

from helpers import ServiceFixture
from test_antigravity_store import upgrade_through
from taskalong.api import RunService
from taskalong.errors import TaskAlongError
from taskalong.store import Store
from taskalong.validation import canonical_bytes, digest, schema, schema_names, seal_versioned
from taskalong.muse_lifecycle import compile_packet
from taskalong.executors.registry import contract_for
from jsonschema import Draft202012Validator


class MuseLifecycleTests(ServiceFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.policy=self.root/'policy.json'; self.policy.write_text('{"purpose":"original contract input"}')
        self.instructions=self.root/'instructions.txt';self.instructions.write_text('Original disposable instructions.\n')
        self.tools=self.root/'tools.json';self.tools.write_text('{"tools":[]}')
        policy={'permission_profile':'bounded-test','policy_sha256':self.sha(self.policy),
            'instructions_sha256':self.sha(self.instructions),'tools_sha256':self.sha(self.tools)}
        profile={**self.profile,'schema_version':'2.11','profile_id':'muse-lifecycle','adapter':'muse',
            'qualification':'production','runtime_version':'1.4.10-R6427.1','model':'wonder-full',
            'reasoning_effort':'high','permission_policy':policy,'permission_policy_digest':digest(policy)}
        profile.pop('digest');self.production=seal_versioned('runtime-profile',profile,version='2.11')
        self.service.register_profile(self.production)
        self.intent=seal_versioned('driver-config',{'profile_id':self.production['profile_id'],
            'profile_digest':self.production['digest'],'permission_policy_path':str(self.policy),
            'permission_policy_sha256':self.sha(self.policy)},version='2.11')
        self.service.configure_muse(self.intent)
        self.service.close()
        with Store.maintenance(self.state) as store:upgrade_through(store,self.root,12)
        self.service=RunService(self.state)
        checker={**self.profile,'qualification':'production','profile_id':'declared-production-checker'}
        checker.pop('digest');self.checker=self.service.register_profile(checker)
        self.raw_config={'config_id':'original-production-contract','qualification':'production',
            'projection':'muse-production-plain/1','transport':'taskalong_owned_production',
            'executable':{'path':str(self.executable),'sha256':self.sha(self.executable)},
            'build':'1.4.10-R6427.1','requested_model':'wonder-full','reasoning_effort':'high',
            'permission_profile':'bounded-test','max_model_steps':1,
            'inference_destination_id':self.production['inference_destination_id'],
            'check_profile_digest':self.checker['digest'],'checks_digest':digest(self.spec()['checks']),
            'review_config_digest':self.spec()['review']['config_digest'],'review_provider':'local-ollama',
            'command_sandbox_digest':digest(self.service._store.setting('command_sandbox')),
            'profile_id':self.production['profile_id'],'profile_digest':self.production['digest'],
            'intent_configuration_digest':self.intent['digest'],
            'declared_inputs':{'instructions_path':str(self.instructions),'tools_path':str(self.tools),'dependency_paths':[]}}
        self.config=self.service.configure_muse_driver(self.raw_config)
        task=self.spec();task.pop('digest');task.update(schema_version='2.12',qualification='production',publication=None,
            execution={'driver_config_digest':self.config['digest']})
        task['budget'].update(max_attempts=1,max_model_steps=1)
        self.task=seal_versioned('task-spec',task,version='2.12')

    @staticmethod
    def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

    def counts(self):
        return {t:self.service._store.db.execute('SELECT count(*) FROM '+t).fetchone()[0]
            for t in ('runs','attempts','effects','leases','authorities','acceptances','events','operations','task_specs')}

    def test_registration_and_validation_never_allocate_or_qualify(self):
        before=self.counts()
        self.assertEqual(self.service.configure_muse_driver(self.raw_config),self.config)
        # History idempotency is separate from every lifecycle allocation.
        before=self.counts()
        for _ in range(2):
            value=self.service.validate_task(self.task)
            self.assertTrue(value['valid']);self.assertFalse(value['readiness']['production_dispatch_allowed'])
            self.assertIn('muse_aggregate_inference_unqualified',value['readiness']['reason_codes'])
            with self.assertRaises(TaskAlongError) as caught:self.service.submit(self.task,operation_key='never-dispatch')
            self.assertEqual(caught.exception.code,'muse_runtime_unqualified')
            self.assertEqual(caught.exception.effect_outcome,'not_sent')
        self.assertEqual(self.counts(),before);self.assertEqual(self.invocations(),[])
        self.assertFalse((self.root/'workspaces').exists())
        with RunService(self.state) as reopened:
            self.assertEqual(reopened.validate_task(self.task),value)

    def test_public_cli_registration_validation_and_submit_keep_dispatch_closed(self):
        config_path=self.root/'production-config.json';config_path.write_bytes(canonical_bytes(self.raw_config))
        task_path=self.root/'production-task.json';task_path.write_bytes(canonical_bytes(self.task))
        before=self.counts()
        for args,code in [(['configure-muse-driver','--config',str(config_path)],0),
                          (['validate','--spec',str(task_path)],0),
                          (['submit','--spec',str(task_path),'--key','production-cli-refusal'],3)]:
            result=subprocess.run([sys.executable,'-m','taskalong','--state-dir',str(self.state),'--json',*args],
                cwd=self.root,env=dict(os.environ),capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,code,result.stdout+result.stderr)
            value=json.loads(result.stdout)
            if code==3:self.assertEqual(value['errors'][0]['code'],'muse_runtime_unqualified')
            self.assertNotIn('Traceback',result.stderr)
        self.assertEqual(self.counts(),before);self.assertEqual(self.invocations(),[])

    def test_qualifications_and_fixture_settings_cannot_open_runtime_gate(self):
        self.service._store.set_setting('muse-production-approval',{'qualified':True,'production_dispatch_allowed':True})
        for field,value in [('production_dispatch_allowed',True),('qualification','synthetic'),('requested_model','other'),
                            ('max_model_steps',2),('reasoning_effort','medium')]:
            with self.subTest(field=field),self.assertRaises(TaskAlongError):
                self.service.configure_muse_driver(self.raw_config|{field:value})
        with self.assertRaises(TaskAlongError) as caught:self.service.submit(self.task,operation_key='forged-grant')
        self.assertEqual(caught.exception.code,'muse_runtime_unqualified');self.assertEqual(self.invocations(),[])

    def test_resealed_checker_under_another_digest_index_refuses_before_admission(self):
        changed={**self.checker,'profile_id':'different-checker'};changed.pop('digest')
        from taskalong.validation import seal
        changed=seal('runtime-profile',changed)
        self.service._store.db.execute('UPDATE profiles SET document=? WHERE digest=?',
            (canonical_bytes(changed).decode(),self.checker['digest']))
        with self.assertRaises(TaskAlongError) as caught:self.service.validate_task(self.task)
        self.assertEqual(caught.exception.code,'check_binding_mismatch')
        self.assertEqual(self.invocations(),[])

    def test_identity_drift_and_malformed_configuration_refuse_without_dispatch(self):
        raw=self.instructions.read_bytes();self.instructions.write_bytes(raw+b'changed')
        with self.assertRaises(TaskAlongError) as caught:self.service.validate_task(self.task)
        self.assertEqual(caught.exception.code,'muse_effective_input_changed')
        self.instructions.write_bytes(raw)
        for value in ({},self.raw_config|{'executable':{'path':'relative','sha256':'f'*64}}):
            with self.assertRaises(TaskAlongError):self.service.configure_muse_driver(value)
        self.assertEqual(self.invocations(),[])

    def packet(self):
        fields={'packet_id':str(uuid4()),'run_id':str(uuid4()),'attempt_id':str(uuid4()),'spec_digest':self.task['digest'],
            'goal':self.task['goal'],'non_goals':self.task['non_goals'],'scope':self.task['scope'],'checks':self.task['checks'],
            'bindings':{'base_commit':self.base,'initial_head':self.base,'initial_content_digest':'b'*64,
                'workspace_id':str(uuid4()),'lease_generation':1},'remaining_budget':self.task['budget'],
            'qualification':'production','extensions':{}}
        # Pure compiler data, expressly no runtime grant or executable authority.
        admission={'driver_config':self.config,'digest':'a'*64,'runtime_subject_digest':'c'*64,
            'authority_id':str(uuid4()),'projection':{'digest':'d'*64},'production_dispatch_allowed':False}
        return compile_packet(fields,admission)

    def test_pure_packet_projection_binds_authority_runtime_and_prompt_bytes(self):
        packet,wire,mapping=self.packet()
        self.assertEqual(packet,wire);self.assertEqual(mapping['wire_packet_digest'],digest(wire))
        self.assertEqual(packet['runtime_subject_digest'],mapping['runtime_subject_digest'])
        self.assertEqual(mapping['prompt_sha256'],hashlib.sha256(canonical_bytes(packet)).hexdigest())
        self.assertEqual(packet['bindings']['driver_config_digest'],self.config['digest'])
        self.assertIn('authority_id',packet['bindings'])
        self.assertEqual(packet['handoff_schema_id'],'urn:taskalong:schema:v2.12:execution-handoff')
        self.assertEqual(self.invocations(),[])

    def test_runtime_subject_and_prompt_mapping_cannot_be_resealed_to_another_subject(self):
        from taskalong.muse_lifecycle import _bind_subject
        packet,_,mapping=self.packet()
        admission={'runtime_subject_digest':packet['runtime_subject_digest']}
        authority={'authority_id':packet['bindings']['authority_id']}
        self.assertEqual(_bind_subject(packet,admission,authority,mapping),admission)
        for change in ({'runtime_subject_digest':'f'*64},{'prompt_sha256':'e'*64}):
            with self.subTest(change=change),self.assertRaises(TaskAlongError):
                _bind_subject(packet,admission,authority,mapping|change)

    def test_exact_driver_refuses_before_capture_directory_or_spawn(self):
        contract=contract_for(self.config,task_version='2.12',projection='muse-production-plain/1')
        driver=contract.factory(self.config,None);packet,_,_=self.packet()
        output=self.root/'never-created'
        with self.assertRaises(TaskAlongError) as caught:
            driver.run(packet,workspace=self.repo,output_dir=output)
        self.assertEqual(caught.exception.code,'muse_runtime_unqualified')
        self.assertFalse(output.exists());self.assertEqual(self.invocations(),[])
        with self.assertRaises(TaskAlongError):driver.preflight(qualification='synthetic',budget={})
        with self.assertRaises(TaskAlongError):contract_for(self.config,task_version='2.9',projection='muse-plain-fixture/1')

    def test_imported_run_cannot_skip_start_admission_or_replay(self):
        run=self.service._store.create_run(self.task,'simulated-imported-state')
        self.service.authorize(run['run_id'],decision_digest=self.task['digest'],scope=['execute','verify','commit_candidate'],qualification='production')
        run=self.service.inspect(run['run_id']);before=self.counts()
        with self.assertRaises(TaskAlongError) as caught:
            self.service.start(run['run_id'],operation_key='blocked-start',expected_revision=run['revision'])
        self.assertEqual(caught.exception.code,'muse_runtime_unqualified')
        self.assertEqual(self.counts(),before);self.assertEqual(self.invocations(),[])
        cap=self.service.capabilities(run['run_id']);self.assertFalse(cap['production_dispatch_allowed'])
        self.assertFalse(self.service.result(run['run_id'])['independently_accepted'])

    def test_review_provider_is_immutable_and_fixture_provider_refuses(self):
        from taskalong.muse_lifecycle import review_options
        self.assertEqual(review_options(self.service._store,self.task),{'expected_provider':'local-ollama'})
        changed=self.service.configure_muse_driver(self.raw_config|{'review_provider':'cloud-ollama'})
        self.assertNotEqual(changed['digest'],self.config['digest'])
        self.assertEqual(review_options(self.service._store,self.task),{'expected_provider':'local-ollama'})
        with self.assertRaises(TaskAlongError):
            self.service.configure_muse_driver(self.raw_config|{'review_provider':'fixture'})
        self.assertEqual(self.invocations(),[])

    def test_original_fixture_completion_and_no_replay_operate_on_format12(self):
        import test_muse_handoff as legacy
        fixture=legacy.MuseHandoffTests('test_completed_handoff_survives_cancel_result_and_reconcile_without_replay')
        fixture.setUp()
        try:
            fixture.service.close()
            with Store.maintenance(fixture.state) as store:upgrade_through(store,fixture.root,12)
            fixture.service=RunService(fixture.state)
            fixture.test_completed_handoff_survives_cancel_result_and_reconcile_without_replay()
        finally:fixture.tearDown()

    def test_new_schemas_and_all_predecessor_resource_bytes(self):
        names={'driver-config','task-spec','worker-packet','packet-projection','execution-handoff','result-view','capabilities-view'}
        self.assertEqual(set(schema_names(version='2.12')),names)
        for name in names:Draft202012Validator.check_schema(schema(name,version='2.12'))
        catalog=json.loads((Path(__file__).parent/'fixtures/pre-muse-lifecycle-resources.json').read_text())
        for path,expected in catalog.items():
            raw=resources.files('taskalong.resources').joinpath(path.removeprefix('src/taskalong/resources/')).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(),expected,path)

    def test_actual_format11_reader_refuses12_without_database_change(self):
        fixture=Path(__file__).parent/'fixtures/legacy_store_v11.py'
        self.assertEqual(self.sha(fixture),'4d2a70ed4edabacd7ee48f49afc7950f24083fbfb2c42c9fee2f7e8ecb3ecbb4')
        spec=importlib.util.spec_from_file_location('taskalong._legacy_store_v11',fixture)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.service.close()
        before={p.name:p.read_bytes() for p in self.state.glob('state.sqlite3*')}
        with self.assertRaises(TaskAlongError) as caught:module.Store(self.state)
        self.assertEqual(caught.exception.code,'unsupported_store_version')
        self.assertEqual({p.name:p.read_bytes() for p in self.state.glob('state.sqlite3*')},before)
        self.service=RunService(self.state)


if __name__=='__main__':unittest.main()
