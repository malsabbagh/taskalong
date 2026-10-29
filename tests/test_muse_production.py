"""Public offline Muse intent; installation is never execution qualification."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from helpers import ServiceFixture
from taskalong.api import RunService
from taskalong.cli import main
from taskalong.errors import TaskAlongError
from taskalong.executors.muse_protocol import project_production_exec_argv
from taskalong.validation import digest, seal_versioned, validate, validate_versioned


class MuseProductionTests(ServiceFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.policy = self.root / 'policy.json'
        self.policy.write_text('{"local_control_only":true}')
        profile = copy.deepcopy(self.profile)
        profile.update(schema_version='2.11', profile_id='muse-production', adapter='muse',
                       qualification='production', runtime_version='1.4.10-R6427.1',
                       model='wonder-full', reasoning_effort='high',
                       permission_policy={'permission_profile':'bounded-test',
                                          'policy_sha256':hashlib.sha256(self.policy.read_bytes()).hexdigest(),
                                          'instructions_sha256':'1'*64, 'tools_sha256':'2'*64})
        profile['permission_policy_digest'] = digest(profile['permission_policy'])
        profile.pop('digest')
        # This executable is a local sentinel, never Muse. No catalog/runtime proof.
        self.production = seal_versioned('runtime-profile', profile, version='2.11')
        self.config = seal_versioned('driver-config', {'profile_id':profile['profile_id'],
            'profile_digest':self.production['digest'], 'permission_policy_path':str(self.policy),
            'permission_policy_sha256':profile['permission_policy']['policy_sha256']}, version='2.11')

    def setup_intent(self):
        self.service.register_profile(self.production)
        self.service.configure_muse(self.config)
        task = self.spec()
        task.update(schema_version='2.11', qualification='production', publication=None,
                    execution={'adapter':'muse','profile_id':self.production['profile_id'],
                               'profile_digest':self.production['digest'],
                               'configuration_digest':self.config['digest']})
        task['budget'].update(max_attempts=1,max_model_steps=1)
        task.pop('digest')
        return seal_versioned('task-spec', task, version='2.11')

    def cli(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(['--state-dir', str(self.state), '--json', *args])
        return code, json.loads(output.getvalue())

    def test_public_roundtrip_refuses_submit_without_effects_and_survives_reopen(self):
        for name, document, args in [('profile',self.production,['register-profile','--profile']),
                                     ('config',self.config,['configure-muse','--config'])]:
            path = self.root / (name+'.json'); path.write_text(json.dumps(document))
            self.assertEqual(self.cli(*args,str(path))[0],0)
        task = self.setup_intent()
        path = self.root / 'task.json'; path.write_text(json.dumps(task))
        before = {t:self.service._store.db.execute('SELECT count(*) FROM '+t).fetchone()[0]
                  for t in ('runs','attempts','effects','leases','authorities','acceptances','events','operations')}
        with patch('subprocess.Popen', side_effect=AssertionError('worker dispatch')):
            # readiness needs no subprocess; validation performs read-only Git inspection.
            code, result = self.cli('muse-readiness','--profile-id',self.production['profile_id'],
                                    '--configuration-digest',self.config['digest'])
            self.assertEqual(code,0)
            self.assertFalse(result['data']['production_dispatch_allowed'])
        code, result = self.cli('validate','--spec',str(path))
        self.assertEqual(code,0); self.assertTrue(result['data']['valid'])
        self.assertFalse(result['data']['readiness']['effective_model_observed'])
        for key in ('first','first','second'):
            code, result = self.cli('submit','--spec',str(path),'--key',key)
            self.assertEqual(code,3)
            self.assertEqual(result['errors'][0]['code'],'muse_runtime_unqualified')
            self.assertEqual(result['errors'][0]['effect_outcome'],'not_sent')
        after = {t:self.service._store.db.execute('SELECT count(*) FROM '+t).fetchone()[0] for t in before}
        self.assertEqual(before,after); self.assertEqual(self.invocations(),[])
        self.assertFalse((self.root/'workspaces').exists())
        with RunService(self.state) as reopened:
            self.assertFalse(reopened.muse_readiness(self.production['profile_id'],self.config['digest'])['production_dispatch_allowed'])
        self.assertEqual(self.service._store.profile(self.profile['profile_id']),self.profile)

    def test_stale_executable_and_policy_are_refused_on_every_observation(self):
        task = self.setup_intent()
        for path, code in ((self.executable,'muse_executable_changed'),(self.policy,'muse_configuration_changed')):
            original = path.read_bytes(); path.write_bytes(original+b' ')
            for call in (lambda:self.service.muse_readiness(self.production['profile_id'],self.config['digest']),
                         lambda:self.service.validate_task(task),
                         lambda:self.service.submit(task,operation_key='stale'),
                         lambda:self.service.configure_muse(self.config)):
                with self.assertRaises(TaskAlongError) as caught: call()
                self.assertEqual(caught.exception.code,code)
                self.assertEqual(caught.exception.effect_outcome,'not_sent')
            path.write_bytes(original)

    def test_immutable_registration_and_changed_bindings(self):
        task = self.setup_intent()
        changed = copy.deepcopy(self.production); changed.pop('digest')
        changed['inference_destination_id']='different'
        with self.assertRaises(TaskAlongError) as caught: self.service.register_profile(changed)
        self.assertEqual(caught.exception.code,'muse_registration_immutable')
        task['execution']['profile_digest']='f'*64; task.pop('digest')
        with self.assertRaises(TaskAlongError) as caught: self.service.validate_task(task)
        self.assertEqual(caught.exception.code,'muse_profile_mismatch')
        config = copy.deepcopy(self.config); config['profile_digest']='f'*64;config.pop('digest')
        with self.assertRaises(TaskAlongError) as caught:self.service.configure_muse(config)
        self.assertEqual(caught.exception.code,'muse_profile_mismatch')

    def test_contract_refuses_fallback_receipts_unknown_fields_and_legacy_reinterpretation(self):
        for field,value in [('profile_id','muse wonder high'),('model','other'),('reasoning_effort','medium'),('qualification','synthetic'),
                            ('qualification_receipt_ids',['00000000-0000-0000-0000-000000000000']),
                            ('runtime_version','future'),('production_dispatch_allowed',True)]:
            document=copy.deepcopy(self.production);document.pop('digest');document[field]=value
            with self.subTest(field=field),self.assertRaises(TaskAlongError):
                self.service.register_profile(document)
        with self.assertRaises(TaskAlongError):validate('runtime-profile',self.production)
        task=self.setup_intent();task['budget']['max_model_steps']=True;task.pop('digest')
        with self.assertRaises(TaskAlongError):self.service.validate_task(task)
        for name in ('runtime-profile','task-spec','driver-config'):
            doc={'runtime-profile':self.production,'task-spec':self.setup_intent(),'driver-config':self.config}[name]
            self.assertEqual(validate_versioned(name,doc,expected_version='2.11'),doc)

    def test_nonregular_symlink_and_oversized_inputs_refuse_without_reading(self):
        from taskalong.muse_production import _fingerprint
        fifo=self.root/'fifo';os.mkfifo(fifo)
        link=self.root/'link';link.symlink_to(self.executable)
        oversized=self.root/'oversized'
        with oversized.open('wb') as stream:stream.truncate(512*1024*1024+1)
        for path in (fifo,link,oversized,self.root):
            with self.subTest(path=path.name),self.assertRaises(TaskAlongError):
                _fingerprint(str(path),executable=True)

    def test_closed_projection_does_not_change_legacy_projection(self):
        options=dict(executable='/opt/muse',build='1.4.10-R6427.1',workspace='/owned/workspace',
                     prompt_file='/owned/prompt',model='wonder-full',permission_profile='bounded',max_model_steps=1)
        argv=project_production_exec_argv(reasoning_effort='high',**options)
        self.assertEqual(argv[-2:],('--reasoning-effort','high'))
        self.assertNotIn('--json',argv)
        self.assertIn('--disable-request-user-input',argv)
        for override in ({'reasoning_effort':'medium'},{'model':'other'},{'max_model_steps':True},{'max_model_steps':2}):
            with self.assertRaises(TaskAlongError):
                project_production_exec_argv(**(options|{'reasoning_effort':'high'}|override))


if __name__=='__main__':unittest.main()
