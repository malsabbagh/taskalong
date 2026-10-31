"""Production preparation measures local inputs; it never qualifies a runtime."""
import copy
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import unittest

from helpers import ServiceFixture, git
from taskalong.api import RunService
from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes, digest, seal_versioned


class MusePreparationTests(ServiceFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.policy = self.root / 'policy.json'
        self.policy.write_text('{"purpose":"original offline input measurement"}')
        self.instructions = self.root / 'instructions.txt'
        self.instructions.write_text('Original disposable instruction input.\n')
        self.tools = self.root / 'tools.json'
        self.tools.write_text('{"tools":[]}\n')
        self.dependency = self.root / 'declared-dependency'
        self.dependency.write_bytes(b'original declared dependency bytes')
        policy = {'permission_profile': 'bounded-test', 'policy_sha256': self.sha(self.policy),
                  'instructions_sha256': self.sha(self.instructions), 'tools_sha256': self.sha(self.tools)}
        profile = {**self.profile, 'schema_version': '2.11', 'profile_id': 'muse-prepare',
                   'adapter': 'muse', 'qualification': 'production', 'runtime_version': '1.4.10-R6427.1',
                   'model': 'wonder-full', 'reasoning_effort': 'high',
                   'permission_policy': policy, 'permission_policy_digest': digest(policy)}
        profile.pop('digest')
        self.production = seal_versioned('runtime-profile', profile, version='2.11')
        self.service.register_profile(self.production)
        self.configuration = seal_versioned('driver-config', {'profile_id': self.production['profile_id'],
            'profile_digest': self.production['digest'], 'permission_policy_path': str(self.policy),
            'permission_policy_sha256': self.sha(self.policy)}, version='2.11')
        self.service.configure_muse(self.configuration)
        spec = self.spec()
        spec.update(schema_version='2.11', qualification='production', publication=None,
                    execution={'adapter': 'muse', 'profile_id': self.production['profile_id'],
                               'profile_digest': self.production['digest'], 'configuration_digest': self.configuration['digest']})
        spec['budget'].update(max_attempts=1, max_model_steps=1)
        spec.pop('digest')
        self.task = seal_versioned('task-spec', spec, version='2.11')
        self.inputs = {'instructions_path': str(self.instructions), 'tools_path': str(self.tools),
                       'dependency_paths': [str(self.dependency)]}

    @staticmethod
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def counts(self):
        return {name: self.service._store.db.execute('SELECT count(*) FROM ' + name).fetchone()[0]
                for name in ('runs', 'attempts', 'effects', 'leases', 'authorities', 'acceptances',
                             'events', 'operations', 'task_specs')}

    def public(self, *args, expected=0):
        result = subprocess.run([sys.executable, '-m', 'taskalong', '--state-dir', str(self.state),
                                 '--json', *map(str, args)], cwd=self.root, env=dict(os.environ),
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        return json.loads(result.stdout)

    def test_public_prepare_and_reopen_preserve_measurements_without_allocating_work(self):
        spec_path, inputs_path = self.root / 'task.json', self.root / 'inputs.json'
        spec_path.write_bytes(canonical_bytes(self.task))
        inputs_path.write_bytes(canonical_bytes(self.inputs))
        before = self.counts()
        value = self.public('prepare-muse', '--spec', spec_path, '--inputs', inputs_path)['data']
        self.assertFalse(value['production_dispatch_allowed'])
        self.assertFalse(value['acceptance_allowed'])
        self.assertFalse(value['dependency_closure_qualified'])
        self.assertEqual(value['spec_digest'], self.task['digest'])
        self.assertEqual(value['source']['tree'], git(self.repo, 'rev-parse', self.base + '^{tree}'))
        self.assertEqual({x['path'] for x in value['source']['files']}, {'arithmetic.py', 'test_arithmetic.py'})
        self.assertEqual(value['instruction_input']['sha256'], self.sha(self.instructions))
        self.assertEqual(value['tool_input']['sha256'], self.sha(self.tools))
        self.assertEqual(value['declared_dependencies'][0]['sha256'], self.sha(self.dependency))
        observed = self.public('muse-preparation', value['preparation_digest'])['data']
        self.assertEqual(observed, value)
        with RunService(self.state) as reopened:
            self.assertEqual(reopened.prepare_muse(self.task, inputs=self.inputs), value)
            self.assertEqual(reopened.muse_preparation(value['preparation_digest']), value)
        self.assertEqual(self.counts(), before)
        self.assertEqual(self.service._store.db.execute(
            "SELECT count(*) FROM settings WHERE name LIKE 'muse-production-preparation:%'").fetchone()[0], 1)
        self.assertEqual(self.invocations(), [])
        self.assertFalse((self.root / 'workspaces').exists())
        result = self.public('submit', '--spec', spec_path, '--key', 'still-unqualified', expected=3)
        self.assertEqual(result['errors'][0]['code'], 'muse_runtime_unqualified')
        self.assertIsNone(result['run_id'])

    def test_symbolic_bindings_do_not_replace_an_executable_with_the_same_path(self):
        from taskalong.muse_preparation import _projection
        for path in ('/__taskalong_owned_workspace__', '/__taskalong_owned_attempt__/prompt.txt'):
            projected = _projection(self.production | {'executable_path': path})
            self.assertEqual(projected[0], path)
            self.assertEqual(projected[projected.index('--workspace') + 1], {'core_binding': 'owned_workspace'})
            self.assertEqual(projected[projected.index('--prompt-file') + 1], {'core_binding': 'prepared_prompt'})

    def test_dependency_order_is_canonical_and_total_size_refuses_without_retention(self):
        second = self.root / 'second-dependency'
        second.write_bytes(b'Other original dependency bytes')
        paths = [str(second), str(self.dependency)]
        first = self.service.prepare_muse(self.task, inputs=self.inputs | {'dependency_paths': paths})
        reordered = self.service.prepare_muse(self.task, inputs=self.inputs | {'dependency_paths': paths[::-1]})
        self.assertEqual(first, reordered)
        before = self.service._store.db.execute(
            "SELECT count(*) FROM settings WHERE name LIKE 'muse-production-preparation:%'").fetchone()[0]
        large_paths = []
        for index in range(3):
            path = self.root / ('large-dependency-' + str(index))
            with path.open('wb') as stream:
                stream.truncate(44 * 1024 * 1024)
            large_paths.append(str(path))
        with self.assertRaises(TaskAlongError) as caught:
            self.service.prepare_muse(self.task, inputs=self.inputs | {'dependency_paths': large_paths})
        self.assertEqual(caught.exception.code, 'muse_dependency_limit')
        self.assertEqual(self.service._store.db.execute(
            "SELECT count(*) FROM settings WHERE name LIKE 'muse-production-preparation:%'").fetchone()[0], before)
        self.assertEqual(self.invocations(), [])

    def test_stale_inputs_are_not_refreshed_and_do_not_create_history(self):
        value = self.service.prepare_muse(self.task, inputs=self.inputs)
        key = 'muse-production-preparation:' + value['preparation_digest']
        original = self.service._store.setting(key)
        before = self.counts()
        for path, code in ((self.executable, 'muse_executable_changed'), (self.policy, 'muse_configuration_changed'),
                           (self.instructions, 'muse_instructions_changed'), (self.tools, 'muse_tools_changed'),
                           (self.dependency, 'muse_preparation_stale')):
            raw = path.read_bytes()
            try:
                path.write_bytes(raw + b'changed')
                with self.subTest(path=path.name), self.assertRaises(TaskAlongError) as caught:
                    self.service.muse_preparation(value['preparation_digest'])
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(caught.exception.effect_outcome, 'not_sent')
                self.assertEqual(self.service._store.setting(key), original)
            finally:
                path.write_bytes(raw)
        self.assertEqual(self.counts(), before)
        self.assertEqual(self.service.muse_preparation(value['preparation_digest']), value)

    def test_permission_mode_drift_requires_a_distinct_preparation(self):
        value = self.service.prepare_muse(self.task, inputs=self.inputs)
        mode = self.dependency.stat().st_mode & 0o777
        self.dependency.chmod(mode ^ 0o100)
        with self.assertRaises(TaskAlongError) as caught:
            self.service.muse_preparation(value['preparation_digest'])
        self.assertEqual(caught.exception.code, 'muse_preparation_stale')
        updated = self.service.prepare_muse(self.task, inputs=self.inputs)
        self.assertNotEqual(value['preparation_digest'], updated['preparation_digest'])
        self.assertFalse(updated['production_dispatch_allowed'])

    def test_declared_inputs_cannot_supply_qualification_or_arbitrary_fields(self):
        for change in ({'production_dispatch_allowed': True}, {'qualification_receipts': []},
                       {'dependency_paths': [str(self.dependency)] * 2}, {'dependency_paths': [True]},
                       {'dependency_paths': [str(self.root / str(i)) for i in range(33)]},
                       {'instructions_path': None}):
            with self.subTest(change=change), self.assertRaises(TaskAlongError) as caught:
                self.service.prepare_muse(self.task, inputs=self.inputs | change)
            self.assertEqual(caught.exception.code, 'muse_preparation_inputs_invalid')
        self.assertEqual(self.service._store.db.execute(
            "SELECT count(*) FROM settings WHERE name LIKE 'muse-production-preparation:%'").fetchone()[0], 0)
        self.assertEqual(self.invocations(), [])

    def test_nonregular_linked_missing_and_oversized_dependencies_refuse(self):
        fifo, link, large = self.root / 'fifo', self.root / 'link', self.root / 'large'
        os.mkfifo(fifo); link.symlink_to(self.dependency)
        with large.open('wb') as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
        for path in (fifo, link, large, self.root, self.root / 'missing'):
            with self.subTest(path=path.name), self.assertRaises(TaskAlongError):
                self.service.prepare_muse(self.task, inputs=self.inputs | {'dependency_paths': [str(path)]})
        self.assertEqual(self.invocations(), [])

    def test_tampered_and_resealed_claims_do_not_become_runtime_authority(self):
        value = self.service.prepare_muse(self.task, inputs=self.inputs)
        key = 'muse-production-preparation:' + value['preparation_digest']
        original = self.service._store.setting(key)
        changed = copy.deepcopy(original)
        changed['assessment']['production_dispatch_allowed'] = True
        self.service._store.set_setting(key, changed)
        with self.assertRaises(TaskAlongError) as caught:
            self.service.muse_preparation(value['preparation_digest'])
        self.assertEqual(caught.exception.code, 'muse_preparation_corrupt')
        changed['digest'] = digest(changed)
        self.service._store.set_setting('muse-production-preparation:' + changed['digest'], changed)
        with self.assertRaises(TaskAlongError) as caught:
            self.service.muse_preparation(changed['digest'])
        self.assertEqual(caught.exception.code, 'muse_preparation_stale')
        with self.assertRaises(TaskAlongError) as caught:
            self.service.submit(self.task, operation_key='forged-preparation')
        self.assertEqual(caught.exception.code, 'muse_runtime_unqualified')
        self.assertEqual(self.invocations(), [])

    def test_resealed_numeric_flags_and_noncanonical_inputs_refuse_readback(self):
        second = self.root / 'second-integrity-input'
        second.write_bytes(b'Original second declared dependency')
        value = self.service.prepare_muse(self.task, inputs=self.inputs | {
            'dependency_paths': [str(second), str(self.dependency)]})
        original = self.service._store.setting('muse-production-preparation:' + value['preparation_digest'])
        for mutation in ('numeric_flag', 'reordered_inputs'):
            changed = copy.deepcopy(original)
            if mutation == 'numeric_flag':
                changed['assessment']['production_dispatch_allowed'] = 0
            else:
                changed['inputs']['dependency_paths'].reverse()
            changed['digest'] = digest(changed)
            self.service._store.set_setting('muse-production-preparation:' + changed['digest'], changed)
            with self.subTest(mutation=mutation):
                with self.assertRaises(TaskAlongError) as caught:
                    self.service.muse_preparation(changed['digest'])
                self.assertEqual(caught.exception.code, 'muse_preparation_stale')
        self.assertEqual(self.service.muse_preparation(value['preparation_digest']), value)
        self.assertEqual(self.invocations(), [])

    def test_base_manifest_is_immutable_when_clean_head_moves(self):
        value = self.service.prepare_muse(self.task, inputs=self.inputs)
        (self.repo / 'new-input.txt').write_text('Different clean head; original base remains the subject.\n')
        git(self.repo, 'add', 'new-input.txt'); git(self.repo, 'commit', '-m', 'Next disposable base')
        self.assertEqual(self.service.muse_preparation(value['preparation_digest']), value)
        task = copy.deepcopy(self.task); task.pop('digest')
        task['repository']['base_commit'] = git(self.repo, 'rev-parse', 'HEAD')
        updated = self.service.prepare_muse(task, inputs=self.inputs)
        self.assertNotEqual(updated['source']['tree'], value['source']['tree'])
        self.assertIn('new-input.txt', {item['path'] for item in updated['source']['files']})
        self.assertNotEqual(updated['preparation_digest'], value['preparation_digest'])

    def test_dirty_and_unsupported_source_refuse_before_retention(self):
        (self.repo / 'untracked').write_text('Not part of the intended base.\n')
        with self.assertRaises(TaskAlongError) as caught:
            self.service.prepare_muse(self.task, inputs=self.inputs)
        self.assertEqual(caught.exception.code, 'dirty_repository')
        (self.repo / 'untracked').unlink()
        (self.repo / 'external-link').symlink_to(self.instructions)
        git(self.repo, 'add', 'external-link'); git(self.repo, 'commit', '-m', 'Unsupported disposable link')
        with self.assertRaises(TaskAlongError) as caught:
            self.service.prepare_muse(self.task, inputs=self.inputs)
        self.assertEqual(caught.exception.code, 'unsupported_git_tree')

    def test_preparation_does_not_change_existing_run_or_store_version(self):
        existing = self.service.submit(self.spec(), operation_key='existing-original-task')
        before, version = self.counts(), self.service._store.format_version
        value = self.service.prepare_muse(self.task, inputs=self.inputs)
        self.assertEqual(self.service.inspect(existing['run_id']), existing)
        self.assertEqual(self.counts(), before)
        self.assertEqual(self.service._store.format_version, version)
        self.assertFalse(value['durable_execution_qualified'])

    def test_kill_before_preparation_commit_leaves_no_partial_record_or_dispatch(self):
        spec_path, inputs_path = self.root / 'crash-task.json', self.root / 'crash-inputs.json'
        spec_path.write_bytes(canonical_bytes(self.task)); inputs_path.write_bytes(canonical_bytes(self.inputs))
        program = '''
import json,os,signal,sys
from taskalong.api import RunService
with RunService(sys.argv[1]) as service:
    def barrier(statement):
        if statement == 'COMMIT':
            os.write(1,b'prepared-before-commit\\n'); signal.pause()
    service._store.db.set_trace_callback(barrier)
    service.prepare_muse(json.load(open(sys.argv[2])), inputs=json.load(open(sys.argv[3])))
'''
        child = subprocess.Popen([sys.executable, '-c', program, str(self.state), str(spec_path), str(inputs_path)],
                                 cwd=self.root, env=dict(os.environ), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            ready, _, _ = select.select([child.stdout], [], [], 15)
            self.assertTrue(ready, 'Preparation commit barrier was not reached.')
            self.assertEqual(child.stdout.readline(), b'prepared-before-commit\n')
            child.send_signal(signal.SIGKILL)
            child.communicate(timeout=5)
            self.assertEqual(child.returncode, -signal.SIGKILL)
        finally:
            if child.poll() is None:
                child.kill(); child.communicate(timeout=5)
        self.assertEqual(self.service._store.db.execute(
            "SELECT count(*) FROM settings WHERE name LIKE 'muse-production-preparation:%'").fetchone()[0], 0)
        self.assertEqual(self.invocations(), [])
        with RunService(self.state) as reopened:
            value = reopened.prepare_muse(self.task, inputs=self.inputs)
            self.assertEqual(reopened.muse_preparation(value['preparation_digest']), value)


if __name__ == '__main__':
    unittest.main()
