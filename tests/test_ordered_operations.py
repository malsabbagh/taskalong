"""Step-relative operations, independently of cumulative task-base scope."""
import hashlib
import unittest
from taskalong.validation import seal, seal_versioned
from test_ordered_tasks import OrderedFixture


class OrderedOperationTests(OrderedFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        source=self.executable.read_text()
        additions='''    if mode == "ordered-add":
        Path("new.py").write_text("def value():\\n    return 1\\n")
        changed = [{"path":"new.py", "operation":"add"}]
    if mode == "ordered-remove":
        Path("new.py").unlink()
        changed = [{"path":"new.py", "operation":"add"}]
    if mode == "ordered-restore":
        Path("arithmetic.py").write_text("def add(a, b):\\n    return a - b\\n")
        changed = [{"path":"arithmetic.py", "operation":"modify"}]
'''
        self.executable.write_text(source.replace('    result = {',additions+'    result = {',1))
        self.profile=seal('runtime-profile',self.profile|{'profile_id':'ordered-operations',
            'executable_sha256':hashlib.sha256(self.executable.read_bytes()).hexdigest()})
        self.service.register_profile(self.profile)

    def task(self, second_operation='modify'):
        task=self.ordered()
        task['scope']={'files':['new.py'],'operations':['add','modify']}
        for index,step in enumerate(task['steps']):
            step['scope']={'files':['new.py'],'operations':['add' if index==0 else second_operation]}
        return seal_versioned('task-spec',task,version='2.7')

    def test_added_file_can_be_modified_by_later_modify_step(self):
        self.set_mode('ordered-add');first,_=self.first(self.task())
        self.set_mode('good');self.advance(first)
        final=self.wait(first['run_id'])
        self.assertEqual([s['status'] for s in final['steps']],['completed','completed'],final)
        self.assertEqual(len(self.invocations()),2)

    def test_added_file_removal_refuses_even_under_add_step(self):
        self.set_mode('ordered-add');first,_=self.first(self.task('add'))
        self.set_mode('ordered-remove');self.advance(first)
        failed=self.wait(first['run_id'])
        self.assertEqual(failed['steps'][1]['status'],'failed')
        self.assertIn('step_delete_unsupported',{b['code'] for b in failed['blockers']})
        self.assertIsNone(failed['steps'][1]['receipt_digest'])
        self.assertIsNone(self.service._store.detail('attempts',failed['steps'][1]['attempt_ids'][-1])['checkpoint'])
        self.assertIsNone(failed['candidate'])
        self.assertEqual(self.service.result(first['run_id'])['next_actions'],['inspect'])

    def test_added_file_modification_refuses_under_add_only_step(self):
        self.set_mode('ordered-add');first,_=self.first(self.task('add'))
        self.set_mode('good');self.advance(first)
        failed=self.wait(first['run_id'])
        self.assertEqual(failed['steps'][1]['status'],'failed')
        self.assertIn('step_scope_violation',{b['code'] for b in failed['blockers']})

    def test_restoring_original_base_bytes_is_step_modification(self):
        task=self.ordered()
        task['steps'][1]['scope']={'files':['arithmetic.py'],'operations':['modify']}
        task=seal_versioned('task-spec',task,version='2.7')
        first,_=self.first(task);self.set_mode('ordered-restore');self.advance(first)
        final=self.wait(first['run_id'])
        self.assertEqual([s['status'] for s in final['steps']],['completed','completed'],final)


if __name__=='__main__':unittest.main()
