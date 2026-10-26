"""Actual ordered fixture workers through the public CLI and service boundary."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from helpers import ServiceFixture, git
from taskalong.api import RunService
from taskalong.errors import TaskAlongError
from taskalong.store import Store
from taskalong.validation import seal_versioned
from test_antigravity_store import upgrade_through


class OrderedFixture(ServiceFixture):
    def setUp(self):
        super().setUp()
        (self.repo / 'second.py').write_text('def add(a, b):\n    return a - b\n')
        git(self.repo, 'add', 'second.py'); git(self.repo, 'commit', '-m', 'Second fixture file')
        self.base = git(self.repo, 'rev-parse', 'HEAD')
        self.service.close()
        with Store.maintenance(self.state) as store:
            upgrade_through(store, self.root, 10)
        self.service = RunService(self.state)

    def ordered(self, **changes):
        task = self.spec(check_argv=[sys.executable, '-B', '-c', 'from arithmetic import add; from second import add as b; assert add(2,3)==5 and b(3,4)==7'], total_seconds=160)
        task.update(schema_version='2.7', scope={'files':['arithmetic.py','second.py'],'operations':['modify']},
            steps=[{'step_id':name,'goal':'Correct addition in '+path,'scope':{'files':[path],'operations':['modify']},'inputs':[],'required':True} for name,path in [('A','arithmetic.py'),('B','second.py')]],
            final_verification={'max_passes':1,'total_active_seconds':100,'max_output_bytes':524288})
        task['budget'].update(max_attempts=4,attempt_output_bytes=65536)
        task.update(changes)
        return seal_versioned('task-spec',task,version='2.7')

    def first(self, task=None):
        run, spec = self.submit(task or self.ordered())
        self.start(run)
        return self.wait(run['run_id'], predicate=lambda x:not x['active_attempt_id'] and x['state'] in {'ready','blocked','cancelled'}),spec

    def advance(self, run, key='advance'):
        return self.service.advance(run['run_id'],expected_step_id='B',predecessor_digest=run['steps'][0]['receipt_digest'],operation_key=key,expected_revision=run['revision'])

    def cli(self,*args):
        result=subprocess.run([sys.executable,'-m','taskalong','--state-dir',str(self.state),'--json',*args],capture_output=True,text=True,timeout=20)
        return result.returncode,json.loads(result.stdout)


class OrderedTasksTests(OrderedFixture,unittest.TestCase):
    def cancel_during_finish(self, *, final):
        task=self.ordered()
        if final:
            task['steps']=task['steps'][:1]
            task=seal_versioned('task-spec',task,version='2.7')
        run,_=self.submit(task)
        with patch.object(self.service._workflow,'_launch_supervisor',lambda *a:None):
            prepared=self.start(run)
        from taskalong.workflow import drive_run
        from taskalong import steps
        original=steps.completed_receipt
        reserved=self.service._store.run(run['run_id'])['reservation_totals']
        def cancel_at_receipt(*args,**kwargs):
            receipt=original(*args,**kwargs)
            current=self.service.inspect(run['run_id'])
            self.service.cancel(run['run_id'],operation_key='cancel-at-receipt',expected_revision=current['revision'])
            return receipt
        with patch('taskalong.steps.completed_receipt',cancel_at_receipt):
            drive_run(self.state,run['run_id'],prepared['active_attempt_id'])
        self.service.close();self.service=RunService(self.state)
        current=self.service.inspect(run['run_id'])
        self.assertEqual(current['state'],'cancelled')
        self.assertEqual(current['steps'][0]['status'],'cancelled')
        self.assertIsNone(current['steps'][0]['receipt_digest'])
        self.assertEqual(current['reservation_totals'],reserved)
        self.assertIsNone(current['candidate']);self.assertIsNone(current['acceptance_id'])
        self.assertEqual(current['final_verification_ids'],[])
        self.assertEqual(len(self.invocations()),1)
        self.assertEqual(self.service.result(run['run_id'])['outcome'],'cancelled')

    def test_cancellation_wins_intermediate_receipt_finish_race(self):
        self.cancel_during_finish(final=False)

    def test_cancellation_wins_final_receipt_finish_race(self):
        self.cancel_during_finish(final=True)

    def test_preparation_interruption_recovers_the_same_reserved_attempt(self):
        run,_=self.submit(self.ordered())
        with patch.object(self.service._workflow,'_launch_supervisor',side_effect=RuntimeError('test interruption before supervisor launch')):
            with self.assertRaises(RuntimeError):self.start(run)
        prepared=self.service.inspect(run['run_id'])
        self.assertEqual(self.invocations(),[])
        self.service.close();self.service=RunService(self.state)
        self.service.reconcile(run['run_id'],operation_key='recover-preparation',expected_revision=prepared['revision'])
        first=self.wait(run['run_id'],predicate=lambda r:not r['active_attempt_id'] and r['state']=='ready')
        self.assertEqual(first['steps'][0]['attempt_ids'],prepared['steps'][0]['attempt_ids'])
        self.assertEqual(first['reservation_totals'],prepared['reservation_totals'])
        self.assertEqual(len(self.invocations()),1)

    def test_late_completed_result_cannot_overwrite_the_newer_step(self):
        first,_=self.first();attempt_id=first['steps'][0]['attempt_ids'][0]
        old=self.service._store.detail('attempts',attempt_id)
        self.barrier_file.touch();self.advance(first)
        second=self.wait(first['run_id'],predicate=lambda r:r['state']=='running')
        before=self.service._store.run(first['run_id'])
        from taskalong.workflow import _finish_attempt
        worker=json.loads(self.service._store.get_blob(old['result_artifact']['sha256']))
        _finish_attempt(self.service._store,first['run_id'],attempt_id,{'state':'completed','process':old['process'],
            'checkpoint':old['checkpoint'],'thread_id':old['thread_id'],'usage':{}},worker)
        self.assertEqual(self.service._store.run(first['run_id']),before)
        self.assertNotEqual(second['active_attempt_id'],attempt_id)
        self.release_file.touch()

    def test_quiescent_ordered_store_can_be_backed_up_and_restored(self):
        run,_=self.submit(self.ordered())
        self.service.close()
        from taskalong.maintenance import verify_backup, restore_backup, verify_restored
        with Store.maintenance(self.state) as store:
            manifest=store.backup(self.root/'ordered-backup',complete=True)
            verified=verify_backup(self.root/'ordered-backup',expected_digest=manifest['digest'])
            self.assertEqual(verified['database']['user_version'],10)
            restore_backup(self.root/'ordered-backup',self.root/'ordered-restore',expected_digest=manifest['digest'])
            self.assertTrue(verify_restored(self.root/'ordered-backup',self.root/'ordered-restore',expected_digest=manifest['digest'])['quarantined'])
        self.service=RunService(self.state)
        self.assertEqual(self.service.inspect(run['run_id'])['steps'],run['steps'])

    def test_public_cli_validation_and_intermediate_result(self):
        spec=self.ordered(); path=self.root/'task.json';path.write_text(json.dumps(spec))
        code,view=self.cli('validate','--spec',str(path));self.assertEqual(code,0,view)
        self.assertEqual(view['data']['step_count'],2)
        run,_=self.first(spec)
        self.assertEqual([s['status'] for s in run['steps']],['completed','pending'],run)
        self.assertIsNone(run['candidate']);self.assertIsNone(run['acceptance_id'])
        code,view=self.cli('result',run['run_id']);self.assertEqual(code,0,view)
        self.assertEqual(view['data']['next_actions'],['advance']);self.assertFalse(view['data']['independently_accepted'])
        self.assertLess(view['data']['observed_usage']['worker_duration_ms'],run['reservation_totals']['active_seconds']*1000)
        self.assertLess(view['data']['observed_usage']['captured_output_bytes'],run['reservation_totals']['output_bytes'])
        self.assertEqual(len(self.invocations()),1)
        self.assertEqual(run['reservation_totals']['attempts'],1)

    def test_explicit_advance_replay_runs_only_next_worker(self):
        first,_=self.first(); self.assertEqual(first['steps'][0]['status'],'completed',first)
        prepared=self.advance(first)
        self.assertEqual(self.advance(first),prepared)
        final=self.wait(first['run_id'])
        self.assertEqual([s['status'] for s in final['steps']],['completed','completed'],final)
        self.assertEqual(len(self.invocations()),2)
        self.assertEqual(final['reservation_totals']['attempts'],2)
        self.assertEqual(final['reservation_totals']['output_bytes'],2*65536+524288)
        self.assertIsNotNone(final['execution_chain_digest'])
        with self.assertRaises(TaskAlongError) as error:
            self.service.advance(first['run_id'],expected_step_id='A',predecessor_digest=first['steps'][0]['receipt_digest'],operation_key='advance',expected_revision=first['revision'])
        self.assertEqual(error.exception.code,'operation_key_conflict')

    def test_failed_b_retry_preserves_a_and_no_refund(self):
        first,_=self.first(); self.set_mode('failed'); self.advance(first)
        failed=self.wait(first['run_id']);self.assertEqual(failed['steps'][1]['status'],'failed',failed)
        self.set_mode('good');self.service.retry(first['run_id'],expected_step_id='B',operation_key='retry',expected_revision=failed['revision'])
        final=self.wait(first['run_id']);self.assertEqual(final['steps'][1]['status'],'completed',final)
        self.assertEqual(final['steps'][0],first['steps'][0]);self.assertEqual(len(self.invocations()),3)
        self.assertEqual(final['reservation_totals']['attempts'],3)

    def test_cancel_between_steps_and_checkpoint_tamper_block(self):
        first,_=self.first();work=Path(self.service._store.lease(first)['workspace']['path'])
        (work/'arithmetic.py').write_text('def add(a,b): return 44\n')
        with self.assertRaises(TaskAlongError) as error:self.advance(first)
        self.assertEqual(error.exception.code,'checkpoint_stale');self.assertEqual(len(self.invocations()),1)
        cancelled=self.service.cancel(first['run_id'],operation_key='cancel',expected_revision=first['revision'])
        self.service.reconcile(first['run_id'],operation_key='cancel-reconcile',expected_revision=cancelled['revision'])
        with self.assertRaises(TaskAlongError):self.advance(first,key='after-cancel')
        self.assertEqual(len(self.invocations()),1)

    def test_duplicate_ids_and_unsupported_inputs_refuse_before_launch(self):
        task=self.ordered();task['steps'][1]['step_id']='A'
        with self.assertRaises(TaskAlongError) as error:seal_versioned('task-spec',task,version='2.7')
        self.assertEqual(error.exception.code,'duplicate_step_id')
        task=self.ordered();task['steps'][0]['inputs']=[{'step_id':'B','output':'future'}]
        with self.assertRaises(TaskAlongError):seal_versioned('task-spec',task,version='2.7')
        self.assertEqual(self.invocations(),[])

    def test_released_fixture_review_accepts_only_complete_task(self):
        reviewer=os.environ.get('TASKALONG_REVIEW_EXECUTABLE')
        if not reviewer:self.skipTest('released reviewer is required in full qualification')
        config=Path(__file__).parent/'fixtures/reviewsensei/approved.yml'
        configured=self.service.configure_review(config,fixture_response=Path(__file__).parent/'fixtures/reviewsensei/clean.json',executable=reviewer)
        task=self.ordered();task['review']['config_digest']=configured['config_digest'];task=seal_versioned('task-spec',task,version='2.7')
        first,_=self.first(task);self.advance(first);final=self.wait(first['run_id'],timeout=35)
        self.assertEqual(final['state'],'accepted',final)
        self.assertTrue(self.service.result(first['run_id'])['independently_accepted'])


if __name__=='__main__':unittest.main()
