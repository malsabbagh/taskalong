"""Local exposure ledger tests. No runtime grant or production CLI dispatch."""
import concurrent.futures
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import unittest
from uuid import uuid4
import test_muse_lifecycle as lifecycle
from taskalong.api import RunService
from taskalong.errors import TaskAlongError
from taskalong.store import Store, encode
from taskalong.validation import canonical_bytes, digest, seal_versioned
from taskalong import muse_exposure as exposure, muse_runtime


class MuseExposureTests(unittest.TestCase):
    def setUp(self):
        self.f=lifecycle.MuseLifecycleTests('test_imported_run_cannot_skip_start_admission_or_replay')
        self.f.setUp();self.addCleanup(self.f.tearDown)
        self.f.service.close()
        with Store.maintenance(self.f.state) as store:
            store.upgrade(operation_key='exposure-fence',target_version=13,
                backup_dir=self.f.root/'backup-13',restore_dir=self.f.root/'restore-13')
        self.f.service=RunService(self.f.state);self.store=self.f.service._store

    def attempt(self, destination=None):
        # Original unexecuted imported-state data exercises storage transitions,
        # never an authenticated runtime or a successful admission observation.
        task=json.loads(canonical_bytes(self.f.task))
        if destination is not None:
            task.pop('digest');task['task_id']=str(uuid4());task['permissions']['inference_destination_id']=destination
            task=seal_versioned('task-spec',task,version='2.12')
        run=self.store.create_run(task,str(uuid4()))
        a={'attempt_id':str(uuid4()),'run_id':run['run_id'],'ordinal':1,
            'driver_config_digest':self.f.config['digest'],
            'admission':{'runtime_subject_digest':'b'*64},'process_receipt':None,'spawn_phase':'not_dispatched'}
        with self.store.transaction() as db:
            db.execute('INSERT INTO attempts VALUES(?,?,?,?,?)',(a['attempt_id'],a['run_id'],1,0,encode(a)))
        return a

    def reserve(self,a):
        with self.store.transaction() as db:return exposure.reserve(self.store,db,a)

    def release(self,a):
        receipt=self.store.detail('attempts',a['attempt_id']).get('process_receipt') or {'invocation_id':str(uuid4()),'pid':123,'pgid':123,'supervisor_pid':124,
            'started_unix_ms':1,'executable_sha256':'a'*64}
        with self.store.transaction() as db:
            stored=self.store.detail('attempts',a['attempt_id']);stored['process_receipt']=receipt;stored['spawn_phase']='spawned'
            db.execute('UPDATE attempts SET document=? WHERE attempt_id=?',(encode(stored),a['attempt_id']))
            return exposure.before_release(self.store,db,a,receipt)

    def finish(self,db,a,process,**kwargs):
        stored=self.store.detail('attempts',a['attempt_id']);stored['process']=process
        db.execute('UPDATE attempts SET document=? WHERE attempt_id=?',(encode(stored),a['attempt_id']))
        return exposure.finish(self.store,db,a,process,**kwargs)

    @staticmethod
    def stopped(**extra):
        return {'termination_confirmed':True,'group_termination_confirmed':True,
            'unaccounted_descendants':False,'timed_out':False,'cancelled':False,'output_limited':False,**extra}

    def test_public_view_and_cli_are_read_only_and_cannot_enable_dispatch(self):
        before=list(self.store.db.iterdump());v=self.f.service.muse_exposure()
        self.assertFalse(v['production_dispatch_allowed']);self.assertEqual(v['entries'],[])
        self.assertFalse(v['account_spending_cap_enforced'])
        r=subprocess.run([sys.executable,'-m','taskalong','--state-dir',str(self.f.state),'--json','muse-exposure'],
            cwd=self.f.root,env=dict(os.environ),capture_output=True,text=True,timeout=20)
        self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout)['data'],v)
        self.assertEqual(list(self.store.db.iterdump()),before);self.assertEqual(self.f.invocations(),[])

    def test_release_is_reserved_durably_and_cannot_be_repeated(self):
        a=self.attempt();self.reserve(a);self.release(a)
        with self.assertRaises(TaskAlongError) as e:self.release(a)
        self.assertEqual(e.exception.code,'muse_redispatch_forbidden')
        with RunService(self.f.state) as reopened:
            v=reopened.muse_exposure();self.assertTrue(v['entries'][0]['held'])
            self.assertEqual(v['entries'][0]['remote_usage'],'unknown')
            self.assertFalse(v['automatic_redispatch_allowed'])

    def test_one_global_slot_blocks_new_run_and_destination_alias(self):
        first,second=self.attempt(),self.attempt('alternate-destination');self.reserve(first)
        with self.assertRaises(TaskAlongError) as e:self.reserve(second)
        self.assertEqual(e.exception.code,'muse_remote_exposure_held')
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM muse_exposure_events').fetchone()[0],1)

    def test_transaction_rollback_does_not_leave_a_false_reservation(self):
        a=self.attempt()
        with self.assertRaises(RuntimeError),self.store.transaction() as db:
            exposure.reserve(self.store,db,a);raise RuntimeError('original test fault')
        self.assertEqual(exposure.view(self.store)['entries'],[])
        with self.assertRaises(TaskAlongError):exposure.reserve(self.store,self.store.db,a)

    def test_two_independent_writers_cannot_both_reserve(self):
        a,b=self.attempt(),self.attempt();barrier=threading.Barrier(2)
        def reserve(item):
            with Store(self.f.state) as other:
                barrier.wait(timeout=10)
                try:
                    with other.transaction() as db:exposure.reserve(other,db,item)
                    return 'reserved'
                except TaskAlongError as e:return e.code
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(reserve,[a,b]))
        self.assertCountEqual(results,['reserved','muse_remote_exposure_held'])

    def test_confirmed_local_stop_does_not_release_remote_exposure(self):
        a=self.attempt();self.reserve(a);self.release(a)
        with self.store.transaction() as db:
            self.finish(db,a,self.stopped(),local_confirmed=True,not_dispatched=False)
        v=exposure.view(self.store);self.assertTrue(v['entries'][0]['local_cessation_confirmed'])
        self.assertEqual(v['entries'][0]['phase'],'local_stopped')
        self.assertTrue(v['entries'][0]['held']);self.assertFalse(v['remote_settlement_supported'])
        with self.assertRaises(TaskAlongError):self.reserve(self.attempt())

    def test_no_send_before_prepare_can_release_only_that_local_slot(self):
        a=self.attempt();self.reserve(a)
        with self.store.transaction() as db:
            self.finish(db,a,{"termination_confirmed":True},local_confirmed=True,not_dispatched=True)
        v=exposure.view(self.store);self.assertEqual(v['entries'][0]['remote_usage'],'not_sent')
        self.assertTrue(v['new_local_invocation_allowed_by_exposure']);self.reserve(self.attempt())

    def test_release_then_no_send_claim_cannot_refund_remote_usage(self):
        a=self.attempt();self.reserve(a);self.release(a)
        with self.store.transaction() as db:
            self.finish(db,a,self.stopped(),local_confirmed=True,not_dispatched=True)
        self.assertTrue(exposure.view(self.store)['entries'][0]['held'])

    def test_timeout_cancel_overflow_and_numeric_proof_stay_honest(self):
        a=self.attempt();self.reserve(a);self.release(a)
        process=self.stopped(termination_confirmed=1,timed_out=True,cancelled=True,output_limited=True)
        with self.store.transaction() as db:
            self.finish(db,a,process,local_confirmed=True,not_dispatched=False)
        v=exposure.view(self.store)['entries'][0]
        self.assertEqual(v['phase'],'local_unknown');self.assertTrue(v['held'])
        self.assertFalse(v['local_cessation_confirmed'])

    def test_history_is_append_only_and_resealed_foreign_attempt_refuses(self):
        a=self.attempt();self.reserve(a)
        for sql in ('DELETE FROM muse_exposure_events',"UPDATE muse_exposure_events SET phase='not_sent'"):
            with self.assertRaises(sqlite3.IntegrityError):self.store.db.execute(sql)
        changed={**a,'admission':{'runtime_subject_digest':'c'*64}}
        self.store.db.execute('UPDATE attempts SET document=? WHERE attempt_id=?',(encode(changed),a['attempt_id']))
        with self.assertRaises(TaskAlongError):self.f.service.muse_exposure()

    def test_foreign_owned_receipt_cannot_be_attached_to_release(self):
        a=self.attempt();self.reserve(a)
        with self.assertRaises(TaskAlongError),self.store.transaction() as db:
            stored=self.store.detail('attempts',a['attempt_id']);stored['process_receipt']={'invocation_id':'original'}
            db.execute('UPDATE attempts SET document=? WHERE attempt_id=?',(encode(stored),a['attempt_id']))
            exposure.before_release(self.store,db,a,{'invocation_id':'foreign'})
        self.assertEqual(self.f.service.muse_exposure()['entries'][0]['phase'],'reserved')

    def test_prepared_executor_intent_prevents_a_false_no_send_refund(self):
        a=self.attempt();self.reserve(a)
        with self.store.transaction() as db:
            db.execute('INSERT INTO operations VALUES(?,?,?,?,?)',('executor.prepare',a['run_id'],a['attempt_id'],'a'*64,'{}'))
        with self.assertRaises(TaskAlongError),self.store.transaction() as db:
            self.finish(db,a,{'termination_confirmed':True},local_confirmed=True,not_dispatched=True)
        self.assertTrue(self.f.service.muse_exposure()['entries'][0]['held'])

    def test_resealed_not_sent_after_release_refuses_and_does_not_clear_hold(self):
        a=self.attempt();self.reserve(a);self.release(a)
        prior=json.loads(self.store.db.execute('SELECT document FROM muse_exposure_events ORDER BY sequence DESC LIMIT 1').fetchone()[0])
        forged={**prior,'phase':'not_sent','previous_digest':prior['digest']};forged['digest']=digest(forged)
        with self.assertRaises(TaskAlongError),self.store.transaction() as db:
            db.execute('INSERT INTO muse_exposure_events(attempt_id,run_id,phase,document) VALUES(?,?,?,?)',
                (a['attempt_id'],a['run_id'],'not_sent',encode(forged)))
            self.f.service.muse_exposure()
        self.assertTrue(self.f.service.muse_exposure()['entries'][0]['held'])

    def test_malformed_journal_refuses_with_typed_error(self):
        a=self.attempt()
        with self.store.transaction() as db:
            db.execute('INSERT INTO muse_exposure_events(attempt_id,run_id,phase,document) VALUES(?,?,?,?)',
                (a['attempt_id'],a['run_id'],'reserved','[]'))
        with self.assertRaises(TaskAlongError) as e:self.f.service.muse_exposure()
        self.assertEqual(e.exception.code,'muse_exposure_invalid')

    def test_actual_format12_reader_refuses13_before_database_write(self):
        path=Path(__file__).parent/'fixtures/legacy_store_v12.py'
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),'b7ad4f84cfd1843da5c5e2f326d0aa64a9194607902a7b45cf1da6452083c65b')
        spec=importlib.util.spec_from_file_location('taskalong._legacy_store_v12',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        before={p.name:p.read_bytes() for p in self.f.state.glob('state.sqlite3*')}
        with self.assertRaises(TaskAlongError) as e:module.Store(self.f.state)
        self.assertEqual(e.exception.code,'unsupported_store_version')
        self.assertEqual({p.name:p.read_bytes() for p in self.f.state.glob('state.sqlite3*')},before)

    def test_unknown_remote_usage_is_allowed_as_a_policy_outcome_not_a_hard_cap(self):
        v=muse_runtime.observe({'budget':{'attempt_seconds':60,'max_output_bytes':1048576,
            'hard_tokens':None,'hard_cost_usd':None}})
        self.assertFalse(v['usage_containment']['absolute_vendor_cessation_guarantee_required'])
        self.assertNotIn('muse_hard_inference_budget_unsupported',v['reason_codes'])
        self.assertIn('muse_hard_inference_budget_unsupported',muse_runtime.observe({'budget':{'hard_tokens':1}})['reason_codes'])
        self.assertFalse(v['production_dispatch_allowed'])
