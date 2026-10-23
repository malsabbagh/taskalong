"""Maintenance uses real locks, private temporary state and independent snapshots."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import subprocess
import sys
from importlib import resources
import errno
import select
import signal
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong.store import Store
from test_contracts import example_spec, example_profile
from helpers import ServiceFixture
from taskalong.api import RunService


def legacy_store():
    path = Path(__file__).parent / "fixtures/legacy_store_v1.py"
    spec = importlib.util.spec_from_file_location("taskalong._legacy_store_v1", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Store


LOCK_WITNESS = r'''
import json,os,sqlite3,sys
from pathlib import Path
path,nonce,operation,expected,ready=sys.argv[1:];ready=int(ready)
expected=json.loads(expected)
result={'nonce':nonce,'phase':'setup','operation':operation,'outcome':'error',
        'identity':None,'sqlite_version':sqlite3.sqlite_version,'error_code':None,
        'base_code':None,'value':None,'connection_closed':False,'rollback_complete':False}
connection=None
try:
    selected=Path(path).resolve(strict=True)
    info=selected.stat();identity={'device':info.st_dev,'inode':info.st_ino}
    result['identity']=identity
    if identity!=expected:raise ValueError('identity')
    connection=sqlite3.connect(selected.as_uri()+'?mode=rw',uri=True,timeout=0,isolation_level=None)
    if connection.execute('PRAGMA busy_timeout=0').fetchone()[0]!=0:raise ValueError('timeout')
    info=selected.stat()
    if identity!={'device':info.st_dev,'inode':info.st_ino}:raise ValueError('identity')
    os.write(ready,b'R');os.close(ready)
    result['phase']='protected_operation'
    try:
        if operation=='read_version':version=connection.execute('PRAGMA user_version').fetchone()[0]
        elif operation=='begin_write':connection.execute('BEGIN IMMEDIATE');version=None
        else:raise ValueError('operation')
    except sqlite3.OperationalError as exc:
        code=getattr(exc,'sqlite_errorcode',None)
        result['error_code']=code
        if type(code) is int:
            result['base_code']=code&255
            if code&255==sqlite3.SQLITE_BUSY:result['outcome']='busy'
    else:
        result['phase']='identity_check'
        if version is None:version=connection.execute('PRAGMA user_version').fetchone()[0]
        identity_uuid=connection.execute("SELECT value FROM metadata WHERE key='store_uuid'").fetchone()[0]
        result.update(phase='protected_operation',outcome='success',value={'format':version,'store_uuid':identity_uuid})
except Exception:
    result['outcome']='error'
finally:
    if connection is not None:
        try:
            if connection.in_transaction:connection.rollback()
            result['rollback_complete']=not connection.in_transaction
        except Exception:pass
        try:connection.close();result['connection_closed']=True
        except Exception:pass
    print(json.dumps(result,separators=(',',':')),flush=True)
'''


def database_identity(state):
    info=(state/'state.sqlite3').stat()
    return {'device':info.st_dev,'inode':info.st_ino}


def parse_lock_receipt(output, *, nonce, operation, identity, store_uuid):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('duplicate field')
            result[key]=value
        return result
    if len(output.encode('utf-8'))>4096:raise ValueError('oversized receipt')
    result=json.loads(output,object_pairs_hook=unique)
    keys={'nonce','phase','operation','outcome','identity','sqlite_version','error_code',
          'base_code','value','connection_closed','rollback_complete'}
    if type(result) is not dict or set(result)!=keys:raise ValueError('receipt shape')
    if result['nonce']!=nonce or result['operation']!=operation:raise ValueError('correlation')
    if result['phase']!='protected_operation':raise ValueError('wrong phase')
    if (type(result['identity']) is not dict or set(result['identity'])!={'device','inode'}
            or any(type(v) is not int for v in result['identity'].values()) or result['identity']!=identity):
        raise ValueError('wrong database')
    if type(result['sqlite_version']) is not str or not 0<len(result['sqlite_version'])<=64:raise ValueError('sqlite identity')
    if result['connection_closed'] is not True or result['rollback_complete'] is not True:raise ValueError('cleanup unconfirmed')
    if result['outcome']=='success':
        if result['error_code'] is not None or result['base_code'] is not None:raise ValueError('success with error')
        value=result['value']
        if (type(value) is not dict or set(value)!={'format','store_uuid'} or type(value['format']) is not int
                or value!={'format':1,'store_uuid':store_uuid}):raise ValueError('wrong logical identity')
    elif result['outcome']=='busy':
        code=result['error_code']
        if (type(code) is not int or code&255!=sqlite3.SQLITE_BUSY or
                type(result['base_code']) is not int or result['base_code']!=code&255 or result['value'] is not None):
            raise ValueError('not numeric BUSY')
    else:raise ValueError('operation did not provide proof')
    return result


def require_lock_denial(receipt):
    code=receipt['error_code']
    if receipt['outcome']!='busy' or type(code) is not int or code&255!=sqlite3.SQLITE_BUSY:
        raise AssertionError('The protected SQLite operation was not refused with numeric BUSY')


def run_lock_witness(state, operation, store_uuid):
    nonce=os.urandom(16).hex();identity=database_identity(state)
    reader,writer=os.pipe()
    child=None
    try:
        child=subprocess.Popen([sys.executable,'-c',LOCK_WITNESS,str(state/'state.sqlite3'),
            nonce,operation,json.dumps(identity),str(writer)],close_fds=True,pass_fds=(writer,),
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        os.close(writer);writer=None
        if not select.select([reader],[],[],15)[0] or os.read(reader,1)!=b'R':
            raise AssertionError('SQLite witness did not complete setup readiness')
        try:output,error=child.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill();child.communicate(timeout=5)
            raise AssertionError('SQLite witness exceeded ten-second containment; no exclusion proof') from None
        if child.returncode!=0 or child.poll() is None:raise AssertionError('SQLite witness exit/reap unconfirmed')
        if error:raise AssertionError('SQLite witness emitted unexpected stderr')
        if database_identity(state)!=identity:raise AssertionError('Database identity changed')
        return parse_lock_receipt(output,nonce=nonce,operation=operation,identity=identity,store_uuid=store_uuid)
    finally:
        os.close(reader)
        if writer is not None:os.close(writer)
        if child is not None and child.poll() is None:
            child.kill();child.communicate(timeout=5)


def logical_fingerprint(store):
    """Use the owning DB connection; never open a second parent DB descriptor."""
    schema=[tuple(r) for r in store.db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name')]
    tables={}
    for name, in store.db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
        quoted='"'+name.replace('"','""')+'"'
        tables[name]=sorted((tuple(r) for r in store.db.execute('SELECT * FROM '+quoted)),key=repr)
    files=[]
    excluded={'state.sqlite3','state.sqlite3-wal','state.sqlite3-shm','state.sqlite3-journal','initialize.lock','maintenance.lock'}
    for path in sorted(store.root.rglob('*')):
        relative=path.relative_to(store.root).as_posix()
        if relative in excluded:continue
        if path.is_symlink():raise AssertionError('Unexpected fixture symlink')
        mode=path.stat().st_mode&0o777
        files.append((relative,mode,'directory' if path.is_dir() else hashlib.sha256(path.read_bytes()).hexdigest()))
    return {'schema':schema,'tables':tables,'files':files,'version':store.db.execute('PRAGMA user_version').fetchone()[0],
            'store_uuid':store.store_uuid}


class StoreMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.state = self.root / "state"
        with Store(self.state) as store:
            self.run = store.create_run(example_spec(), "submit")
            self.blob = store.put_blob(b"synthetic retained evidence")
            self.store_uuid = store.store_uuid

    def tearDown(self):
        self.temporary.cleanup()

    def test_advisory_only_owner_cannot_fool_real_sqlite_exclusion_witnesses(self):
        import fcntl
        with Store(self.state) as store:before=logical_fingerprint(store)
        observations=[]
        descriptor=os.open(self.state/'maintenance.lock',os.O_RDWR)
        try:
            fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
            for operation in ('read_version','begin_write'):
                with self.subTest(operation=operation):
                    receipt=run_lock_witness(self.state,operation,self.store_uuid)
                    self.assertEqual(receipt['outcome'],'success')
                    with self.assertRaises(AssertionError):require_lock_denial(receipt)
                    observations.append({'denial_assertion_rejected':True,'receipt':receipt})
        finally:os.close(descriptor)
        with Store(self.state) as store:self.assertEqual(logical_fingerprint(store),before)
        print(json.dumps({'kind':'maintenance_advisory_only_counterexample','observations':observations,
                          'logical_state_unchanged':True}),file=sys.stderr,flush=True)

    def test_real_sqlite_witnesses_refuse_reads_and_writes_only_while_maintenance_owns_state(self):
        control=self.state/'.codex'
        control.mkdir(mode=0o700)
        (control/'AGENTS.md').write_bytes(b'Synthetic retained control data, never authority.')
        (control/'AGENTS.md').chmod(0o600)
        with Store(self.state) as store:before=logical_fingerprint(store)
        observations=[]
        for operation in ('read_version','begin_write'):
            receipt=run_lock_witness(self.state,operation,self.store_uuid)
            self.assertEqual(receipt['outcome'],'success')
            observations.append({'owner_phase':'before','parent_observed_reaped':True,'receipt':receipt})
        with Store.maintenance(self.state) as owner:
            self.assertEqual(owner.db.execute('PRAGMA locking_mode').fetchone()[0],'exclusive')
            self.assertEqual(owner.db.execute('PRAGMA journal_mode').fetchone()[0],'delete')
            locked=logical_fingerprint(owner)
            self.assertEqual(locked,before)
            for operation in ('read_version','begin_write'):
                with self.subTest(operation=operation):
                    receipt=run_lock_witness(self.state,operation,self.store_uuid)
                    require_lock_denial(receipt)
                    self.assertEqual(receipt['base_code'],sqlite3.SQLITE_BUSY)
                    self.assertEqual(logical_fingerprint(owner),locked)
                    observations.append({'owner_phase':'owned','parent_observed_reaped':True,'receipt':receipt})
        for operation in ('read_version','begin_write'):
            receipt=run_lock_witness(self.state,operation,self.store_uuid)
            self.assertEqual(receipt['outcome'],'success')
            observations.append({'owner_phase':'after','parent_observed_reaped':True,'receipt':receipt})
        with Store(self.state) as store:self.assertEqual(logical_fingerprint(store),before)
        print(json.dumps({'kind':'maintenance_real_kernel_exclusion','observations':observations,
                          'logical_state_unchanged':True,'owner_locking':'exclusive','owner_journal':'delete',
                          'claim':'independent zero-wait witnesses; not legacy busy-handler latency'}),file=sys.stderr,flush=True)

    def test_lock_witness_protocol_rejects_missing_wrong_or_unrelated_evidence(self):
        from copy import deepcopy
        nonce='a'*32;identity=database_identity(self.state)
        valid={'nonce':nonce,'phase':'protected_operation','operation':'read_version','outcome':'busy',
            'identity':identity,'sqlite_version':sqlite3.sqlite_version,'error_code':sqlite3.SQLITE_BUSY,
            'base_code':sqlite3.SQLITE_BUSY,'value':None,'connection_closed':True,'rollback_complete':True}
        def parse(output):
            return parse_lock_receipt(output,nonce=nonce,operation='read_version',identity=identity,store_uuid=self.store_uuid)
        require_lock_denial(parse(json.dumps(valid)))
        extended=deepcopy(valid);extended['error_code']=sqlite3.SQLITE_BUSY|256
        require_lock_denial(parse(json.dumps(extended)))
        cases=[('',None),('nonobject',json.dumps([valid])),('duplicate/trailing',json.dumps(valid)+'\n'+json.dumps(valid)),
               ('duplicate key',json.dumps(valid)[:-1]+',"nonce":"'+nonce+'"}'),('oversized',' '*4097)]
        for field,value in [('nonce','b'*32),('phase','setup'),('operation','begin_write'),
                ('identity',{'device':identity['device'],'inode':identity['inode']+1}),
                ('identity',{'device':True,'inode':identity['inode']}),('error_code',None),
                ('error_code',True),('error_code','5'),('error_code',5.0),('error_code',sqlite3.SQLITE_LOCKED),
                ('error_code',sqlite3.SQLITE_READONLY),('error_code',sqlite3.SQLITE_CANTOPEN),
                ('base_code',True),('outcome','error'),('connection_closed',False),('rollback_complete',False)]:
            bad=deepcopy(valid);bad[field]=value;cases.append((field+':'+str(value),json.dumps(bad)))
        bad=deepcopy(valid);del bad['nonce'];cases.append(('missing nonce',json.dumps(bad)))
        bad=deepcopy(valid);del bad['error_code'];cases.append(('missing error code',json.dumps(bad)))
        bad=deepcopy(valid);bad['extra']='unexpected';cases.append(('extra field',json.dumps(bad)))
        for name,output in cases:
            with self.subTest(case=name),self.assertRaises((ValueError,TypeError)):
                parse('' if output is None else output)

    def test_ready_witness_timeout_is_failure_and_owned_child_is_killed_and_reaped(self):
        from unittest.mock import Mock
        child=Mock();child.returncode=None
        child.poll.side_effect=lambda:child.returncode
        child.kill.side_effect=lambda:setattr(child,'returncode',-signal.SIGKILL)
        child.communicate.side_effect=[subprocess.TimeoutExpired('synthetic-witness',10),('','')]
        def start(*args,**kwargs):
            os.write(kwargs['pass_fds'][0],b'R')
            return child
        with patch.object(subprocess,'Popen',side_effect=start):
            with self.assertRaisesRegex(AssertionError,'no exclusion proof'):
                run_lock_witness(self.state,'read_version',self.store_uuid)
        child.kill.assert_called_once_with()
        self.assertEqual([call.kwargs['timeout'] for call in child.communicate.call_args_list],[10,5])
        self.assertEqual(child.returncode,-signal.SIGKILL)

    def test_current_client_lifetime_gate_refuses_maintenance(self):
        with Store(self.state):
            with self.assertRaises(TaskAlongError) as failure:
                Store.maintenance(self.state)
            self.assertEqual(failure.exception.code, "maintenance_busy")
        with Store.maintenance(self.state):
            with self.assertRaises(TaskAlongError) as failure:
                Store(self.state)
            self.assertEqual(failure.exception.code, "maintenance_busy")

    def test_system_alias_and_directory_identity_cannot_hide_overlapping_targets(self):
        from taskalong.maintenance import restore_backup
        aliases = [(alias,alias.resolve()) for alias in (Path("/var"),Path("/tmp"))
                   if alias.is_symlink() and self.root.is_relative_to(alias.resolve())]
        if not aliases:self.skipTest("No trusted OS directory alias contains this fixture root")
        alias,canonical = aliases[0]
        for operation in ("backup","upgrade"):
            state = self.root / ("alias-"+operation)
            with Store(state):pass
            nested = state/"nested"
            selected = alias/nested.relative_to(canonical)
            with self.subTest(operation=operation):
                with Store.maintenance(state) as store:
                    with self.assertRaises(TaskAlongError) as failure:
                        if operation == "backup":store.backup(selected,complete=True)
                        else:store.upgrade(operation_key="alias-refused",backup_dir=self.root/"outside",restore_dir=selected)
                    self.assertEqual(failure.exception.code,"backup_target" if operation=="backup" else "maintenance_target")
                    self.assertEqual(store.format_version,1)
                    self.assertEqual(store.db.execute("SELECT count(*) FROM operations").fetchone()[0],0)
                self.assertFalse(nested.exists())
        case_source = self.root/"CaseSource"
        with Store(case_source):pass
        alternate = case_source.with_name(case_source.name.swapcase())
        if alternate.exists() and alternate.samefile(case_source):
            with Store.maintenance(case_source) as store:
                with self.assertRaises(TaskAlongError) as failure:store.backup(alternate/"nested",complete=True)
                self.assertEqual(failure.exception.code,"backup_target")
                self.assertFalse((case_source/"nested").exists())
        backup = self.root/"valid-backup"
        with Store.maintenance(self.state) as store:manifest=store.backup(backup,complete=True)
        with self.assertRaises(TaskAlongError) as failure:
            restore_backup(backup,alias/(backup/"nested").relative_to(canonical),expected_digest=manifest["digest"])
        self.assertEqual(failure.exception.code,"restore_target")
        self.assertFalse((backup/"nested").exists())

    def test_selected_and_captured_directory_symlinks_stay_rejected(self):
        from taskalong.maintenance import restore_backup
        selected = self.root/"operator-link"
        selected.symlink_to(self.state,target_is_directory=True)
        backup = self.root/"valid-backup"
        with Store.maintenance(self.state) as store:
            manifest=store.backup(backup,complete=True)
            with self.assertRaises(TaskAlongError) as failure:store.backup(selected/"nested",complete=True)
            self.assertEqual(failure.exception.code,"unsafe_state_path")
        with self.assertRaises(TaskAlongError) as failure:
            restore_backup(backup,selected/"nested",expected_digest=manifest["digest"])
        self.assertEqual(failure.exception.code,"unsafe_state_path")
        self.assertFalse((self.state/"nested").exists())
        outside=self.root/"external-control"
        outside.mkdir(mode=0o700)
        payload=outside/"private-capture"
        payload.write_bytes(b"synthetic external control")
        payload.chmod(0o600)
        (self.state/"redirect").symlink_to(outside,target_is_directory=True)
        partial=self.root/"refused-copy"
        with Store.maintenance(self.state) as store:
            with self.assertRaises(TaskAlongError) as failure:store.backup(partial,complete=True)
            self.assertEqual(failure.exception.code,"unsafe_state_path")
        self.assertTrue(partial.exists())
        self.assertFalse((partial/"redirect/private-capture").exists())
        self.assertEqual(payload.read_bytes(),b"synthetic external control")

    def test_predecessor_ignores_gate_but_kernel_refuses_exclusivity(self):
        with legacy_store()(self.state):
            with self.assertRaises(TaskAlongError) as failure:
                Store.maintenance(self.state)
            self.assertEqual(failure.exception.code, "maintenance_exclusivity_unproven")
        with Store.maintenance(self.state) as maintenance:
            self.assertEqual(maintenance.db.execute("PRAGMA locking_mode").fetchone()[0], "exclusive")
            self.assertEqual(maintenance.db.execute("PRAGMA journal_mode").fetchone()[0], "delete")
            connection = sqlite3.connect(self.state / "state.sqlite3", timeout=.01)
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    connection.execute("SELECT * FROM metadata").fetchall()
            finally:
                connection.close()
        with legacy_store()(self.state) as reopened:
            self.assertEqual(reopened.store_uuid, self.store_uuid)

    def test_uncertain_attempt_and_unresolved_effect_refuse_maintenance(self):
        for active, confirmed in ((1, True), (0, False), (0, None)):
            with Store(self.state) as store:
                store.db.execute("INSERT INTO attempts VALUES(?,?,?,?,?)", ("fixture-attempt", self.run["run_id"], 1, active,
                    json.dumps({"termination_confirmed": confirmed})))
            try:
                with self.subTest(active=active, confirmed=confirmed), self.assertRaises(TaskAlongError) as failure:
                    with Store.maintenance(self.state):
                        pass
                self.assertEqual(failure.exception.code, "maintenance_not_quiescent")
            finally:
                with Store(self.state) as store:
                    store.db.execute("DELETE FROM attempts")
        with Store(self.state) as store:
            store.db.execute("INSERT INTO effects VALUES(?,?,?,?,?,?,?)", ("fixture-effect", self.run["run_id"], "fixture", "executor.start", "a"*64,
                "unknown", json.dumps({"phase":"unknown", "kind":"executor.start", "response":None})))
        with self.assertRaises(TaskAlongError) as failure:
            with Store.maintenance(self.state):
                pass
        self.assertEqual(failure.exception.code, "maintenance_not_quiescent")

    def test_complete_backup_and_fresh_restore_preserve_private_control_and_rows(self):
        from taskalong.maintenance import restore_backup, verify_backup
        capture = self.state / "attempts/retained/capture.txt"
        capture.parent.parent.mkdir(mode=0o700)
        capture.parent.mkdir(mode=0o700)
        capture.write_bytes(b"synthetic stopped-process capture")
        capture.chmod(0o700)
        backup, restored = self.root / "backup", self.root / "restored"
        with Store.maintenance(self.state) as store:
            expected = {name: [tuple(row) for row in store.db.execute("SELECT * FROM " + name + " ORDER BY 1")]
                        for name in ("runs", "events", "operations", "blobs")}
            manifest = store.backup(backup, complete=True)
        self.assertEqual(verify_backup(backup, expected_digest=manifest["digest"]), manifest)
        files = {item["path"]: item for item in manifest["files"]}
        self.assertIn("blobs/" + self.blob["sha256"], files)
        self.assertIn("attempts/retained/capture.txt", files)
        self.assertNotIn("state.sqlite3-wal", files)
        for name, item in files.items():
            path = backup / name
            self.assertEqual(path.stat().st_mode & 0o777, item["mode"])
            self.assertEqual(item["mode"] & 0o077, 0)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), item["sha256"])
        receipt = restore_backup(backup, restored, expected_digest=manifest["digest"])
        self.assertEqual(receipt["backup_digest"], manifest["digest"])
        self.assertTrue(receipt["quarantined"])
        self.assertEqual((restored / "attempts/retained/capture.txt").read_bytes(), capture.read_bytes())
        self.assertEqual((restored / "attempts/retained/capture.txt").stat().st_mode & 0o777, 0o700)
        with sqlite3.connect(restored / "state.sqlite3") as db:
            for name, rows in expected.items():
                self.assertEqual(db.execute("SELECT * FROM " + name + " ORDER BY 1").fetchall(), rows)
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchall(), [("ok",)])
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
        for client in (Store, legacy_store()):
            with self.assertRaises(TaskAlongError) as failure:
                client(restored)
            self.assertEqual(failure.exception.code, "unsupported_store_application")
        with self.assertRaises(TaskAlongError):restore_backup(backup, self.state, expected_digest=manifest["digest"])
        with self.assertRaises(TaskAlongError):restore_backup(backup, restored, expected_digest=manifest["digest"])

    def test_complete_backup_includes_uncheckpointed_committed_wal(self):
        code = "from taskalong.store import Store;import os,sys;s=Store(sys.argv[1]);s.set_setting('wal-only',{'retained':True});os._exit(0)"
        subprocess.run([sys.executable, "-c", code, str(self.state)], check=True, timeout=10)
        self.assertTrue(Path(str(self.state / "state.sqlite3") + "-wal").is_file())
        with Store.maintenance(self.state) as store:
            manifest = store.backup(self.root / "wal-backup", complete=True)
        with sqlite3.connect(self.root / "wal-backup/state.sqlite3") as db:
            value = db.execute("SELECT document FROM settings WHERE name='wal-only'").fetchone()[0]
            self.assertEqual(json.loads(value), {"retained":True})
        self.assertTrue(manifest["database"]["tables"]["settings"]["rows"])

    def test_numbered_upgrade_is_additive_restored_and_idempotent(self):
        profile = example_profile()
        with Store(self.state) as store:
            store.register_profile(profile)
            original = {name:[tuple(row) for row in store.db.execute("SELECT * FROM " + name + " ORDER BY 1")]
                        for name in ("profiles","runs","events","task_specs","blobs")}
        arguments = {"operation_key":"upgrade-once", "backup_dir":self.root / "before-upgrade", "restore_dir":self.root / "restore-proof"}
        with Store.maintenance(self.state) as store:
            receipt = store.upgrade(**arguments)
            self.assertEqual(store.db.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertEqual(store.db.execute("SELECT value FROM metadata WHERE key='format_version'").fetchone()[0], "2")
            self.assertEqual(store.upgrade(**arguments), receipt)
            with self.assertRaises(TaskAlongError) as conflict:
                store.upgrade(**(arguments | {"restore_dir":self.root / "other-restore"}))
            self.assertEqual(conflict.exception.code, "operation_key_conflict")
            for name, rows in original.items():
                self.assertEqual([tuple(row) for row in store.db.execute("SELECT * FROM " + name + " ORDER BY 1")], rows)
            historical = store.db.execute("SELECT document FROM document_history WHERE kind='runtime_profile'").fetchone()[0]
            self.assertEqual(historical, original["profiles"][0][2])
            self.assertEqual(store.db.execute("SELECT count(*) FROM store_migrations").fetchone()[0], 1)
            self.assertTrue((arguments["restore_dir"] / "restore-receipt.json").is_file())
        with Store(self.state) as reopened:
            self.assertEqual(reopened.store_uuid, self.store_uuid)
            self.assertEqual(reopened.db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(reopened.db.execute("PRAGMA foreign_key_check").fetchall(), [])
        before = (self.state / "state.sqlite3").read_bytes()
        with self.assertRaises(TaskAlongError) as old:
            legacy_store()(self.state)
        self.assertEqual(old.exception.code, "unsupported_store_version")
        self.assertEqual((self.state / "state.sqlite3").read_bytes(), before)

    def test_versioned_history_is_exact_immutable_and_never_current_authority(self):
        from taskalong.bindings import ProviderProfile
        from taskalong.qualification import QualificationDecision
        from taskalong.validation import seal_versioned
        resource = resources.files("taskalong.resources")
        first = ProviderProfile(resource.joinpath("examples/v2/provider-profile.json").read_bytes())
        second = ProviderProfile.from_dict(seal_versioned("provider-profile", first.to_dict() | {"revision":2}, version="2.0"))
        decision = QualificationDecision(resource.joinpath("examples/v2.1/qualification-decision.json").read_bytes())
        with Store(self.state) as old:
            with self.assertRaises(TaskAlongError) as failure:
                old.record_document(first, operation_key="before-upgrade")
            self.assertEqual(failure.exception.code, "store_upgrade_required")
        with Store.maintenance(self.state) as maintenance:
            maintenance.upgrade(operation_key="upgrade", backup_dir=self.root / "backup", restore_dir=self.root / "restore")
        with Store(self.state) as store:
            receipt = store.record_document(first, operation_key="profile-one")
            self.assertTrue(receipt["historical_only"])
            self.assertEqual(store.record_document(first, operation_key="profile-one"), receipt)
            with self.assertRaises(TaskAlongError) as conflict:
                store.record_document(second, operation_key="profile-one")
            self.assertEqual(conflict.exception.code, "operation_key_conflict")
            store.record_document(second, operation_key="profile-two")
            history = store.document_history("provider_profile", first.to_dict()["profile_id"])
            self.assertEqual({entry.to_bytes() for entry in history}, {first.to_bytes(), second.to_bytes()})
            self.assertTrue(store.record_document(decision, operation_key="decision")["historical_only"])
            self.assertFalse(decision.to_dict()["production_dispatch_allowed"])
            for table in ("document_history", "store_migrations"):
                for statement in ("DELETE FROM " + table, "UPDATE " + table + " SET document='{}'"):
                    with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError):
                        store.db.execute(statement)

    def test_missing_changed_and_symlinked_blobs_preserve_failed_backup(self):
        path = self.state / "blobs" / self.blob["sha256"]
        original = path.read_bytes()
        for mode in ("missing", "changed", "symlink"):
            path.unlink()
            if mode == "changed":
                path.write_bytes(b"changed capture")
                path.chmod(0o600)
            elif mode == "symlink":
                external = self.root / "external"
                external.write_bytes(b"must remain untouched")
                path.symlink_to(external)
            target = self.root / ("backup-" + mode)
            with Store.maintenance(self.state) as store:
                with self.subTest(mode=mode), self.assertRaises(TaskAlongError):
                    store.backup(target, complete=True)
                self.assertEqual(store.db.execute("PRAGMA user_version").fetchone()[0], 1)
                self.assertTrue(target.is_dir())
                self.assertFalse((target / "backup-manifest.json").exists())
            if path.exists() or path.is_symlink():path.unlink()
            path.write_bytes(original)
            path.chmod(0o600)
        self.assertEqual((self.root / "external").read_bytes(), b"must remain untouched")

    def test_backup_tamper_missing_and_symlink_refuse_restore_before_destination(self):
        from taskalong.maintenance import restore_backup
        for mode in ("changed", "missing", "symlink", "manifest"):
            backup = self.root / ("backup-" + mode)
            with Store.maintenance(self.state) as store:
                manifest = store.backup(backup, complete=True)
            blob = backup / "blobs" / self.blob["sha256"]
            if mode == "changed":blob.write_bytes(b"changed")
            elif mode == "missing":blob.unlink()
            elif mode == "symlink":
                blob.unlink()
                blob.symlink_to(self.state / "blobs" / self.blob["sha256"])
            else:(backup / "backup-manifest.json").write_bytes(b"{}")
            target = self.root / ("restore-" + mode)
            with self.subTest(mode=mode), self.assertRaises(TaskAlongError):
                restore_backup(backup, target, expected_digest=manifest["digest"])
            self.assertFalse(target.exists())

    def test_disk_full_during_backup_and_restore_retains_partial_artifacts(self):
        from taskalong.maintenance import restore_backup
        backup = self.root / "backup-full"
        with Store.maintenance(self.state) as store:
            with patch("taskalong.maintenance.os.fsync", side_effect=OSError(errno.ENOSPC,"synthetic full device")):
                with self.assertRaises(TaskAlongError) as failure:
                    store.backup(backup, complete=True)
            self.assertEqual(failure.exception.code, "backup_io")
            self.assertTrue(backup.is_dir())
            self.assertFalse((backup / "backup-manifest.json").exists())
            manifest = store.backup(self.root / "complete", complete=True)
        restored = self.root / "restore-full"
        with patch("taskalong.maintenance.os.fsync", side_effect=OSError(errno.ENOSPC,"synthetic full device")):
            with self.assertRaises(TaskAlongError) as failure:
                restore_backup(self.root / "complete", restored, expected_digest=manifest["digest"])
        self.assertEqual(failure.exception.code, "restore_io")
        self.assertFalse(restored.exists())
        self.assertEqual(len(list(self.root.glob(".restore-full-restore-*"))), 1)
        with Store(self.state) as store:
            self.assertEqual(store.get_blob(self.blob["sha256"]), b"synthetic retained evidence")

    def test_failed_ddl_rolls_back_all_schema_markers_and_retries_same_intent(self):
        arguments = {"operation_key":"upgrade", "backup_dir":self.root / "backup", "restore_dir":self.root / "restore"}
        with Store.maintenance(self.state) as store:
            def deny(action, first, second, database, trigger):
                return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_INSERT and first == "store_migrations" else sqlite3.SQLITE_OK
            store.db.set_authorizer(deny)
            try:
                with self.assertRaises(TaskAlongError) as failure:store.upgrade(**arguments)
                self.assertEqual(failure.exception.code, "store_upgrade_failed")
            finally:store.db.set_authorizer(None)
            self.assertEqual(store.db.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertEqual(store.db.execute("SELECT value FROM metadata WHERE key='format_version'").fetchone()[0], "1")
            self.assertIsNone(store.db.execute("SELECT name FROM sqlite_master WHERE name='document_history'").fetchone())
            self.assertEqual(json.loads(store.db.execute("SELECT response FROM operations WHERE command='maintenance.upgrade'").fetchone()[0]), {"phase":"prepared"})
            receipt = store.upgrade(**arguments)
            self.assertEqual(receipt["to_version"], 2)

    def test_format_markers_and_altered_history_schema_are_rejected_unchanged(self):
        for version, marker in ((2,"1"),(1,"2"),(2,"2")):
            state = self.root / ("markers-" + str(version) + marker)
            with Store(state) as store:
                store.db.execute("UPDATE metadata SET value=? WHERE key='format_version'", (marker,))
                store.db.execute("PRAGMA user_version=" + str(version))
            before = (state / "state.sqlite3").read_bytes()
            with self.subTest(version=version,marker=marker), self.assertRaises(TaskAlongError):Store(state)
            self.assertEqual((state / "state.sqlite3").read_bytes(), before)
        with Store.maintenance(self.state) as store:
            store.upgrade(operation_key="upgrade", backup_dir=self.root / "backup", restore_dir=self.root / "restore")
            store.db.execute("DROP TRIGGER immutable_document_history_delete")
            store.db.execute("CREATE TRIGGER immutable_document_history_delete BEFORE DELETE ON document_history BEGIN SELECT 1; END")
        before = (self.state / "state.sqlite3").read_bytes()
        with self.assertRaises(TaskAlongError) as failure:Store(self.state)
        self.assertEqual(failure.exception.code, "store_integrity")
        self.assertEqual((self.state / "state.sqlite3").read_bytes(), before)

    def kill_at_barrier(self, program, *arguments):
        reader, writer = os.pipe()
        process = subprocess.Popen([sys.executable, "-c", program, *map(str,arguments), str(writer)],
            pass_fds=(writer,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.close(writer)
        try:
            ready, _, _ = select.select([reader], [], [], 15)
            if not ready or os.read(reader,1) != b"R":
                process.kill()
                _, error = process.communicate(timeout=5)
                self.fail("Synthetic barrier not reached: " + error.decode(errors="replace")[-1000:])
            process.send_signal(signal.SIGKILL)
            process.communicate(timeout=5)
            self.assertEqual(process.returncode, -signal.SIGKILL)
        finally:
            os.close(reader)
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)

    def test_real_process_crash_during_ddl_or_after_commit_has_one_format(self):
        for position in ("during-ddl", "after-commit"):
            state = self.root / position
            with Store(state):pass
            program = r'''
import os,signal,sys
from pathlib import Path
from taskalong.store import Store
root,position,fd = sys.argv[1:];root=Path(root);fd=int(fd)
with Store.maintenance(root) as store:
    def barrier(statement):
        if position=='during-ddl' and statement.startswith('INSERT INTO store_migrations'):
            os.write(fd,b'R');signal.pause()
    store.db.set_trace_callback(barrier)
    store.upgrade(operation_key='upgrade',backup_dir=root.parent/(position+'-backup'),restore_dir=root.parent/(position+'-restore'))
    os.write(fd,b'R');signal.pause()
'''
            self.kill_at_barrier(program, state, position)
            with Store(state) as reopened:
                self.assertEqual(reopened.format_version, 1 if position == "during-ddl" else 2)
                self.assertEqual(reopened.db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            with Store.maintenance(state) as store:
                receipt = store.upgrade(operation_key="upgrade",backup_dir=self.root/(position+"-backup"),restore_dir=self.root/(position+"-restore"))
                self.assertEqual(receipt["to_version"],2)

    def test_process_crash_during_backup_or_restore_preserves_prior_format(self):
        for position in ("backup", "restore"):
            state = self.root / position
            with Store(state) as store:store.put_blob(b"retained capture")
            program = r'''
import os,signal,sys
from pathlib import Path
from taskalong.store import Store
import taskalong.maintenance as maintenance
root,position,fd=sys.argv[1:];root=Path(root);fd=int(fd)
def stop():os.write(fd,b'R');signal.pause()
if position=='backup':
    original=maintenance._file
    def capture(path,destination=None):
        result=original(path,destination)
        if destination is not None and path.parent.name=='blobs':stop()
        return result
    maintenance._file=capture
else:
    original=maintenance._write
    def receipt(path,data):
        if path.name=='restore-receipt.json':stop()
        return original(path,data)
    maintenance._write=receipt
with Store.maintenance(root) as store:
    store.upgrade(operation_key='upgrade',backup_dir=root.parent/(position+'-backup'),restore_dir=root.parent/(position+'-restore'))
'''
            self.kill_at_barrier(program,state,position)
            with Store(state) as store:
                self.assertEqual(store.format_version,1)
                self.assertEqual(store.db.execute("PRAGMA integrity_check").fetchone()[0],"ok")
            backup = self.root/(position+"-backup")
            self.assertTrue(backup.exists())
            if position == "backup":self.assertFalse((backup/"backup-manifest.json").exists())
            else:
                restored = self.root/(position+"-restore")
                self.assertFalse(restored.exists())
                stages = list(self.root.glob("."+restored.name+"-restore-*"))
                self.assertEqual(len(stages),1)
                for client in (Store,legacy_store()):
                    with self.assertRaises(TaskAlongError):client(stages[0])

    def test_early_restore_failure_never_exposes_initializable_payload(self):
        from taskalong import maintenance
        with Store.maintenance(self.state) as store:
            manifest = store.backup(self.root / "backup", complete=True)
        original = maintenance._file
        target = self.root / "early-restore"
        def fail_after_copy(path, destination=None):
            result = original(path, destination)
            if destination is not None and path.parent.name == "blobs":
                raise OSError(errno.ENOSPC, "synthetic early copy failure")
            return result
        with patch.object(maintenance, "_file", side_effect=fail_after_copy):
            with self.assertRaises(TaskAlongError) as failure:
                maintenance.restore_backup(self.root / "backup", target, expected_digest=manifest["digest"])
        self.assertEqual(failure.exception.code,"restore_io")
        self.assertFalse(target.exists())
        stages = list(self.root.glob(".early-restore-restore-*"))
        self.assertEqual(len(stages),1)
        self.assertTrue((stages[0]/"blobs"/self.blob["sha256"]).is_file())
        for client in (Store,legacy_store()):
            with self.assertRaises(TaskAlongError) as refused:client(stages[0])
            self.assertEqual(refused.exception.code,"unsupported_store_application")

    def test_restore_directories_are_bound_to_trusted_backup_not_self_signed_receipt(self):
        from taskalong.maintenance import restore_backup, verify_restored
        from taskalong.validation import digest, canonical_bytes
        empty = self.state / "empty-private-control"
        empty.mkdir(mode=0o700)
        with Store.maintenance(self.state) as store:
            manifest = store.backup(self.root / "backup", complete=True)
        for change in ("removed", "mode"):
            target = self.root / change
            receipt = restore_backup(self.root / "backup", target, expected_digest=manifest["digest"])
            if change == "removed":
                (target/empty.name).rmdir()
                receipt["directories"] = [item for item in receipt["directories"] if item["path"] != empty.name]
            else:
                (target/empty.name).chmod(0o500)
                next(item for item in receipt["directories"] if item["path"] == empty.name)["mode"] = 0o500
            receipt["digest"] = digest(receipt)
            (target/"restore-receipt.json").write_bytes(canonical_bytes(receipt))
            with self.subTest(change=change):
                with self.assertRaises(TaskAlongError) as failure:
                    verify_restored(self.root / "backup", target, expected_digest=manifest["digest"])
                self.assertEqual(failure.exception.code,"restore_integrity")
            if change == "mode":(target/empty.name).chmod(0o700)

    def test_atomic_restore_publication_preserves_racing_directory_and_refuses_missing_primitive(self):
        from taskalong import maintenance
        with Store.maintenance(self.state) as store:
            manifest = store.backup(self.root / "backup", complete=True)
        original = maintenance._publish_restore
        for occupied in (False,True):
            target = self.root / ("racing-"+str(occupied))
            def race(stage, destination):
                destination.mkdir(mode=0o700)
                if occupied:(destination/"later-state").write_bytes(b"must survive")
                return original(stage, destination)
            with patch.object(maintenance,"_publish_restore",side_effect=race):
                with self.assertRaises(TaskAlongError) as failure:
                    maintenance.restore_backup(self.root/"backup",target,expected_digest=manifest["digest"])
            self.assertEqual(failure.exception.code,"restore_exists")
            self.assertEqual(sorted(item.name for item in target.iterdir()),["later-state"] if occupied else [])
            if occupied:self.assertEqual((target/"later-state").read_bytes(),b"must survive")
        target = self.root/"unsupported"
        with patch.object(maintenance.ctypes,"CDLL",return_value=object()):
            with self.assertRaises(TaskAlongError) as failure:
                maintenance.restore_backup(self.root/"backup",target,expected_digest=manifest["digest"])
        self.assertEqual(failure.exception.code,"restore_publication_unsupported")
        self.assertFalse(target.exists())

    def test_sigkill_early_restore_and_after_publication_preserve_quarantine(self):
        from taskalong.maintenance import verify_restored
        with Store.maintenance(self.state) as store:
            manifest = store.backup(self.root / "backup", complete=True)
        program = r'''
import os,signal,sys
from pathlib import Path
import taskalong.maintenance as maintenance
source,target,identity,position,fd=sys.argv[1:];fd=int(fd)
def stop():os.write(fd,b'R');signal.pause()
if position=='early':
    original=maintenance._file
    def copy(path,destination=None):
        result=original(path,destination)
        if destination is not None and path.parent.name=='blobs':stop()
        return result
    maintenance._file=copy
else:
    original=maintenance._publish_restore
    def publish(stage,target):
        original(stage,target);stop()
    maintenance._publish_restore=publish
maintenance.restore_backup(source,target,expected_digest=identity)
'''
        for position in ("early","published"):
            target=self.root/position
            self.kill_at_barrier(program,self.root/"backup",target,manifest["digest"],position)
            if position == "early":
                self.assertFalse(target.exists())
                stages=list(self.root.glob(".early-restore-*"))
                self.assertEqual(len(stages),1)
                inspected=stages[0]
                self.assertTrue((inspected/"blobs"/self.blob["sha256"]).is_file())
            else:
                inspected=target
                self.assertTrue(verify_restored(self.root/"backup",target,expected_digest=manifest["digest"])["quarantined"])
            for client in (Store,legacy_store()):
                with self.assertRaises(TaskAlongError) as failure:client(inspected)
                self.assertEqual(failure.exception.code,"unsupported_store_application")

    def test_concurrent_public_facade_cannot_open_during_maintenance(self):
        program = "from taskalong.api import RunService;from taskalong.errors import TaskAlongError;import sys\ntry:RunService(sys.argv[1])\nexcept TaskAlongError as e:print(e.code)"
        with Store.maintenance(self.state):
            result = subprocess.run([sys.executable,"-c",program,str(self.state)],capture_output=True,text=True,check=True,timeout=10)
        self.assertEqual(result.stdout.strip(),"maintenance_busy")

    def test_control_instructions_are_backed_up_as_private_data(self):
        control = self.state / ".codex"
        control.mkdir(mode=0o700)
        path = control / "AGENTS.md"
        path.write_bytes(b"Original synthetic private instruction capture; never authority.")
        path.chmod(0o600)
        with Store.maintenance(self.state) as store:
            manifest = store.backup(self.root / "backup",complete=True)
        self.assertIn(".codex/AGENTS.md",{item["path"] for item in manifest["files"]})

    def test_observed_unknown_or_inconsistent_effect_is_not_quiescence_proof(self):
        for kind, document_kind in (("unknown.dispatch","unknown.dispatch"),("executor.start","workspace.create")):
            with Store(self.state) as store:
                document={"effect_id":"effect", "run_id":self.run["run_id"], "kind":document_kind, "phase":"observed", "response":{"termination_confirmed":True}}
                store.db.execute("INSERT INTO effects VALUES(?,?,?,?,?,?,?)",("effect",self.run["run_id"],"once",kind,"a"*64,"observed",json.dumps(document)))
            try:
                with self.subTest(kind=kind), self.assertRaises(TaskAlongError):
                    with Store.maintenance(self.state):pass
            finally:
                with Store(self.state) as store:store.db.execute("DELETE FROM effects")

    def test_backup_freshness_refuses_new_source_state_without_rewinding_it(self):
        arguments={"operation_key":"upgrade","backup_dir":self.root/"backup","restore_dir":self.root/"restore"}
        with Store.maintenance(self.state) as store:
            store.db.set_authorizer(lambda action,first,second,database,trigger:
                sqlite3.SQLITE_DENY if action==sqlite3.SQLITE_INSERT and first=="store_migrations" else sqlite3.SQLITE_OK)
            with self.assertRaises(TaskAlongError):store.upgrade(**arguments)
            store.db.set_authorizer(None)
            store.set_setting("later-change",{"must_remain":True})
            with self.assertRaises(TaskAlongError) as failure:store.upgrade(**arguments)
            self.assertEqual(failure.exception.code,"backup_stale")
            self.assertEqual(store.setting("later-change"),{"must_remain":True})
            self.assertEqual(store.format_version,1)

    def test_malformed_effect_response_refuses_maintenance_with_typed_integrity_error(self):
        for response in ("wrong-shape", 42, True, [], ["unexpected"]):
            with self.subTest(response=response):
                with Store(self.state) as store:
                    document={"effect_id":"effect", "run_id":self.run["run_id"], "kind":"executor.start", "phase":"observed", "response":response}
                    store.db.execute("INSERT INTO effects VALUES(?,?,?,?,?,?,?)",("effect",self.run["run_id"],"once","executor.start","a"*64,"observed",json.dumps(document)))
                try:
                    with self.assertRaises(TaskAlongError) as failure:
                        with Store.maintenance(self.state):pass
                    self.assertEqual(failure.exception.code,"store_integrity")
                    with Store(self.state) as store:
                        self.assertEqual(store.format_version,1)
                        self.assertEqual(store.db.execute("SELECT document FROM effects").fetchone()[0],json.dumps(document))
                        self.assertEqual(store.db.execute("SELECT count(*) FROM operations WHERE command='maintenance.upgrade'").fetchone()[0],0)
                finally:
                    with Store(self.state) as store:store.db.execute("DELETE FROM effects")

    def test_exact_predecessor_opens_before_after_and_prevents_maintenance_while_active(self):
        fixture=Path(__file__).parent/'fixtures/legacy_store_v1.py'
        self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(),
                         '356f4286ed1113d6d528093c208adb641dcb0c0dc5a3c8e8072cf75da5eeca55')
        # The pinned predecessor's first protected file read is PRAGMA user_version.
        # This full-client proof complements the independent real lock witnesses;
        # it makes no claim about its default busy-handler wall-time latency.
        program=r'''
import importlib.util,json,os,signal,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('taskalong._legacy_store_v1',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
with module.Store(sys.argv[2]) as store:
    info=(Path(sys.argv[2])/'state.sqlite3').stat()
    result={'nonce':sys.argv[3],'store_uuid':store.store_uuid,
        'format':store.db.execute('PRAGMA user_version').fetchone()[0],
        'identity':{'device':info.st_dev,'inode':info.st_ino}}
    output=json.dumps(result,separators=(',',':'))
    if len(sys.argv)==5:os.write(int(sys.argv[4]),output.encode());signal.pause()
    else:print(output,flush=True)
'''
        identity=database_identity(self.state)
        def check(output,nonce):
            self.assertLess(len(output),4096)
            self.assertEqual(json.loads(output),{'nonce':nonce,'store_uuid':self.store_uuid,'format':1,'identity':identity})
        def once():
            nonce=os.urandom(16).hex()
            result=subprocess.run([sys.executable,'-c',program,str(fixture),str(self.state),nonce],
                close_fds=True,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0)
            self.assertEqual(result.stderr,'')
            check(result.stdout,nonce)
        with Store(self.state) as store:before=logical_fingerprint(store)
        once()
        nonce=os.urandom(16).hex();reader,writer=os.pipe()
        child=subprocess.Popen([sys.executable,'-c',program,str(fixture),str(self.state),nonce,str(writer)],
            close_fds=True,pass_fds=(writer,),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        os.close(writer)
        try:
            self.assertTrue(select.select([reader],[],[],10)[0],'Exact predecessor did not open')
            check(os.read(reader,4096).decode(),nonce)
            self.assertIsNone(child.poll())
            with self.assertRaises(TaskAlongError) as failure:
                with Store.maintenance(self.state):pass
            self.assertEqual(failure.exception.code,'maintenance_exclusivity_unproven')
            self.assertIsNone(child.poll(),'A dead predecessor is not active-client refusal proof')
        finally:
            os.close(reader)
            if child.poll() is None:child.kill()
            child.communicate(timeout=5)
        self.assertEqual(child.returncode,-signal.SIGKILL)
        once()
        with Store(self.state) as store:self.assertEqual(logical_fingerprint(store),before)
        print(json.dumps({'kind':'maintenance_exact_predecessor_compatibility',
            'fixture_sha256':hashlib.sha256(fixture.read_bytes()).hexdigest(),'format':1,
            'store_uuid':self.store_uuid,'identity':identity,'opened_before':True,'opened_after':True,
            'active_client_refusal':'maintenance_exclusivity_unproven','active_during_refusal':True,
            'parent_observed_reaped':True,'logical_state_unchanged':True,
            'legacy_contended_constructor_latency_qualified':False}),file=sys.stderr,flush=True)


class UpgradedStoreJourneyTests(ServiceFixture, unittest.TestCase):
    def test_existing_synthetic_lifecycle_operates_on_upgraded_store_and_backups(self):
        self.service.close()
        try:
            with Store.maintenance(self.state) as store:
                store.upgrade(operation_key="upgrade",backup_dir=self.root/"backup",restore_dir=self.root/"restore")
        finally:self.service=RunService(self.state)
        run,_=self.submit()
        self.start(run)
        finished=self.wait(run["run_id"])
        self.assertEqual(finished["state"],"blocked")
        self.assertIn("required_review_missing",{item["code"] for item in finished["blockers"]})
        self.assertEqual(len(self.invocations()),1)
        self.service.close()
        try:
            with Store.maintenance(self.state) as store:
                manifest=store.backup(self.root/"after-lifecycle",complete=True)
            self.assertIn("attempts",{item["path"] for item in manifest["directories"]})
        finally:self.service=RunService(self.state)


if __name__ == "__main__":
    unittest.main()
