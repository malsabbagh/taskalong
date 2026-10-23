"""One bounded diagnostic campaign, never a replacement qualification gate."""
import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
import zipfile

HEAD = '91042f14a5b47a1f739fe39ed7f20cd26f7918da'
PIN = '356f4286ed1113d6d528093c208adb641dcb0c0dc5a3c8e8072cf75da5eeca55'
PRELUDE = r'''
import json
with sqlite3.connect(':memory:') as diagnostic_info:
    print(json.dumps({'phase':'build','python':sys.version,'sqlite':sqlite3.sqlite_version,
      'source_id':diagnostic_info.execute('SELECT sqlite_source_id()').fetchone()[0],
      'compile_options':[r[0] for r in diagnostic_info.execute('PRAGMA compile_options')]}),file=sys.stderr,flush=True)
diagnostic_count=0
def diagnostic_profile(frame,event,arg):
    global diagnostic_count
    if event not in ('c_call','c_return','c_exception'):return
    name=getattr(arg,'__name__','')
    if name not in ('connect','execute','fetchone'):return
    if diagnostic_count>=32:return
    diagnostic_count+=1
    print(json.dumps({'phase':event,'function':name,'line':frame.f_lineno,
      'frame':os.path.basename(frame.f_code.co_filename),'monotonic':time.monotonic(),
      'cpu':time.process_time()}),file=sys.stderr,flush=True)
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--wheel', type=Path, required=True)
    args = parser.parse_args()
    source, work, wheel = (p.resolve() for p in (args.source, args.work, args.wheel))
    assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()==HEAD
    os.chdir(work)
    sys.path.insert(0, str(work/'installed-tests'))
    import taskalong
    import test_store_migration as tests
    package = Path(taskalong.__file__).resolve().parent
    assert package.is_relative_to(Path(sys.prefix).resolve()) and not package.is_relative_to(source)
    with zipfile.ZipFile(wheel) as archive:
        payloads=[n for n in archive.namelist() if n.startswith('taskalong/') and not n.endswith('/')]
        assert len(payloads)==90
        for name in payloads:
            assert (package.parent/name).read_bytes()==archive.read(name)==(source/'src'/name).read_bytes()
    assert Path(tests.__file__).read_bytes()==(source/'tests/test_store_migration.py').read_bytes()
    fixture=work/'installed-tests/fixtures/legacy_store_v1.py'
    assert fixture.read_bytes()==(source/'tests/fixtures/legacy_store_v1.py').read_bytes()
    assert hashlib.sha256(fixture.read_bytes()).hexdigest()==PIN
    replacements=[(str(source),'$SOURCE'),(str(work),'$WORK'),(str(Path(sys.prefix).resolve()),'$PYTHON_PREFIX'),
                  (os.environ.get('RUNNER_TEMP','__unused_temp__'),'$RUNNER_TEMP'),
                  (os.environ.get('GITHUB_WORKSPACE','__unused_workspace__'),'$WORKSPACE')]
    def safe(value):
        for old,new in replacements:value=value.replace(old,new)
        return re.sub(r'/private/var/folders/[^\s\"\x27]+', '$TEMP',value)
    def event(phase,**fields):
        print(safe(json.dumps({'phase':phase,'monotonic':time.monotonic(),**fields})),flush=True)
    original_method=tests.StoreMigrationTests.test_exact_predecessor_process_prevents_and_is_excluded_by_maintenance
    parsed=ast.parse(Path(tests.__file__).read_text())
    klass=next(n for n in parsed.body if isinstance(n,ast.ClassDef) and n.name=='StoreMigrationTests')
    method=next(n for n in klass.body if isinstance(n,ast.FunctionDef) and n.name==original_method.__name__)
    tree=ast.Module(body=[method],type_ignores=[])
    # Preserve the original setup/pin/program and exact second-direction block.
    block=next(n for n in method.body if isinstance(n,ast.With))
    assert len(method.body[:3])==3 and isinstance(method.body[2],ast.Assign)
    method.body=method.body[:3]+[block]
    method.name='diagnostic_maintenance_first'
    namespace={}
    exec(compile(ast.fix_missing_locations(tree),str(Path(tests.__file__)),'exec'),tests.__dict__,namespace)
    setattr(tests.StoreMigrationTests,method.name,namespace[method.name])
    original_popen=subprocess.Popen
    original_exclusive=tests.Store._exclusive_database
    class TracedPopen(original_popen):
        def __init__(self,argv,*a,**kw):
            argv=list(argv)
            self.probe=len(argv)==7 and argv[1]=='-c' and 'predecessor-probe' in argv[2]
            if self.probe:
                program=argv[2]
                anchor='if len(sys.argv)>4:'
                assert program.count(anchor)==1
                program=program.replace(anchor,PRELUDE+'\n'+anchor)
                program=program.replace('faulthandler.dump_traceback_later(8)',
                  "faulthandler.dump_traceback_later(8)\n    sys.setprofile(diagnostic_profile)")
                argv[2]=program
            super().__init__(argv,*a,**kw)
            event('child_started',pid=self.pid,contended_probe=self.probe)
        def communicate(self,*a,**kw):
            event('communicate_entry',pid=self.pid,timeout=kw.get('timeout'))
            try:out,err=super().communicate(*a,**kw)
            except subprocess.TimeoutExpired:
                event('communicate_deadline',pid=self.pid);raise
            if isinstance(err,bytes):err=err.decode('utf-8','replace')
            event('child_reaped',pid=self.pid,returncode=self.returncode,stderr=(err or '')[-16000:])
            return out,err.encode() if not self.text_mode and err is not None else err
        def kill(self):
            event('owned_child_kill',pid=self.pid)
            return super().kill()
    def exclusive(owner):
        event('exclusive_entry')
        try:result=original_exclusive(owner)
        except BaseException as exc:
            event('exclusive_refused',code=getattr(exc,'code',type(exc).__name__));raise
        event('exclusive_acquired',locking=owner.db.execute('PRAGMA locking_mode').fetchone()[0],
              journal=owner.db.execute('PRAGMA journal_mode').fetchone()[0])
        return result
    trials=[]
    for kind,name in [('unchanged-control',original_method.__name__),
                      ('instrumented-full',original_method.__name__),
                      ('instrumented-maintenance-first',method.name)]:
        event('trial_entry',trial=kind)
        output=io.StringIO()
        runner=unittest.TextTestRunner(stream=output,verbosity=2)
        suite=unittest.TestSuite([tests.StoreMigrationTests(name)])
        if kind=='unchanged-control':result=runner.run(suite)
        else:
            with patch.object(tests.subprocess,'Popen',TracedPopen),patch.object(tests.Store,'_exclusive_database',exclusive):
                result=runner.run(suite)
        event('trial_result',trial=kind,passed=result.wasSuccessful(),report=output.getvalue())
        trials.append({'trial':kind,'passed':result.wasSuccessful(),'tests':result.testsRun})
    event('diagnostic_summary',source_head=HEAD,wheel_sha256=hashlib.sha256(wheel.read_bytes()).hexdigest(),
          predecessor_sha256=PIN,source_import=False,package_files_verified=len(payloads),trials=trials,
          qualification=False,failed_PR_gate_resolved=False)
    return 0 if all(row['passed'] for row in trials) else 1


if __name__=='__main__':raise SystemExit(main())
