"""One bounded diagnostic campaign, never a replacement qualification gate."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
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


def bounded_collect(process, timeout):
    """The caller alone owns drain/reap. No exception text leaves this seam."""
    result={'status':'completed','cleanup_confirmed':False}
    out=err=b''
    try:
        try:out,err=process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            result['status']='tool_timeout'
            process.kill()
            try:out,err=process.communicate(timeout=2)
            except subprocess.TimeoutExpired:result['status']='cleanup_drain_timeout'
    except OSError as exc:result.update(status='tool_io_error',errno=exc.errno)
    except Exception:result['status']='tool_diagnostic_error'
    finally:
        try:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
            result['cleanup_confirmed']=process.poll() is not None
        except subprocess.TimeoutExpired:result['cleanup_status']='wait_timeout'
        except OSError as exc:result.update(cleanup_status='io_error',cleanup_errno=exc.errno)
        except Exception:result['cleanup_status']='diagnostic_error'
        for stream in (process.stdout,process.stderr):
            if stream is not None:
                try:stream.close()
                except OSError as exc:result.update(pipe_close_errno=exc.errno)
                except Exception:result['pipe_close_status']='diagnostic_error'
    result['exit']=process.returncode
    return result,out or b'',err or b''


def check_sample_tool(path,popen):
    result={'available':path.is_file() and os.access(path,os.X_OK),'supported_invocation':False}
    if not result['available']:return result
    try:
        process=popen([str(path),'-h'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        state,out,err=bounded_collect(process,5)
        result.update(state)
        if state['status']=='completed' and state['cleanup_confirmed']:
            text=(out+err).decode('utf-8','replace')
            result['supported_invocation']=all(n in text for n in ('samplingInterval','-mayDie','-file'))
    except OSError as exc:result.update(status='help_unavailable',errno=exc.errno)
    except Exception:result['status']='help_diagnostic_error'
    return result


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
    sample_path=Path('/usr/bin/sample')
    sample_check=check_sample_tool(sample_path,original_popen)
    event('native_tool_check',**sample_check)
    native_records=[]
    native_sessions=[]
    class NativeSample:
        def __init__(self,child):
            self.child=child
            self.cancelled=threading.Event()
            self.process=None
            self.record={'scheduled':time.monotonic(),'delay_seconds':4,'duration_seconds':2,'interval_ms':10}
            self.path=self.timer=None
            native_sessions.append(self)
            try:
                descriptor,name=tempfile.mkstemp(prefix='sqlite-owned-native-',suffix='.txt')
                os.close(descriptor)
                self.path=Path(name)
                self.timer=threading.Timer(4,self.capture)
                self.timer.daemon=True
                self.timer.start()
            except OSError as exc:
                self.timer=None
                self.record.update(status='sampler_setup_error',errno=exc.errno,cleanup_confirmed=True)
            except Exception:
                self.timer=None
                self.record.update(status='sampler_setup_error',cleanup_confirmed=True)
        def capture(self):
            try:
                if self.cancelled.is_set() or self.child.poll() is not None:
                    self.record.update(status='target_exited_or_cancelled',cleanup_confirmed=True);return
                self.record['launch']=time.monotonic()
                self.process=original_popen([str(sample_path),str(self.child.pid),'2','10','-mayDie','-file',str(self.path)],
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                if self.cancelled.is_set():self.process.kill()
                state,out,err=bounded_collect(self.process,5)
                self.record.update(state)
                self.record.update(finish=time.monotonic(),
                    tool_output_sha256=hashlib.sha256(out+err).hexdigest())
                tool_text=(out+err).decode('utf-8','replace').lower()
                self.record['tool_error_tokens']=[token for token in (
                    'operation not permitted','permission denied','task_for_pid',
                    'could not examine','cannot examine','no such process','invalid argument',
                    'not supported') if token in tool_text]
                if state['status']=='completed':
                    self.record['status']='captured' if self.process.returncode==0 else 'attach_failed'
            except OSError as exc:
                self.record.update(status='launch_failed',errno=exc.errno,finish=time.monotonic(),cleanup_confirmed=self.process is None)
                if self.process is not None:
                    state,_,_=bounded_collect(self.process,2);self.record.update(state)
            except Exception:
                self.record.update(status='sampler_diagnostic_error',cleanup_confirmed=self.process is None)
                if self.process is not None:
                    state,_,_=bounded_collect(self.process,2);self.record.update(state)
        def finish(self):
            try:return self._finish()
            except Exception:
                # Finalization is diagnostic: never replace an original test failure.
                self.cancelled.set()
                try:
                    if self.process is not None:self.process.kill()
                    if self.timer is not None:
                        self.timer.cancel();self.timer.join(timeout=2)
                except Exception:pass
                return {'status':'sampler_finalization_error','cleanup_confirmed':False,
                        'raw_report_uploaded':False}
        def _finish(self):
            self.cancelled.set()
            if self.timer is not None:
                self.timer.cancel();self.timer.join(timeout=8)
                if self.timer.is_alive():
                    # Only request cancellation: capture retains sole pipe/reap ownership.
                    if self.process is not None:
                        try:self.process.kill()
                        except OSError:pass
                    self.timer.join(timeout=2)
                    if self.timer.is_alive():
                        return {'status':'sampler_cleanup_incomplete','cleanup_confirmed':False,
                                'raw_report_uploaded':False}
            self.record.setdefault('status','cancelled_before_launch')
            if self.path is None:return dict(self.record)
            try:
                with self.path.open('rb') as stream:data=stream.read(4*1024*1024+1)
            except OSError as exc:return {**self.record,'status':'report_unavailable','report_errno':exc.errno}
            if len(data)>4*1024*1024:
                self.record['report']='over_bound';return self.record
            self.record['raw_report_sha256']=hashlib.sha256(data).hexdigest()
            # Raw samples include paths/command lines: never print or upload them.
            # The allowlist deliberately omits unknown symbols and metadata.
            functions={'sqlite3_prepare_v2','sqlite3_step','sqlite3LockAndPrepare','sqlite3Prepare',
                'sqlite3BtreeBeginTrans','sqlite3PagerSharedLock','sqlite3OsSleep','sqlite3_sleep',
                'sqliteDefaultBusyCallback','sqlite3InvokeBusyHandler','unixSleep','unixLock',
                'unixFileControl','fcntl','__fcntl','usleep','nanosleep','__semwait_signal',
                'pthread_mutex_lock','__psynch_mutexwait','__psynch_cvwait'}
            modules={'Python','libsqlite3.dylib','libsqlite3.0.dylib','libsystem_c.dylib',
                'libsystem_kernel.dylib','libsystem_pthread.dylib','_sqlite3.cpython-313-darwin.so'}
            selected=[]
            for line in data.decode('utf-8','replace').splitlines():
                match=re.fullmatch(r'[ |+!:]*([0-9]+)\s+([A-Za-z_][A-Za-z_0-9]*) \(in ([A-Za-z_0-9.\-]+)\).*',line)
                if match and match[2] in functions and match[3] in modules:
                    selected.append({'count':int(match[1]),'function':match[2],'module':match[3]})
            self.record['allowlisted_frames']=selected[:32]
            self.record['raw_report_uploaded']=False
            self.record['raw_report_retained_after_runner']=False
            self.record['observer_effects']='Tool briefly suspends/resumes target; no timing subtraction.'
            return self.record
    original_communicate=TracedPopen.communicate
    def sampled_communicate(child,*a,**kw):
        if child.probe and not hasattr(child,'native_sample'):
            # Called only after the unchanged readiness assertion. Do not delay
            # or replace original communicate(timeout=10) with sampler work.
            child.native_sample=NativeSample(child)
        return original_communicate(child,*a,**kw)
    TracedPopen.communicate=sampled_communicate
    trials=[]
    for kind,name in [('unchanged-control',original_method.__name__),
                      ('instrumented-full-native',original_method.__name__)]:
        if kind!='unchanged-control' and not sample_check['supported_invocation']:
            event('sampling_stopped',reason='tool_unavailable_or_unsupported')
            trials.append({'trial':kind,'passed':False,'tests':0,'status':'not_run'});break
        event('trial_entry',trial=kind)
        output=io.StringIO()
        runner=unittest.TextTestRunner(stream=output,verbosity=2)
        suite=unittest.TestSuite([tests.StoreMigrationTests(name)])
        if kind=='unchanged-control':result=runner.run(suite)
        else:
            try:
                with patch.object(tests.subprocess,'Popen',TracedPopen),patch.object(tests.Store,'_exclusive_database',exclusive):
                    result=runner.run(suite)
            finally:
                # Even a failed original child kill/reap must finalize the sampler.
                for session in native_sessions:
                    report=session.finish();native_records.append(report)
                    event('native_sample',**report)
        event('trial_result',trial=kind,passed=result.wasSuccessful(),report=output.getvalue())
        trials.append({'trial':kind,'passed':result.wasSuccessful(),'tests':result.testsRun})
    event('diagnostic_summary',source_head=HEAD,wheel_sha256=hashlib.sha256(wheel.read_bytes()).hexdigest(),
          predecessor_sha256=PIN,source_import=False,package_files_verified=len(payloads),trials=trials,
          native_samples=native_records,native_evidence_usable=len(native_records)==1 and
              native_records[0].get('status')=='captured' and native_records[0].get('cleanup_confirmed') is True
              and bool(native_records[0].get('allowlisted_frames')),
          qualification=False,failed_PR_gate_resolved=False)
    return 0 if all(row['passed'] for row in trials) else 1


if __name__=='__main__':raise SystemExit(main())
