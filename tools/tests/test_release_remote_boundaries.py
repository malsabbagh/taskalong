import io,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[2];TOOLS=ROOT/'tools'
for p in (str(ROOT),str(TOOLS)):
    if p not in sys.path: sys.path.insert(0,p)
import tools.release_remote as rr
import release_remote as rr_top
GE=rr.ReleaseGateError;REPO='malsabbagh/taskalong';GH='https://api.github.com/repos/'+REPO
BS=bytes([92]);SHA='a'*40
class Resp:
    def __init__(s,data,status=200): s.data=data;s.pos=0;s.status=status
    def read(s,n=-1):
        n=len(s.data)-s.pos if n<0 else n;c=s.data[s.pos:s.pos+n];s.pos+=len(c);return c
    def close(s): pass
class Op:
    def __init__(s,data=b'{}'): s.data=data;s.reqs=[]
    def open(s,req,timeout=None): s.reqs.append(req);return Resp(s.data)
class GoodProc:
    def __init__(s): s.stdout=io.BytesIO(b'ok');s.stderr=io.BytesIO(b'');s.terminated=0;s.killed=0
    def poll(s): return 0
    def wait(s,timeout=None): return 0
    def terminate(s): s.terminated+=1
    def kill(s): s.killed+=1
class WaitBad:
    def __init__(s,fail=1,tbad=False,kbad=False): s.stdout=io.BytesIO(b'ok');s.stderr=io.BytesIO(b'');s.waits=0;s.terminated=0;s.killed=0;s.fail=fail;s.tbad=tbad;s.kbad=kbad;s.done=False
    def poll(s): return 0 if s.done else None
    def wait(s,timeout=None):
        s.waits+=1
        if s.waits<=s.fail: raise OSError('sekret-wait')
        s.done=True;return 0
    def terminate(s):
        s.terminated+=1
        if s.tbad: raise RuntimeError('sekret-term')
    def kill(s):
        s.killed+=1;s.done=True
        if s.kbad: raise RuntimeError('sekret-kill')
class T(unittest.TestCase):
    def test_surrogates(self):
        self.assertIsNot(rr,rr_top);self.assertTrue(hasattr(rr_top,'read_json'))
        bad=[b'"'+BS+b'ud800"',b'"'+BS+b'udfff"',b'{"' +BS+b'ud800":1}',b'{"a":"x"'+BS+b'ud800"}',b'["'+BS+b'udc00"]']
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.json'
            for data in bad:
                p.write_bytes(data)
                with self.assertRaises(GE): rr.read_json(p)
                with self.assertRaises(rr_top.ReleaseGateError): rr_top.read_json(p)
            p.write_bytes(b'"'+BS+b'ud83d'+BS+b'ude00"');self.assertEqual(rr.read_json(p),chr(0x1f600))
            p.write_bytes(('"'+chr(0x1f600)+chr(0xe9)+'"').encode('utf-8'));self.assertEqual(rr.read_json(p),chr(0x1f600)+chr(0xe9))
        with self.assertRaises(GE): rr.canonical_bytes(chr(0xd800))
        with self.assertRaises(GE): rr.canonical_bytes({chr(0xdfff):1})
        self.assertEqual(rr.canonical_bytes(chr(0x1f600)).decode('utf-8'),chr(34)+chr(0x1f600)+chr(34))
        for data,ok in [(bad[0],False),(b'"'+BS+b'ud83d'+BS+b'ude00"',True)]:
            c=rr.HttpsClient(opener=Op(data))
            if ok: self.assertEqual(c.get_json(GH+'/actions/runs/1'),chr(0x1f600))
            else:
                with self.assertRaises(GE): c.get_json(GH+'/actions/runs/1')
    def test_encoded_url_traversal(self):
        op=Op();c=rr.HttpsClient(github_token='t',opener=op)
        c.get_json('https://registry.npmjs.org/@taskalong%2Fcli/0.1.0-alpha.1')
        c.get_json('https://registry.npmjs.org/@taskalong%2fcli/0.1.0-alpha.1')
        c.get_json(GH+'/actions/runs/1');c.get_bytes('https://registry.npmjs.org/@taskalong/cli/-/cli-0.1.0-alpha.1.tgz',max_bytes=16)
        n=len(op.reqs);self.assertEqual(n,4)
        bad=[GH+'/%2e%2e%2fother-repo/actions/runs/1',GH+'/%2f..%2f..%2fforeign/repo/actions/runs/1',GH+'/actions/%5cruns/1',GH+'/actions/%5Cruns/1',GH+'/%2e%2e/actions/runs/1',GH+'/actions/%2fruns/1',GH+'/actions/runs/1%2f..%2f2','https://registry.npmjs.org/@taskalong%2fcli%2f0.1.0-alpha.1','https://registry.npmjs.org/@taskalong%5ccli/0.1.0-alpha.1','https://registry.npmjs.org/@taskalong/cli/-/%2e%2e%2fcli-0.1.0-alpha.1.tgz','https://pypi.org/pypi/taskalong/%2e%2e%2f0.1.0a1/json']
        for u in bad:
            with self.subTest(u=u):
                with self.assertRaises(GE): c.get_json(u)
                with self.assertRaises(GE): c.get_bytes(u)
        self.assertEqual(len(op.reqs),n)
    def test_git_env_boundary(self):
        cap={};proc=GoodProc()
        def popen(argv,**kw): cap.update(argv=argv,kw=kw);return proc
        rogue={'GIT_DIR':'/tmp/other/.git','GIT_WORK_TREE':'/tmp/other','GIT_COMMON_DIR':'/tmp/c','GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'core.hooksPath','GIT_CONFIG_VALUE_0':'/tmp/x','GIT_CONFIG_PARAMETERS':'x','GIT_OBJECT_DIRECTORY':'/tmp/o','GIT_ALTERNATE_OBJECT_DIRECTORIES':'/tmp/a','GIT_INDEX_FILE':'/tmp/i','GIT_NAMESPACE':'ns','GIT_CEILING_DIRECTORIES':'/','GIT_TRACE':'1','PATH':'/usr/bin','HOME':'/home/x','LANG':'en_US.UTF-8','GNUPGHOME':'/home/x/.gnupg','TMPDIR':'/tmp'}
        with mock.patch.dict(os.environ,rogue,clear=False),mock.patch.object(rr.subprocess,'Popen',popen):
            r=rr.git_read('/some/root','rev-parse','--verify','HEAD')
        self.assertEqual(r.stdout,b'ok');self.assertFalse(cap['kw']['shell']);self.assertIn('env',cap['kw'])
        env=cap['kw']['env'];self.assertFalse(any(k.upper().startswith('GIT_') for k in env))
        for k in rogue:
            if k.startswith('GIT_'): self.assertNotIn(k,env)
        self.assertEqual((env['PATH'],env['HOME'],env['LANG'],env['GNUPGHOME']),('/usr/bin','/home/x','en_US.UTF-8','/home/x/.gnupg'))
        self.assertIn('-C',cap['argv']);self.assertEqual(cap['argv'][cap['argv'].index('-C')+1],'/some/root')
        self.assertIn('--no-pager',cap['argv']);self.assertIn('core.fsmonitor=false',cap['argv']);self.assertIn('core.hooksPath=/dev/null',cap['argv'])
    @unittest.skipUnless(shutil.which('git'),'git absent')
    def test_git_disposable_repo_not_redirected(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);home=base/'home';home.mkdir()
            env={k:v for k,v in os.environ.items() if not k.upper().startswith('GIT_')};env.update(HOME=str(home),GIT_CONFIG_NOSYSTEM='1')
            def make(name,text):
                repo=base/name;repo.mkdir()
                for args in [['git','init','-q',str(repo)],['git','-C',str(repo),'add','f.txt']]:
                    if args[-1]=='f.txt': (repo/'f.txt').write_text(text)
                    subprocess.run(args,check=True,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                subprocess.run(['git','-C',str(repo),'-c','user.email=a@b.c','-c','user.name=t','-c','commit.gpgsign=false','commit','-q','-m','x'],check=True,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                return repo
            a=make('a','a');b=make('b','b')
            ha=rr.git_read(a,'rev-parse','--verify','HEAD').stdout.strip();hb=rr.git_read(b,'rev-parse','--verify','HEAD').stdout.strip()
            self.assertNotEqual(ha,hb)
            with mock.patch.dict(os.environ,{'GIT_DIR':str(b/'.git'),'GIT_WORK_TREE':str(b),'GIT_CONFIG_COUNT':'0'},clear=False):
                self.assertEqual(rr.git_read(a,'rev-parse','--verify','HEAD').stdout.strip(),ha)
    def test_git_wait_cleanup(self):
        for kw in [dict(),dict(tbad=True),dict(fail=2,tbad=True,kbad=True)]:
            proc=WaitBad(**kw)
            with mock.patch.object(rr.subprocess,'Popen',lambda argv,p=proc,**k: p):
                with self.assertRaises(GE) as cm: rr.git_read('.','rev-parse','--verify','HEAD')
            self.assertGreaterEqual(proc.terminated,1);self.assertNotIn('sekret',str(cm.exception))
            self.assertLessEqual(proc.waits,4)
        proc=WaitBad(fail=2,tbad=True,kbad=True)
        with mock.patch.object(rr.subprocess,'Popen',lambda argv,**k: proc):
            with self.assertRaises(GE): rr.git_read('.','cat-file','-p',SHA)
        self.assertGreaterEqual(proc.killed,1)
        good=GoodProc()
        with mock.patch.object(rr.subprocess,'Popen',lambda argv,**k: good):
            self.assertEqual(rr.git_read('.','cat-file','-t',SHA).stdout,b'ok')
if __name__=='__main__': unittest.main()
