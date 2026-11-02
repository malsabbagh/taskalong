import copy,hashlib,io,os,sys,tempfile,threading,unittest,urllib.error
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[2];TOOLS=ROOT/'tools'
for p in (str(ROOT),str(TOOLS)):
    if p not in sys.path: sys.path.insert(0,p)
import tools.release_remote as rr
import release_remote as rr_top
SHA='a'*40;TREE='b'*40;REPO='malsabbagh/taskalong';GH='https://api.github.com/repos/'+REPO
CI='.github/workflows/ci.yml';DW='.github/workflows/npm-consumer.yml'
CORE=rr._rm._CORE_JOBS;DIST=rr._rm._DISTRIBUTION_JOBS;VERS=dict(rr._rm._VERSIONS)
GE=rr.ReleaseGateError;NF=rr.ReleaseNotFound
def rurl(r): return GH+'/actions/runs/'+str(r)
def jurl(r,p): return rurl(r)+'/attempts/1/jobs?per_page=100&page='+str(p)
def raw_run(r,wf):
    return {'id':r,'run_attempt':1,'path':wf,'event':'push','head_branch':'main','head_sha':SHA,'status':'completed','conclusion':'success','repository':{'full_name':REPO},'head_repository':{'full_name':REPO},'extra':'ignored'}
class Client:
    def __init__(s,routes): s.routes=routes;s.urls=[]
    def get_json(s,url):
        s.urls.append(url);v=s.routes[url];return copy.deepcopy(v.pop(0) if len(v)>1 else v[0])
def mk(r=10,wf=CI,names=CORE,mut_run=None,mut_jobs=None,second=None,pages=None,jbase=1000):
    run=raw_run(r,wf)
    if mut_run: mut_run(run)
    jobs=[{'id':jbase+i,'name':n,'run_id':r,'run_attempt':1,'status':'completed','conclusion':'success','extra':i} for i,n in enumerate(names)]
    if mut_jobs: mut_jobs(jobs)
    routes={rurl(r):[run] if second is None else [run,second]}
    if callable(pages): pages=pages(jobs)
    if pages is None: pages=[jobs]
    for i,p in enumerate(pages,1): routes[jurl(r,i)]=[p if type(p) is dict else {'total_count':len(jobs),'jobs':p}]
    return Client(routes)
class Resp:
    def __init__(s,data,status=200): s.data=data;s.pos=0;s.status=status;s.sizes=[]
    def read(s,n=-1):
        s.sizes.append(n);n=len(s.data)-s.pos if n<0 else n;c=s.data[s.pos:s.pos+n];s.pos+=len(c);return c
    def close(s): pass
class Op:
    def __init__(s,fn): s.fn=fn;s.reqs=[];s.tos=[]
    def open(s,req,timeout=None): s.reqs.append(req);s.tos.append(timeout);return s.fn(req)
class Proc:
    def __init__(s,o,e,rc=0,alive=False): s.stdout=o;s.stderr=e;s._rc=rc;s.alive=alive;s.terminated=False;s.killed=False
    def poll(s): return None if s.alive and not s.terminated and not s.killed else s._rc
    def wait(s,timeout=None): return s._rc
    def terminate(s):
        s.terminated=True
        for x in (s.stdout,s.stderr):
            ev=getattr(x,'ev',None)
            if ev: ev.set()
    def kill(s): s.killed=True;s.terminate()
class Block:
    def __init__(s): s.ev=threading.Event()
    def read1(s,n): s.ev.wait(2);return b''
    def read(s,n=-1): return s.read1(n)
class T(unittest.TestCase):
    def test_imports_canonical_read_json(self):
        self.assertIsNot(rr,rr_top);self.assertTrue(hasattr(rr_top,'qualify_source'))
        self.assertEqual(rr.canonical_bytes({'b':1,'a':[True,None]}),b'{"a":[true,null],"b":1}')
        self.assertNotEqual(rr.canonical_bytes(True),rr.canonical_bytes(1))
        self.assertNotEqual(rr.canonical_bytes(False),rr.canonical_bytes(0))
        cyc=[];cyc.append(cyc)
        for bad in [(1,),cyc,float('nan'),chr(0xd800),{1:2},object()]:
            with self.subTest(bad=type(bad).__name__): self.assertRaises(GE,rr.canonical_bytes,bad)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.json';p.write_bytes(b'{"a":1}');self.assertEqual(rr.read_json(p),{'a':1})
            for data in [b'{"a":1,"a":2}',b'{"a":NaN}',b'{"a":1e999}',bytes([255]),b'x'*(1048577)]:
                p.write_bytes(data)
                with self.assertRaises(GE): rr.read_json(p)
            with self.assertRaises(GE): rr.read_json(d)
    def test_https(self):
        op=Op(lambda req: Resp(b'{}'));c=rr.HttpsClient(github_token='sekret',opener=op)
        c.get_json(GH+'/actions/runs/1');self.assertEqual(op.reqs[-1].get_header('Authorization'),'Bearer sekret')
        self.assertEqual(op.reqs[-1].get_header('X-github-api-version'),'2022-11-28');self.assertEqual(op.tos[-1],20)
        for u in ['https://pypi.org/pypi/taskalong/0.1.0a1/json','https://registry.npmjs.org/@taskalong%2Fcli/0.1.0-alpha.1']:
            c.get_json(u);self.assertIsNone(op.reqs[-1].get_header('Authorization'))
        n=len(op.reqs)
        for u in ['https://example.com/x','http://api.github.com/repos/'+REPO+'/x',GH+'/../x','https://pypi.org/pypi/taskalong/0.1.0a1/json?q=1','https://user@api.github.com/repos/'+REPO+'/x']:
            with self.assertRaises(GE): c.get_json(u)
        self.assertEqual(len(op.reqs),n)
        with mock.patch.dict(os.environ,{'GH_TOKEN':'envtok','GITHUB_TOKEN':'other'}):
            op2=Op(lambda req: Resp(b'{}'));rr.HttpsClient(opener=op2).get_json(GH+'/x')
            self.assertEqual(op2.reqs[-1].get_header('Authorization'),'Bearer envtok')
        big=Resp(b'x'*20);c2=rr.HttpsClient(opener=Op(lambda req: big))
        with self.assertRaises(GE): c2.get_bytes('https://registry.npmjs.org/@taskalong/cli/-/cli-0.1.0-alpha.1.tgz',max_bytes=4)
        self.assertEqual(big.sizes,[5])
        for data in ['{"a":1,"a":2}'.encode(),'{"a":NaN}'.encode(),bytes([255])]:
            cc=rr.HttpsClient(github_token='sekret',opener=Op(lambda req,data=data: Resp(data)))
            with self.assertRaises(GE) as cm: cc.get_json(GH+'/x')
            self.assertNotIn('sekret',str(cm.exception))
        def err(code):
            def f(req): raise urllib.error.HTTPError(req.full_url,code,'m',None,io.BytesIO(b'sekret'))
            return f
        with self.assertRaises(NF): rr.HttpsClient(opener=Op(err(404))).get_json(GH+'/x')
        for fn,exc in [(err(403),'x'),(lambda req: Resp(b'',302),'x')]:
            with self.assertRaises(GE) as cm: rr.HttpsClient(github_token='sekret',opener=Op(fn)).get_json(GH+'/x')
            self.assertNotIsInstance(cm.exception,NF);self.assertNotIn('sekret',str(cm.exception))
        with self.assertRaises(GE) as cm: rr.HttpsClient(opener=Op(lambda req: (_ for _ in ()).throw(TimeoutError('sekret')))).get_json(GH+'/x')
        self.assertNotIsInstance(cm.exception,NF);self.assertNotIn('sekret',str(cm.exception))
    def test_git(self):
        cap={};proc=Proc(io.BytesIO(b'ok'),io.BytesIO(b'e'))
        def popen(argv,**kw): cap.update(argv=argv,kw=kw,called=cap.get('called',0)+1);return cap['proc']
        cap['proc']=proc
        with mock.patch.object(rr.subprocess,'Popen',popen):
            r=rr.git_read('.','rev-parse','--verify','HEAD')
            self.assertEqual((r.stdout,r.stderr,r.returncode),(b'ok',b'e',0));self.assertFalse(cap['kw']['shell'])
            self.assertIn('core.fsmonitor=false',cap['argv']);self.assertIn('core.hooksPath=/dev/null',cap['argv']);self.assertIn('--no-pager',cap['argv'])
            n=cap['called']
            for a in [('status',),('fetch',),('cat-file','-p','ZZZ'),('verify-tag','--raw','A'*40)]:
                with self.assertRaises(GE): rr.git_read('.',*a)
            self.assertEqual(cap['called'],n)
            cap['proc']=Proc(io.BytesIO(b'x'*40000),io.BytesIO(b'y'*40000),alive=True)
            with self.assertRaises(GE): rr.git_read('.','cat-file','-p',SHA)
            bad=Proc(io.BytesIO(b'x'*70000),io.BytesIO(b''),alive=True)
            bad.terminate=lambda: (_ for _ in ()).throw(RuntimeError('sekret'));cap['proc']=bad
            with self.assertRaises(GE) as cm: rr.git_read('.','cat-file','-p',SHA)
            self.assertIn('exceeds',str(cm.exception));self.assertNotIn('sekret',str(cm.exception))
            blk=Proc(Block(),io.BytesIO(b''),alive=True);cap['proc']=blk
            with mock.patch.object(rr,'_GIT_TIMEOUT',0.05),mock.patch.object(rr,'_CLEANUP',0.05):
                with self.assertRaises(GE) as cm: rr.git_read('.','cat-file','-p',SHA)
            self.assertIn('timed out',str(cm.exception));self.assertTrue(blk.terminated)
    def test_fetch_success_pagination(self):
        c=mk(pages=lambda js:[js[:5],js[5:]]);out=rr.fetch_run(10,CI,CORE,SHA,client=c)
        self.assertEqual([j['name'] for j in out['jobs']],sorted(CORE));self.assertEqual(out['attempt'],1)
        self.assertNotIn('extra',out);self.assertEqual(c.urls.count(rurl(10)),2)
        c2=mk(20,DW,DIST,mut_jobs=lambda js: [j.pop('run_attempt') for j in js],jbase=2000)
        self.assertEqual(len(rr.fetch_run(20,DW,DIST,SHA,client=c2)['jobs']),3)
        suf=mk(mut_run=lambda r: r.update(path=CI+'@refs/heads/main'))
        self.assertEqual(rr.fetch_run(10,CI,CORE,SHA,client=suf)['id'],10)
    def test_fetch_rejects(self):
        cases=[
            ('event',dict(mut_run=lambda r:r.update(event='pull_request'))),('branch',dict(mut_run=lambda r:r.update(head_branch='x'))),
            ('repo',dict(mut_run=lambda r:r['repository'].update(full_name='x/y'))),('headrepo',dict(mut_run=lambda r:r['head_repository'].update(full_name='x/y'))),
            ('suffix',dict(mut_run=lambda r:r.update(path=CI+'@refs/heads/x'))),('workflow',dict(mut_run=lambda r:r.update(path=DW))),
            ('source',dict(mut_run=lambda r:r.update(head_sha='c'*40))),('status',dict(mut_run=lambda r:r.update(conclusion='failure'))),
            ('runid',dict(mut_run=lambda r:r.update(id=11))),('boolrun',dict(mut_run=lambda r:r.update(id=True))),
            ('missing',dict(mut_jobs=lambda js:js.pop())),('extra',dict(mut_jobs=lambda js:js.append(dict(js[0],id=9999,name='x')))),
            ('dupname',dict(mut_jobs=lambda js:js.append(dict(js[0],id=9999)))),('dupid',dict(mut_jobs=lambda js:js[1].update(id=js[0]['id']))),
            ('jobrun',dict(mut_jobs=lambda js:js[0].update(run_id=99))),('jobatt',dict(mut_jobs=lambda js:js[0].update(run_attempt=2))),
            ('jobbool',dict(mut_jobs=lambda js:js[0].update(id=True))),('jobfail',dict(mut_jobs=lambda js:js[0].update(status='queued'))),
            ('total',dict(pages=lambda js:[{'total_count':9,'jobs':js},{'total_count':9,'jobs':[]}])),
            ('limit',dict(pages=lambda js:[{'total_count':1001,'jobs':js}])),
            ('totalbool',dict(pages=lambda js:[{'total_count':True,'jobs':js}])),
        ]
        for name,kw in cases:
            with self.subTest(name=name): self.assertRaises(GE,rr.fetch_run,10,CI,CORE,SHA,client=mk(**kw))
        second=raw_run(10,CI);second.update(run_attempt=2)
        with self.assertRaises(GE): rr.fetch_run(10,CI,CORE,SHA,client=mk(second=second))
        for rid,wf,names in [(True,CI,CORE),(0,CI,CORE),(10,CI,()),(10,CI,DIST),(10,'x',CORE)]:
            with self.assertRaises(GE): rr.fetch_run(rid,wf,names,SHA,client=mk())
    def test_qualify(self):
        def combined(djbase=2000):
            a=mk(10,CI,CORE,jbase=1000);b=mk(20,DW,DIST,jbase=djbase);return Client({**a.routes,**b.routes})
        def runq(client,gitstate=None,versions=None):
            st={'head':0,'ver':0,'calls':[]};gs=gitstate or {}
            def fake_git(root,*args):
                st['calls'].append(args)
                import subprocess
                if args[-1]=='HEAD': st['head']+=1;v=gs.get('sha2',SHA) if st['head']>1 and gs.get('change') else SHA;return subprocess.CompletedProcess(args,0,v.encode()+bytes([10]),b'')
                if args[-1]=='HEAD^{tree}': return subprocess.CompletedProcess(args,0,TREE.encode()+bytes([10]),b'')
                return subprocess.CompletedProcess(args,0,gs.get('status',b''),b'')
            def fake_check(root,tag):
                st['ver']+=1;self.assertEqual(tag,'v0.1.0a1')
                return versions(st['ver']) if callable(versions) else dict(VERS)
            with mock.patch.object(rr,'git_read',fake_git),mock.patch.object(rr,'check_tree',fake_check):
                return rr.qualify_source('.',10,20,client=client),st
        client=combined();r,st=runq(client)
        self.assertEqual(set(r),{'format','repository','source_sha','source_tree','versions','core','distribution','evidence_provenance','publication_allowed','tag_creation_allowed','digest'})
        self.assertEqual((r['format'],r['repository'],r['publication_allowed'],r['tag_creation_allowed']),('taskalong-source-qualification/1',REPO,False,False))
        body=dict(r);d=body.pop('digest');self.assertEqual(d,hashlib.sha256(rr.canonical_bytes(body)).hexdigest())
        client.routes[rurl(10)][0].update(head_sha='c'*40);self.assertEqual(r['source_sha'],SHA)
        r['core']['jobs'].clear();r2,_st=runq(combined());self.assertEqual(len(r2['core']['jobs']),8)
        self.assertTrue(all(a[0] in ('rev-parse','status') for a in st['calls']))
        with self.assertRaises(GE): runq(combined(),{'status':b' M x'})
        with self.assertRaises(GE): runq(combined(),{'change':True,'sha2':'c'*40})
        with self.assertRaises(GE): runq(combined(),versions=lambda n: dict(VERS,tag='v9'))
        with self.assertRaises(GE): runq(combined(djbase=1000))
if __name__=='__main__': unittest.main()
