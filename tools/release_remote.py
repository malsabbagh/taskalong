# Read-only transport and remote source-CI qualification; grants no publication permission.
import hashlib,json,math,os,re,ssl,stat,subprocess,threading,time
import urllib.error,urllib.parse,urllib.request
from pathlib import Path
if __package__:
    from . import release_manifest as _rm
    from .release_version import check_tree
else:
    import release_manifest as _rm
    from release_version import check_tree
class ReleaseGateError(ValueError): pass
class ReleaseNotFound(ReleaseGateError): pass
_REPO='malsabbagh/taskalong';_MAXID=2**53-1;_FILE=1048576;_JSON=4194304
_GITLIM=65536;_GIT_TIMEOUT=20;_CLEANUP=2;_TIMEOUT=20
_SHA=re.compile('[0-9a-f]{40}')
_CI='.github/workflows/ci.yml';_DISTWF='.github/workflows/npm-consumer.yml'
_WFJOBS={_CI:_rm._CORE_JOBS,_DISTWF:_rm._DISTRIBUTION_JOBS}
_VERSIONS=dict(_rm._VERSIONS);_GH='https://api.github.com/repos/'+_REPO
_ID='[1-9][0-9]{0,15}';_H40='[0-9a-f]{40}'
_GHPATH=re.compile('/repos/'+_REPO+'/(?:actions/runs/'+_ID+'(?:/attempts/'+_ID+'(?:/jobs)?|/jobs|/artifacts)?|actions/(?:jobs|artifacts)/'+_ID+'|commits/'+_H40+'|git/(?:commits|tags)/'+_H40+'|git/ref/tags/v0[.]1[.]0a1|environments/(?:pypi|npm)(?:/deployment-branch-policies(?:/'+_ID+')?)?)')
def _ustr(v):
    try: v.encode('utf-8')
    except Exception: raise ReleaseGateError('invalid Unicode in JSON value') from None
def _strict(v,seen=None):
    if seen is None: seen=set()
    t=type(v)
    if v is None or t in (bool,int): return
    if t is str: _ustr(v);return
    if t is float:
        if not math.isfinite(v): raise ReleaseGateError('nonfinite JSON value')
        return
    if t in (list,dict):
        if id(v) in seen: raise ReleaseGateError('circular JSON value')
        seen.add(id(v))
        try:
            if t is dict:
                for k,x in v.items():
                    if type(k) is not str: raise ReleaseGateError('JSON keys must be strings')
                    _ustr(k);_strict(x,seen)
            else:
                for x in v: _strict(x,seen)
        finally: seen.discard(id(v))
        return
    raise ReleaseGateError('unsupported JSON value')
def canonical_bytes(value):
    try:
        _strict(value);return _rm.manifest_bytes(value)
    except ReleaseGateError: raise
    except Exception: raise ReleaseGateError('invalid canonical JSON value') from None
def _pairs(p):
    o={}
    for k,v in p:
        if k in o: raise ReleaseGateError('duplicate JSON key')
        o[k]=v
    return o
def _badconst(x): raise ReleaseGateError('nonfinite JSON value')
def _float(x):
    v=float(x)
    if not math.isfinite(v): raise ReleaseGateError('nonfinite JSON value')
    return v
def _loads(data):
    try:
        v=json.loads(data.decode('utf-8'),object_pairs_hook=_pairs,parse_constant=_badconst,parse_float=_float)
        _strict(v);return v
    except ReleaseGateError: raise
    except Exception: raise ReleaseGateError('invalid JSON') from None
def read_json(path):
    try:
        p=Path(path);st=p.lstat()
        if not stat.S_ISREG(st.st_mode): raise ReleaseGateError('JSON path is not a regular file')
        with p.open('rb') as f: data=f.read(_FILE+1)
    except ReleaseGateError: raise
    except Exception: raise ReleaseGateError('cannot read JSON file') from None
    if len(data)>_FILE: raise ReleaseGateError('JSON file exceeds 1 MiB')
    return _loads(data)
def _url_kind(url,for_json):
    if type(url) is not str or not url or chr(92) in url or any(ord(c)<32 or ord(c)==127 for c in url):
        raise ReleaseGateError('URL not allowed')
    try:
        u=urllib.parse.urlsplit(url);port=u.port
    except Exception: raise ReleaseGateError('URL not allowed') from None
    host=(u.hostname or '').lower()
    if u.scheme!='https' or u.fragment or u.username or u.password or port is not None or u.netloc.lower()!=host:
        raise ReleaseGateError('URL not allowed')
    _meta=host=='registry.npmjs.org' and re.fullmatch('/@taskalong(?i:%2f)cli/0[.]1[.]0-alpha[.]1',u.path) is not None
    if host=='api.github.com':
        if _GHPATH.fullmatch(u.path) is None: raise ReleaseGateError('URL not allowed')
        if u.query:
            if len(u.query)>1024 or any(not 32<ord(c)<127 for c in u.query): raise ReleaseGateError('URL not allowed')
            keys=[k.lower() for k,v in urllib.parse.parse_qsl(u.query,keep_blank_values=True)]
            if any(k in ('token','access_token','authorization','password','client_secret') for k in keys):
                raise ReleaseGateError('URL not allowed')
        return host
    if u.query: raise ReleaseGateError('URL not allowed')
    if host=='pypi.org' and u.path=='/pypi/taskalong/0.1.0a1/json': return host
    if host=='registry.npmjs.org':
        if _meta: return host
        if u.path=='/@taskalong/cli/-/cli-0.1.0-alpha.1.tgz' and not for_json: return host
    raise ReleaseGateError('URL not allowed')
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl): return None
class HttpsClient:
    def __init__(self,*,github_token=None,opener=None):
        if github_token is None: github_token=os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
        if not github_token: github_token=None
        elif type(github_token) is not str or any(ord(c)<33 or ord(c)==127 for c in github_token):
            raise ReleaseGateError('invalid GitHub token')
        self._token=github_token
        self._opener=opener if opener is not None else urllib.request.build_opener(_NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    def _read(self,url,limit,for_json):
        host=_url_kind(url,for_json)
        h={'User-Agent':'taskalong-release-remote/1','Accept':'application/json' if for_json else 'application/octet-stream'}
        if host=='api.github.com':
            h['Accept']='application/vnd.github+json';h['X-GitHub-Api-Version']='2022-11-28'
            if self._token: h['Authorization']='Bearer '+self._token
        req=urllib.request.Request(url,headers=h,method='GET')
        fn=getattr(self._opener,'open',self._opener)
        try: resp=fn(req,timeout=_TIMEOUT)
        except urllib.error.HTTPError as e:
            code=getattr(e,'code',None)
            try: e.close()
            except Exception: pass
            if code==404: raise ReleaseNotFound('remote resource not found') from None
            raise ReleaseGateError('remote request failed') from None
        except ReleaseGateError: raise
        except Exception: raise ReleaseGateError('remote request failed') from None
        try:
            code=getattr(resp,'status',None)
            if code is None and hasattr(resp,'getcode'): code=resp.getcode()
            if code is None: code=200
            if type(code) is not int: raise ReleaseGateError('remote request failed')
            if code==404: raise ReleaseNotFound('remote resource not found')
            if code!=200: raise ReleaseGateError('remote request failed')
            out=bytearray()
            while True:
                want=min(65536,limit+1-len(out))
                chunk=resp.read(want)
                if not chunk: break
                if not isinstance(chunk,(bytes,bytearray)): raise ReleaseGateError('remote response failed')
                out+=chunk
                if len(out)>limit: raise ReleaseGateError('remote response exceeds limit')
            return bytes(out)
        except ReleaseGateError: raise
        except Exception: raise ReleaseGateError('remote response failed') from None
        finally:
            try: resp.close()
            except Exception: pass
    def get_bytes(self,url,*,max_bytes=1048576):
        if type(max_bytes) is not int or not 0<=max_bytes<=_JSON: raise ReleaseGateError('invalid max_bytes')
        return self._read(url,max_bytes,False)
    def get_json(self,url): return _loads(self._read(url,_JSON,True))
def _stop(proc):
    try:
        if proc.poll() is None:
            try: proc.terminate()
            except Exception: pass
            try: proc.wait(timeout=_CLEANUP);return
            except Exception: pass
            try: proc.kill()
            except Exception: pass
            try: proc.wait(timeout=_CLEANUP)
            except Exception: pass
    except Exception: pass
def _git_env():
    return {k:v for k,v in os.environ.items() if not k.upper().startswith('GIT_')}
def git_read(root,*args):
    fixed={('rev-parse','--verify','HEAD'),('rev-parse','--verify','HEAD^{tree}'),('status','--porcelain=v1','--untracked-files=all')}
    ok=args in fixed or (len(args)==3 and args[:2] in {('cat-file','-t'),('cat-file','-p'),('verify-tag','--raw')} and type(args[2]) is str and _SHA.fullmatch(args[2]) is not None)
    if not ok or any(type(a) is not str for a in args): raise ReleaseGateError('git command not allowed')
    try: root_s=os.fspath(root)
    except Exception: raise ReleaseGateError('invalid git root') from None
    if type(root_s) is not str: raise ReleaseGateError('invalid git root')
    argv=['git','--no-pager','-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null','-C',root_s]+list(args)
    try: proc=subprocess.Popen(argv,shell=False,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=_git_env())
    except Exception: raise ReleaseGateError('git unavailable') from None
    out,err=bytearray(),bytearray();state={'total':0,'over':False,'err':False};lock=threading.Lock()
    def reader(stream,buf):
        try:
            while True:
                chunk=stream.read1(8192) if hasattr(stream,'read1') else stream.read(8192)
                if not chunk: break
                if not isinstance(chunk,(bytes,bytearray)): raise TypeError
                with lock:
                    state['total']+=len(chunk)
                    if state['total']>_GITLIM: state['over']=True
                    else: buf+=chunk
                if state['over']: break
        except Exception: state['err']=True
    ts=[threading.Thread(target=reader,args=(proc.stdout,out),daemon=True),threading.Thread(target=reader,args=(proc.stderr,err),daemon=True)]
    [t.start() for t in ts];deadline=time.monotonic()+_GIT_TIMEOUT
    while any(t.is_alive() for t in ts):
        if state['over']: _stop(proc);raise ReleaseGateError('git output exceeds limit')
        if time.monotonic()>=deadline: _stop(proc);raise ReleaseGateError('git command timed out')
        for t in ts: t.join(0.01)
    if state['over']: _stop(proc);raise ReleaseGateError('git output exceeds limit')
    if state['err']: _stop(proc);raise ReleaseGateError('git command failed')
    try: rc=proc.wait(timeout=max(0.0,deadline-time.monotonic()))
    except subprocess.TimeoutExpired: _stop(proc);raise ReleaseGateError('git command timed out') from None
    except Exception: _stop(proc);raise ReleaseGateError('git command failed') from None
    if rc!=0: _stop(proc);raise ReleaseGateError('git command failed')
    return subprocess.CompletedProcess(argv,0,bytes(out),bytes(err))
def _pos(v): return type(v) is int and 1<=v<=_MAXID
def _get(client,url):
    try: return client.get_json(url)
    except ReleaseGateError: raise
    except Exception: raise ReleaseGateError('remote read failed') from None
def _identity(raw,run_id,wf,sha):
    if type(raw) is not dict: raise ReleaseGateError('run identity mismatch')
    rid,att=raw.get('id'),raw.get('run_attempt')
    if not _pos(rid) or rid!=run_id or not _pos(att): raise ReleaseGateError('run identity mismatch')
    repo=raw.get('repository');head=raw.get('head_repository') if 'head_repository' in raw else repo
    if type(repo) is not dict or repo.get('full_name')!=_REPO or type(head) is not dict or head.get('full_name')!=_REPO:
        raise ReleaseGateError('run repository mismatch')
    exp={'event':'push','head_branch':'main','head_sha':sha,'status':'completed','conclusion':'success'}
    if any(type(raw.get(k)) is not str or raw.get(k)!=v for k,v in exp.items()): raise ReleaseGateError('run identity mismatch')
    path=raw.get('path')
    if type(path) is not str or path not in (wf,wf+'@refs/heads/main'): raise ReleaseGateError('run workflow mismatch')
    return {'id':rid,'attempt':att,'repository':_REPO,'head_repository':_REPO,'workflow':wf,'path':path,'event':'push','ref':'refs/heads/main','branch':'main','head_sha':sha,'status':'completed','conclusion':'success'}
def fetch_run(run_id,workflow,job_names,source_sha,*,client):
    if not _pos(run_id): raise ReleaseGateError('invalid run id')
    if type(source_sha) is not str or _SHA.fullmatch(source_sha) is None: raise ReleaseGateError('invalid source sha')
    if type(workflow) is not str or workflow not in _WFJOBS: raise ReleaseGateError('invalid workflow')
    exp=_WFJOBS[workflow]
    try: names=list(job_names)
    except Exception: raise ReleaseGateError('invalid job names') from None
    if type(job_names) is str or len(names)!=len(exp) or any(type(x) is not str for x in names) or set(names)!=set(exp):
        raise ReleaseGateError('invalid job names')
    base=_GH+'/actions/runs/'+str(run_id);ident=_identity(_get(client,base),run_id,workflow,source_sha);att=ident['attempt']
    got=[];total=None
    for page in range(1,11):
        env=_get(client,base+'/attempts/'+str(att)+'/jobs?per_page=100&page='+str(page))
        if type(env) is not dict: raise ReleaseGateError('jobs envelope mismatch')
        tc=env.get('total_count')
        if type(tc) is not int or not 0<=tc<=1000: raise ReleaseGateError('jobs total mismatch')
        if total is None: total=tc
        elif tc!=total: raise ReleaseGateError('jobs total mismatch')
        pj=env.get('jobs')
        if type(pj) is not list: raise ReleaseGateError('jobs envelope mismatch')
        if not pj and len(got)<total: raise ReleaseGateError('jobs pagination incomplete')
        got+=pj
        if len(got)>total: raise ReleaseGateError('jobs total mismatch')
        if len(got)==total: break
    if total is None or len(got)!=total: raise ReleaseGateError('jobs pagination incomplete')
    seen=set();norm=[]
    for j in got:
        if type(j) is not dict: raise ReleaseGateError('job mismatch')
        jid=j.get('id')
        if not _pos(jid) or jid in seen: raise ReleaseGateError('job id mismatch')
        seen.add(jid)
        if 'run_id' in j and (not _pos(j['run_id']) or j['run_id']!=run_id): raise ReleaseGateError('job run mismatch')
        if 'run_attempt' in j and (not _pos(j['run_attempt']) or j['run_attempt']!=att): raise ReleaseGateError('job attempt mismatch')
        norm.append({'id':jid,'name':j.get('name'),'run_id':run_id,'attempt':att,'status':j.get('status'),'conclusion':j.get('conclusion')})
    runobj={'id':run_id,'attempt':att,'repository':_REPO,'workflow':workflow,'event':'push','ref':'refs/heads/main','head_sha':source_sha,'status':'completed','conclusion':'success','jobs':norm}
    try: out,_ids=_rm._run(runobj,'run',workflow,tuple(names),source_sha)
    except Exception: raise ReleaseGateError('run jobs mismatch') from None
    ident2=_identity(_get(client,base),run_id,workflow,source_sha)
    if canonical_bytes(ident)!=canonical_bytes(ident2): raise ReleaseGateError('run changed during readback')
    return out
def _line(data):
    try: t=data.decode('ascii').strip()
    except Exception: raise ReleaseGateError('source identity mismatch') from None
    if _SHA.fullmatch(t) is None: raise ReleaseGateError('source identity mismatch')
    return t
def _snapshot(root):
    sha=_line(git_read(root,'rev-parse','--verify','HEAD').stdout)
    tree=_line(git_read(root,'rev-parse','--verify','HEAD^{tree}').stdout)
    if git_read(root,'status','--porcelain=v1','--untracked-files=all').stdout!=b'':
        raise ReleaseGateError('source checkout is not clean')
    try: vers=check_tree(root,'v0.1.0a1')
    except ReleaseGateError: raise
    except Exception: raise ReleaseGateError('version check failed') from None
    if type(vers) is not dict or canonical_bytes(vers)!=canonical_bytes(_VERSIONS): raise ReleaseGateError('version mismatch')
    return {'source_sha':sha,'source_tree':tree,'versions':dict(vers)}
def qualify_source(root,core_run_id,distribution_run_id,*,client):
    if not _pos(core_run_id) or not _pos(distribution_run_id) or core_run_id==distribution_run_id:
        raise ReleaseGateError('run ids must differ')
    s1=_snapshot(root)
    core=fetch_run(core_run_id,_CI,_rm._CORE_JOBS,s1['source_sha'],client=client)
    dist=fetch_run(distribution_run_id,_DISTWF,_rm._DISTRIBUTION_JOBS,s1['source_sha'],client=client)
    if {j['id'] for j in core['jobs']} & {j['id'] for j in dist['jobs']}: raise ReleaseGateError('job ids overlap across runs')
    s2=_snapshot(root)
    if canonical_bytes(s1)!=canonical_bytes(s2): raise ReleaseGateError('source changed during qualification')
    r={'format':'taskalong-source-qualification/1','repository':_REPO,'source_sha':s1['source_sha'],'source_tree':s1['source_tree'],'versions':s1['versions'],'core':core,'distribution':dist,'evidence_provenance':'remote_github_readback','publication_allowed':False,'tag_creation_allowed':False}
    r['digest']=hashlib.sha256(canonical_bytes(r)).hexdigest()
    return _loads(canonical_bytes(r))
__all__=['ReleaseGateError','ReleaseNotFound','canonical_bytes','read_json','HttpsClient','git_read','fetch_run','qualify_source']
