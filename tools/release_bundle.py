import argparse,gzip,hashlib,io,json,os,shutil,stat,subprocess,sys,tarfile,tempfile
from pathlib import Path
import check_dist,release_version
PY="0.1.0a1";NV="0.1.0-alpha.1";MAX=1048576;LIM=262144;EXP="taskalong 0.1.0a1 (API/schema 1.0)"
URL="git+https://github.com/malsabbagh/taskalong.git"
M={"package/package.json":"package.json","package/bin/taskalong.js":"bin/taskalong.js","package/README.md":"README.md","package/LICENSE":"LICENSE"}
class ReleaseError(ValueError):pass
E=ReleaseError
def _read(p,n):
 p=Path(p)
 try:s=p.lstat()
 except OSError as e:raise E("missing file") from e
 if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_size>n:raise E("unsafe file")
 b=p.read_bytes()
 if len(b)>n:raise E("unsafe file")
 return b
def _dup(q):
 if len({k for k,_ in q})<len(q):raise E("duplicate key")
 return dict(q)
def _const(x):raise E("bad constant")
def _tree(root):
 try:r=release_version.check_tree(root,"v"+PY)
 except (ValueError,OSError) as e:raise E(str(e) or "bad source") from e
 if r!={"python":PY,"npm":NV,"tag":"v"+PY}:raise E("bad source version")
def _src(root,rel):
 p=root
 for x in Path("packages/npm/cli",rel).parts:
  p/=x
  if p.is_symlink():raise E("symlink in source")
 if not p.resolve().is_relative_to(root):raise E("source escape")
 return _read(p,LIM)
def _meta(b):
 try:m=json.loads(b.decode(),object_pairs_hook=_dup,parse_constant=_const)
 except (UnicodeDecodeError,json.JSONDecodeError) as e:raise E("bad package.json") from e
 bad=("scripts","dependencies","devDependencies","optionalDependencies","peerDependencies","bundleDependencies","bundledDependencies")
 if not isinstance(m,dict) or any(k in m for k in bad):raise E("bad metadata")
 q=m.get("repository");u=q if isinstance(q,str) else q.get("url") if isinstance(q,dict) else None
 if isinstance(q,dict) and q.get("type","git")!="git":raise E("bad metadata")
 e=m.get("engines");c=m.get("publishConfig");t=m.get("taskalong")
 ok=(m.get("name"),m.get("version"),m.get("license"),m.get("type"),u)==("@taskalong/cli",NV,"MIT","commonjs",URL) and m.get("bin")=={"taskalong":"bin/taskalong.js"} and m.get("files")==["bin/taskalong.js","README.md","LICENSE"] and isinstance(e,dict) and e.get("node")==">=22.14.0" and isinstance(c,dict) and c.get("access")=="public" and isinstance(t,dict) and t.get("pythonVersion")==PY
 if not ok:raise E("bad metadata")
def audit_npm(root,archive):
 root=Path(root).resolve();_tree(root);comp=_read(archive,MAX)
 try:
  with gzip.GzipFile(fileobj=io.BytesIO(comp)) as g:raw=g.read(MAX+1)
 except (OSError,EOFError) as e:raise E("bad gzip") from e
 if len(raw)>MAX:raise E("archive too large")
 d={}
 try:
  with tarfile.open(fileobj=io.BytesIO(raw),mode="r:") as t:
   ms=t.getmembers()
   if len(ms)!=4 or {m.name for m in ms}!=set(M):raise E("bad members")
   for m in ms:
    if not m.isreg() or m.size>LIM or m.mode not in ({420,493} if m.name.endswith(".js") else {420}):raise E("unsafe member")
    f=t.extractfile(m);b=f.read(LIM+1) if f else b""
    if len(b)!=m.size:raise E("bad member")
    d[m.name]=b
 except tarfile.TarError as e:raise E("bad tar") from e
 if any(d[a]!=_src(root,r) for a,r in M.items()):raise E("source mismatch")
 if hashlib.sha256(d["package/LICENSE"]).hexdigest()!=str(check_dist.APPROVED_LICENSE_SHA256).lower():raise E("bad license")
 _meta(d["package/package.json"])
 return {"archive_sha256":hashlib.sha256(comp).hexdigest(),"archive_size":len(comp),"members":[{"name":n,"sha256":hashlib.sha256(d[n]).hexdigest(),"size":len(d[n])} for n in sorted(d)],"npm_version":NV,"python_version":PY,"source_consistent":True}
def _run(a,cwd,env):
 try:r=subprocess.run(a,cwd=cwd,env=env,shell=False,timeout=120,capture_output=True)
 except (OSError,subprocess.TimeoutExpired) as e:raise E("command unavailable") from e
 if len(r.stdout)+len(r.stderr)>65536:raise E("output too large")
 if r.returncode:raise E("command failed")
 return r.stdout
def _exe(x,w):
 if x:
  if Path(x).is_file():return os.path.abspath(str(x))
  y=shutil.which(str(x))
  if y:return os.path.abspath(y)
 raise E(w+" unavailable")
def _npm(node,x):
 if x:return _exe(x,"npm-cli.js")
 n=shutil.which("npm")
 if n:
  r=Path(n).resolve()
  if r.name=="npm-cli.js" and r.is_file():return str(r)
 p=Path(node)
 for q in (p.parent/"node_modules/npm/bin/npm-cli.js",p.parent.parent/"lib/node_modules/npm/bin/npm-cli.js"):
  if q.is_file():return os.path.abspath(q)
 raise E("npm-cli.js unavailable")
def npm_consumer(root,archive,python,*,node=None,npm_cli=None):
 a=audit_npm(root,archive);py=_exe(python,"python");nd=_exe(node or "node","node");cli=_npm(nd,npm_cli);arc=str(Path(archive).resolve());co=Path(root).resolve()
 with tempfile.TemporaryDirectory(prefix="taskalong-consumer-") as td:
  t=Path(td)
  if t.resolve().is_relative_to(co):raise E("temp in checkout")
  pre=t/"prefix";cache=t/"cache";pre.mkdir();cache.mkdir();u=t/"u.npmrc";g=t/"g.npmrc";u.write_text("");g.write_text("")
  env={k:v for k,v in os.environ.items() if not k.upper().startswith("NPM_CONFIG_") and k not in ("NODE_AUTH_TOKEN","NPM_TOKEN")}
  env.update(NPM_CONFIG_USERCONFIG=str(u),NPM_CONFIG_GLOBALCONFIG=str(g),NPM_CONFIG_CACHE=str(cache),TASKALONG_PYTHON=py)
  _run([nd,cli,"install","--prefix",str(pre),"--offline","--ignore-scripts","--no-audit","--no-fund","--no-update-notifier","--no-package-lock","--cache",str(cache),"--userconfig",str(u),"--globalconfig",str(g),arc],t,env)
  b=pre/"node_modules/@taskalong/cli/bin/taskalong.js"
  if not b.is_file():raise E("installed bin missing")
  o=_run([nd,str(b),"--version"],t,env)
  try:s=o.decode()
  except UnicodeDecodeError as e:raise E("bad version output") from e
  if s.rstrip("\r\n")!=EXP:raise E("bad version output")
 return {"archive_sha256":a["archive_sha256"],"archive_size":a["archive_size"],"consumer":"ok","invocation":"node installed bin/taskalong.js --version","npm_shim_tested":False,"npm_version":NV,"python_version":PY,"version_output":EXP}
def main(argv=None):
 p=argparse.ArgumentParser();s=p.add_subparsers(dest="c",required=True);a=s.add_parser("audit-npm");b=s.add_parser("npm-consumer")
 for q in (a,b):q.add_argument("--root",required=True);q.add_argument("--archive",required=True)
 b.add_argument("--python",required=True);b.add_argument("--node");b.add_argument("--npm-cli")
 x=p.parse_args(argv)
 try:r=audit_npm(x.root,x.archive) if x.c=="audit-npm" else npm_consumer(x.root,x.archive,x.python,node=x.node,npm_cli=x.npm_cli)
 except E as e:print("error:",e,file=sys.stderr);return 1
 print(json.dumps(r,sort_keys=True));return 0
if __name__=="__main__":raise SystemExit(main())
