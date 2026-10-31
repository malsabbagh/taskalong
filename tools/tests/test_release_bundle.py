import gzip,io,json,os,subprocess,sys,tarfile as tf,tempfile,unittest
from pathlib import Path as P
from unittest import mock
sys.path.insert(0,str(P(__file__).resolve().parents[1]))
import release_bundle as rb
# synthetic mocks below; not a real consumer smoke
R=P(__file__).resolve().parents[2];F="package.json bin/taskalong.js README.md LICENSE".split();RT=tf.REGTYPE
def W(p,b):p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
class T(unittest.TestCase):
 def setUp(s):
  s.t=tempfile.TemporaryDirectory();s.addCleanup(s.t.cleanup);s.r=P(s.t.name)
  for x in "pyproject.toml LICENSE README.md src/taskalong/__init__.py taskalong/__init__.py".split()+[f"packages/npm/cli/{y}" for y in F]:
   p=R/x
   if p.is_file():W(s.r/x,p.read_bytes())
  s.c=s.r/"packages/npm/cli"
 def its(s):return [["package/"+x,(s.c/x).read_bytes(),420,RT] for x in F]
 def arc(s,it=None):
  p=s.r/"a.tgz"
  with tf.open(p,"w:gz") as t:
   for n,b,m,y in it or s.its():i=tf.TarInfo(n);i.mode=m;i.type=y;i.linkname="x";i.size=len(b) if y==RT else 0;t.addfile(i,io.BytesIO(b) if y==RT else None)
  return p
 def rawit(s,it=None):
  b=io.BytesIO()
  with tf.open(fileobj=b,mode="w") as t:
   for n,d,m,y in it or s.its():i=tf.TarInfo(n);i.mode=m;i.type=y;i.size=len(d) if y==RT else 0;t.addfile(i,io.BytesIO(d) if y==RT else None)
  return b.getvalue()
 def rgz(s,raw):p=s.r/"a.tgz";p.write_bytes(gzip.compress(raw));return p
 def cut(s,it):return sum(512+((len(d)+511)//512*512 if y==RT else 0) for _,d,_,y in it)
 def bad(s,it=None,p=None):s.assertRaises(rb.ReleaseError,rb.audit_npm,s.r,p or s.arc(it))
 def test_ok(s):
  a=rb.audit_npm(s.r,s.arc());assert len(a["members"])==4 and a["source_consistent"] and len(a["archive_sha256"])==64
 def test_hidden_tar(s):
  it=s.its();raw=s.rawit(it);base=raw[:s.cut(it)];z=b"\0"*512;rep=[["package/bin/taskalong.js",b"evil\n",420,RT]];rr=s.rawit(rep)[:s.cut(rep)]
  s.assertTrue(rb.audit_npm(s.r,s.rgz(base+2*z))["source_consistent"])
  s.assertTrue(rb.audit_npm(s.r,s.rgz(raw))["source_consistent"])
  pad=bytearray(base+2*z);pad[512+len(it[0][1])]=1
  chk=bytearray(base+2*z);chk[148]^=1
  xh=bytearray(rr[:512]);xh[156:157]=b"x";xh[148:156]=b" "*8;xh[148:156]=f"{sum(xh):06o}\0 ".encode()
  for x in (base+z+rr+2*z,base+2*z+rr+2*z,base+2*z+b"x"*512,base+z,base,base+rr+2*z,bytes(pad),bytes(chk),base[:-1],base[:512],bytes(xh)+rr[512:]+base+2*z):s.bad(p=s.rgz(x))
  rel,res=s.tools();c=[];p=s.rgz(base+z+rr+2*z)
  with mock.patch.object(rb.subprocess,"run",s.fake(c)):s.assertRaises(rb.ReleaseError,rb.npm_consumer,s.r,p,rel[0],node=rel[1],npm_cli=rel[2])
  s.assertEqual(c,[])
 def test_bad(s):
  b=s.its()
  for i,j,v in [(0,0,"../x"),(0,2,438),(0,3,tf.SYMTYPE),(0,3,tf.DIRTYPE),(2,1,b"x"*262145)]:c=[x[:] for x in b];c[i][j]=v;s.bad(c)
  s.bad(b+[b[0]]);s.bad(b+[["package/x",b"x",420,RT]])
  o=(s.c/"package.json").read_bytes()
  for k,v in [("scripts",{"x":1}),("dependencies",{"x":1}),("optionalDependencies",{"x":1}),("version","9")]:d=json.loads(o);d[k]=v;(s.c/"package.json").write_text(json.dumps(d));s.bad()
  (s.c/"package.json").write_bytes(o)
  p=s.r/"b";p.write_bytes(b"no");s.bad(p=p);s.assertRaises(rb.ReleaseError,rb.npm_consumer,s.r,p,sys.executable)
  p=s.arc();(s.c/"README.md").write_bytes(b"z");s.bad(p=p)
  W(s.c/"LICENSE",b"bad");s.bad()
 def test_tree_exact(s):
  p=s.arc()
  for v in (None,{},{"python":rb.PY},{"python":rb.PY,"npm":rb.NV,"tag":"v"+rb.PY,"x":1}):
   with mock.patch.object(rb.release_version,"check_tree",return_value=v):s.assertRaises(rb.ReleaseError,rb.audit_npm,s.r,p)
 def sym(s,src,dst):
  try:dst.symlink_to(src,target_is_directory=src.is_dir())
  except (OSError,NotImplementedError):raise unittest.SkipTest("symlinks unavailable")
 def test_symlink_leaf(s):
  p=s.arc();e=tempfile.TemporaryDirectory();s.addCleanup(e.cleanup);x=P(e.name)/"README.md";x.write_bytes((s.c/"README.md").read_bytes());(s.c/"README.md").unlink();s.sym(x,s.c/"README.md");s.bad(p=p)
 def test_symlink_parent(s):
  p=s.arc();e=tempfile.TemporaryDirectory();s.addCleanup(e.cleanup);x=P(e.name)/"bin";x.mkdir();(x/"taskalong.js").write_bytes((s.c/"bin/taskalong.js").read_bytes());(s.c/"bin/taskalong.js").unlink();(s.c/"bin").rmdir();s.sym(x,s.c/"bin");s.bad(p=p)
 def test_venv_exe(s):
  vd=s.r/"venv";other=s.r/"other";other.mkdir()
  if os.name!="nt":
   probe=s.r/"probe"
   try:probe.symlink_to(sys.executable)
   except (OSError,NotImplementedError):raise unittest.SkipTest("symlinks unavailable")
   probe.unlink()
  cmd=[sys.executable,"-m","venv","--without-pip"]+(["--symlinks"] if os.name!="nt" else [])+[str(vd)]
  r=subprocess.run(cmd,capture_output=True,text=True,timeout=120)
  s.assertEqual(r.returncode,0,r.stderr[-1000:] or r.stdout[-1000:])
  vp=vd/("Scripts/python.exe" if os.name=="nt" else "bin/python")
  s.assertTrue(vp.exists())
  if os.name!="nt":s.assertTrue(vp.is_symlink())
  rel=os.path.relpath(vp,other);cwd=os.getcwd();s.addCleanup(os.chdir,cwd);os.chdir(other)
  sel=rb._exe(rel,"python")
  s.assertEqual(P(sel).parent.resolve(),(vd/("Scripts" if os.name=="nt" else "bin")).resolve())
  s.assertEqual(P(sel).name,vp.name)
  o=subprocess.run([sel,"-c","import sys;print(sys.prefix)"],cwd=other,capture_output=True,text=True,timeout=30)
  s.assertEqual(o.returncode,0,o.stderr)
  s.assertEqual(P(o.stdout.strip()).resolve(),vd.resolve())
 def fake(s,calls,ver=None,data=None):
  def f(a,cwd=None,env=None,shell=None,timeout=None,capture_output=None):
   calls.append((list(a),cwd,dict(env or {}),shell,timeout,capture_output))
   if len(calls)==1:
    b=P(a[a.index("--prefix")+1])/"node_modules/@taskalong/cli/bin/taskalong.js";b.parent.mkdir(parents=True);b.write_bytes((s.c/"bin/taskalong.js").read_bytes() if data is None else data);return subprocess.CompletedProcess(a,0,b"",b"")
   return subprocess.CompletedProcess(a,0,((ver or rb.EXP)+"\n").encode(),b"")
  return f
 def tools(s):
  d=s.r/"fake";d.mkdir(exist_ok=True);n=("python","node","npm-cli.js")
  for x in n:(d/x).write_text("x")
  s.addCleanup(os.chdir,os.getcwd());os.chdir(s.r)
  return [f"fake/{x}" for x in n],[os.path.abspath(f"fake/{x}") for x in n]
 def test_mock_consumer_synthetic(s):
  rel,res=s.tools();c=[];a0=s.arc()
  with mock.patch.dict(os.environ,{"NPM_CONFIG_REGISTRY":"https://x","NPM_TOKEN":"t","KEEPME":"1"}),mock.patch.object(rb.subprocess,"run",s.fake(c)):
   o=rb.npm_consumer(s.r,a0,rel[0],node=rel[1],npm_cli=rel[2])
  s.assertFalse(o["npm_shim_tested"]);s.assertIn("node installed",o["invocation"]);s.assertEqual(len(c),2)
  a,cwd,env,sh,to,cap=c[0];t=P(cwd);pre=t/"prefix";ca=t/"cache";u=t/"u.npmrc";g=t/"g.npmrc"
  s.assertEqual(a,[res[1],res[2],"install","--prefix",str(pre),"--offline","--ignore-scripts","--no-audit","--no-fund","--no-update-notifier","--no-package-lock","--cache",str(ca),"--userconfig",str(u),"--globalconfig",str(g),str(a0.resolve())])
  s.assertEqual((sh,to,cap),(False,120,True));s.assertFalse(t.resolve().is_relative_to(s.r.resolve()))
  s.assertEqual(env["TASKALONG_PYTHON"],res[0]);s.assertEqual(env["NPM_CONFIG_CACHE"],str(ca));s.assertEqual(env["NPM_CONFIG_USERCONFIG"],str(u));s.assertEqual(env["KEEPME"],"1");s.assertNotIn("NPM_CONFIG_REGISTRY",env);s.assertNotIn("NPM_TOKEN",env)
  s.assertEqual(c[1][0],[res[1],str(pre/"node_modules/@taskalong/cli/bin/taskalong.js"),"--version"])
 def test_mock_wrong_version(s):
  rel,res=s.tools();c=[]
  with mock.patch.object(rb.subprocess,"run",s.fake(c,"wrong")):s.assertRaises(rb.ReleaseError,rb.npm_consumer,s.r,s.arc(),rel[0],node=rel[1],npm_cli=rel[2])
  s.assertEqual(len(c),2)
 def test_mock_installed_bin_mismatch(s):
  good=(s.c/"bin/taskalong.js").read_bytes();same=bytes([good[0]^1])+good[1:];a=s.arc()
  for data in (good+b"x",good[:-1],same):
   rel,res=s.tools();c=[]
   with mock.patch.object(rb.subprocess,"run",s.fake(c,data=data)):s.assertRaises(rb.ReleaseError,rb.npm_consumer,s.r,a,rel[0],node=rel[1],npm_cli=rel[2])
   s.assertEqual(len(c),1)
if __name__=="__main__":unittest.main()
