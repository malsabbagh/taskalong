import contextlib, importlib.util, io, json, tempfile, unittest
from pathlib import Path

_f = Path(__file__).resolve().parents[1] / 'tools' / 'release_version.py'
_s = importlib.util.spec_from_file_location('release_version', _f)
rv = importlib.util.module_from_spec(_s)
_s.loader.exec_module(rv)

def _ver(v):
  return '__version__=' + repr(v)

class ReleaseVersionTests(unittest.TestCase):
  def make(self, root, v='0.1.0a1', init=None, npm='0.1.0-alpha.1', name='@taskalong/cli', toml=None, pkg=None):
    r = Path(root)
    files = {
      'pyproject.toml': toml if toml is not None else 'project={name="taskalong",version="' + v + '"}',
      'src/taskalong/__init__.py': _ver(v) if init is None else init,
      'packages/npm/cli/package.json': pkg if pkg is not None else json.dumps({'name': name, 'version': npm, 'taskalong': {'pythonVersion': v}}),
    }
    for rel, text in files.items():
      p = r / rel
      p.parent.mkdir(parents=True, exist_ok=True)
      p.write_text(text, encoding='utf-8')
    return r

  def test_mappings(self):
    cases = {'1.2.3': '1.2.3', '0.1.0a1': '0.1.0-alpha.1', '1.0.0b2': '1.0.0-beta.2', '2.3.4rc3': '2.3.4-rc.3', '9007199254740991.0.0': '9007199254740991.0.0', '0.9007199254740991.0': '0.9007199254740991.0', '0.0.9007199254740991': '0.0.9007199254740991', '1.2.3a9007199254740991': '1.2.3-alpha.9007199254740991'}
    for v, npm in cases.items():
      with self.subTest(v=v):
        self.assertEqual(rv.release_versions(v), {'python': v, 'npm': npm, 'tag': 'v' + v})

  def test_invalid_versions(self):
    bad = ['', 'v1.2.3', ' 1.2.3', '1.2.3 ', '1.2', '1.2.3.4', '01.2.3', '1.02.3', '1.2.03', '1.2.3a0', '1.2.3a01', '1.2.3a', '1.2.3c1', '1.2.3-alpha.1', '1.2.3+local', '1.2.3.post1', '1.2.3.dev1', '1!1.2.3', '1.2.3é', '9' * 61 + '.2.3', '9007199254740992.0.0', '0.9007199254740992.0', '0.0.9007199254740992', '1.2.3a9007199254740992', None, True, 1, 1.2, b'1.2.3', [], {}]
    for v in bad:
      with self.subTest(v=repr(v)), self.assertRaises(ValueError):
        rv.release_versions(v)

  def test_valid_snapshot(self):
    with tempfile.TemporaryDirectory() as d:
      r = self.make(d)
      want = {'python': '0.1.0a1', 'npm': '0.1.0-alpha.1', 'tag': 'v0.1.0a1'}
      self.assertEqual(rv.check_tree(r, 'v0.1.0a1'), want)
      self.assertEqual(rv.check_tree(str(r), 'v0.1.0a1'), want)

  def test_bad_trees(self):
    bad = [
      {'v': '1.2'}, {'init': _ver('0.1.0a2')}, {'npm': '0.1.0a1'}, {'name': 'taskalong'},
      {'pkg': '{"name":"@taskalong/cli","version":"0.1.0-alpha.1","version":"9.9.9"}'},
      {'init': _ver('0.1.0a1') + ';' + _ver('0.1.0a1')}, {'init': '__version__=get_version()'},
      {'init': '__version__=('}, {'toml': 'project={'}, {'toml': 'project={}'}, {'pkg': '{'},
    ]
    with tempfile.TemporaryDirectory() as d:
      for kw in bad:
        with self.subTest(kw=kw), self.assertRaises(ValueError):
          rv.check_tree(self.make(d, **kw), 'v0.1.0a1')
      for tag in ['0.1.0a1', 'v0.1.0-alpha.1', 'v0.1.0a2']:
        with self.subTest(tag=tag), self.assertRaises(ValueError):
          rv.check_tree(self.make(d), tag)

  def test_missing_and_oversized(self):
    big = 1024 * 1024
    cases = [('pyproject.toml', b' #' + b'x' * big), ('src/taskalong/__init__.py', b' #' + b'x' * big), ('packages/npm/cli/package.json', b' ' * (big + 1))]
    with tempfile.TemporaryDirectory() as d:
      r = self.make(d)
      def bad():
        with self.assertRaises(ValueError):
          rv.check_tree(r, 'v0.1.0a1')
      for rel, pad in cases:
        with self.subTest(rel=rel):
          self.make(d); (r / rel).unlink(); bad()
          self.make(d); p = r / rel; p.write_bytes(p.read_bytes() + pad); bad()

  def test_init_not_executed(self):
    with tempfile.TemporaryDirectory() as d:
      sentinel = Path(d) / 'pwned.txt'
      init = _ver('0.1.0a1') + f';open({str(sentinel)!r},"w").write("x");raise SystemExit(9)'
      r = self.make(d, init=init)
      self.assertEqual(rv.check_tree(r, 'v0.1.0a1')['python'], '0.1.0a1')
      self.assertFalse(sentinel.exists())

  def test_regressions(self):
    h = '{"name":"@taskalong/cli","version":"0.1.0-alpha.1","taskalong":{"pythonVersion":"0.1.0a1"},"x":'
    ts = ('NaN', 'Infinity', '-Infinity')
    bad = [h + t + '}' for t in ts] + [h + '{"y":[' + t + ']}}' for t in ts]
    b = {'name': '@taskalong/cli', 'version': '0.1.0-alpha.1', 'taskalong': {'pythonVersion': '0.1.0a1'}}
    bad += [json.dumps(dict(b, taskalong=m)) for m in (None, 1, 'x', [], {}, {'pythonVersion': '0.1.0a2'}, {'pythonVersion': 1})]
    p = dict(b); del p['taskalong']; bad.append(json.dumps(p))
    with tempfile.TemporaryDirectory() as d:
      for pkg in bad:
        with self.subTest(pkg=pkg), self.assertRaises(ValueError):
          rv.check_tree(self.make(d, pkg=pkg), 'v0.1.0a1')
      deeps = [{'toml': 'project={name="taskalong",version="0.1.0a1"}\nx=' + '[' * 2000 + ']' * 2000}, {'pkg': h + '[' * 2000 + ']' * 2000 + '}'}, {'init': _ver('0.1.0a1') + '\nx=' + '(' * 2000 + '1' + ')' * 2000}]
      for kw in deeps:
        with self.subTest(kw=list(kw)):
          try:
            self.assertEqual(rv.check_tree(self.make(d, **kw), 'v0.1.0a1')['python'], '0.1.0a1')
          except ValueError:
            pass
      r = self.make(d, toml='project={')
      e = io.StringIO()
      with contextlib.redirect_stderr(e):
        self.assertEqual(rv.main(['--root', str(r), '--tag', 'v0.1.0a1']), 1)
      self.assertTrue(e.getvalue().startswith('error: '))
      self.assertNotIn('Traceback', e.getvalue())

if __name__ == '__main__':
  unittest.main()
