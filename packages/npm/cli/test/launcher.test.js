'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { constants } = require('node:os');
const { main, pythonVersionFromNpm, expectedPythonVersion, resolvePython, buildPythonCode } = require('../bin/taskalong.js');
const pkg = { version: '1.2.3-rc.1' };
function run(result, opts = {}, argv = []) {
  const calls = []; const seen = { err: '' };
  const st = main(argv, { packageJson: pkg, env: {}, platform: 'linux', writeStderr: (s) => { seen.err += s; }, spawnSync: (...a) => { calls.push(a); if (result instanceof Error) throw result; return result; }, ...opts });
  return { st, calls, err: seen.err };
}
test('synthetic version mapping and boundaries', () => {
  const M = '9007199254740991'; const O = '9007199254740992';
  for (const [a, b] of [['0.0.0', '0.0.0'], ['1.2.3', '1.2.3'], ['1.2.3-alpha.1', '1.2.3a1'], ['1.2.3-beta.2', '1.2.3b2'], ['1.2.3-rc.3', '1.2.3rc3'], [`${M}.0.0`, `${M}.0.0`], [`1.2.3-rc.${M}`, `1.2.3rc${M}`]]) assert.equal(pythonVersionFromNpm(a), b);
  assert.equal(pythonVersionFromNpm(`${M}.${M}.${M}-rc.999999999999`).length, 64);
  for (const v of ['', '1.2', '01.2.3', '1.02.3', '1.2.03', '1.2.3-dev.1', '1.2.3-alpha.0', '1.2.3-alpha.01', '1.2.3-alpha', '1.2.3+1', `${O}.0.0`, `0.${O}.0`, `0.0.${O}`, `1.2.3-rc.${O}`, `${M}.${M}.${M}-rc.${M}`, null, 1]) assert.throws(() => pythonVersionFromNpm(v), /unsupported/);
});
test('synthetic metadata, selection, generated-code version', () => {
  assert.equal(expectedPythonVersion({ version: '1.2.3-beta.2' }), '1.2.3b2');
  assert.equal(expectedPythonVersion({ version: '1.2.3-beta.2', taskalong: { pythonVersion: '1.2.3b2' } }), '1.2.3b2');
  for (const p of [null, {}, { version: 'x' }, { version: '1.2.3', taskalong: { pythonVersion: '1.2.4' } }]) assert.throws(() => expectedPythonVersion(p));
  const lit = '/syn thetic/$(x);`y`/python';
  assert.equal(resolvePython({ TASKALONG_PYTHON: lit }, 'win32'), lit);
  assert.equal(resolvePython({}, 'win32'), 'python');
  assert.equal(resolvePython({}, 'linux'), 'python3');
  for (const v of ['1.2.3a0', '01.2.3', '1.2.3-rc.1', '1.2.3;evil', '']) assert.throws(() => buildPythonCode(v), /invalid Python version/);
});
test('synthetic spawn argv and options', () => {
  const env = { TASKALONG_PYTHON: '/syn thetic/$(x);python', SYNTHETIC: '1' };
  const argv = ['--help', 'a;rm -rf /', '$(x)', 'sp ace', ''];
  const r = run({ status: 7 }, { env }, argv);
  assert.equal(r.st, 7); assert.equal(r.calls.length, 1);
  const [exe, args, opts] = r.calls[0];
  assert.equal(exe, env.TASKALONG_PYTHON);
  assert.deepEqual(args, ['-I', '-c', buildPythonCode('1.2.3rc1'), 'taskalong', ...argv]);
  assert.deepEqual(opts, { shell: false, stdio: 'inherit', env });
  assert.equal(opts.env, env);
  assert.equal(run({ status: 0 }, { platform: 'win32' }).calls[0][0], 'python');
  assert.equal(run({ status: 0 }, { platform: 'darwin' }).calls[0][0], 'python3');
});
test('synthetic exit, errors, signal, invalid metadata', () => {
  assert.equal(run({ status: 0 }).st, 0);
  assert.equal(run({}).st, 1);
  let r = run({ error: Object.assign(new Error('x'), { code: 'ENOENT' }) });
  assert.equal(r.st, 127); assert.match(r.err, /taskalong==1\.2\.3rc1/);
  assert.equal(run({ error: Object.assign(new Error('x'), { code: 'EACCES' }) }).st, 126);
  assert.equal(run(new Error('boom')).st, 127);
  const kills = []; r = run({ signal: 'SIGTERM' }, { kill: (s) => kills.push(s) });
  assert.deepEqual(kills, ['SIGTERM']); assert.equal(r.st, 128 + constants.signals.SIGTERM);
  assert.equal(run({ signal: 'SIGNOPE' }, { kill: () => {} }).st, 1);
  for (const p of [{ version: '1.2.3-alpha.0' }, { version: '1.2.3', taskalong: { pythonVersion: '9.9.9' } }, null]) {
    r = run({ status: 0 }, { packageJson: p }); assert.equal(r.st, 78); assert.equal(r.calls.length, 0); assert.match(r.err, /invalid package metadata/);
  }
});
const PY = `
import sys,tempfile,types,importlib.metadata,importlib.util
from pathlib import Path
class Rec(str):pass
v=sys.argv[1];base=Path(tempfile.gettempdir()).resolve()/'synthetic-taskalong';site=base/'site';o=site/'taskalong'/'__init__.py';files=['taskalong/__init__.py']
if v=='missing':files=None
elif v=='empty':files=[]
elif v=='elsewhere':files=[Rec('taskalong/__init__.py')]
elif v=='arbitrary':o=site/'taskalong'/'arbitrary.py';files=['taskalong/__init__.py','taskalong/arbitrary.py']
elif v=='shadow':o=base/'checkout'/'taskalong'/'__init__.py'
class EP:
 group='console_scripts';name='taskalong';value='taskalong.cli:main'
 def load(self):return lambda:(print('SYNTHETIC_LOADED'),43)[1]
class D:
 version='1.2.3';entry_points=[EP()]
 def __init__(self):self.files=files
 def locate_file(self,p):return base/'elsewhere'/str(p) if isinstance(p,Rec) else site/str(p)
importlib.metadata.distribution=lambda n:D()
importlib.util.find_spec=lambda n:types.SimpleNamespace(origin=str(o))
sys.argv=['taskalong'];exec(compile(${JSON.stringify(buildPythonCode('1.2.3'))},'synthetic','exec'))
`;
test('synthetic Python origin guard', () => {
  const py = process.env.TASKALONG_TEST_PYTHON || (process.platform === 'win32' ? 'python' : 'python3');
  for (const [name, st, hit] of [['good', 43, true], ['missing', 78, false], ['empty', 78, false], ['elsewhere', 78, false], ['arbitrary', 78, false], ['shadow', 78, false]]) {
    const r = spawnSync(py, ['-I', '-c', PY, name], { encoding: 'utf8', timeout: 15000, shell: false });
    assert.equal(r.status, st, `${name}: ${r.stdout || ''} ${r.stderr || ''} ${r.error || ''}`);
    assert.equal((r.stdout || '').includes('SYNTHETIC_LOADED'), hit, name);
    if (!hit) assert.match(r.stderr || '', /incompatible Python runtime/);
  }
});
