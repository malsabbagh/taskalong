#!/usr/bin/env node
'use strict';

const { spawnSync } = require('node:child_process');
const { constants } = require('node:os');

const NPM_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(alpha|beta|rc)\.(0|[1-9]\d*))?$/;

function pythonVersionFromNpm(version) {
  const m = typeof version === 'string' && NPM_RE.exec(version);
  if (!m) throw new Error('unsupported npm package version');
  return `${m[1]}.${m[2]}.${m[3]}${m[4] ? { alpha: 'a', beta: 'b', rc: 'rc' }[m[4]] + m[5] : ''}`;
}

function expectedPythonVersion(pkg) {
  if (!pkg) throw new Error('missing package metadata');
  const mapped = pythonVersionFromNpm(pkg.version);
  const literal = pkg.taskalong && pkg.taskalong.pythonVersion;
  if (literal !== undefined && literal !== mapped) throw new Error('conflicting version metadata');
  return mapped;
}

function resolvePython(env = process.env, platform = process.platform) {
  return (env && env.TASKALONG_PYTHON) || (platform === 'win32' ? 'python' : 'python3');
}

function buildPythonCode(expected) {
  if (!/^\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?$/.test(expected || '')) throw new Error('invalid Python version');
  return `import sys
import importlib.metadata
import importlib.util
from pathlib import Path
EXPECTED = ${JSON.stringify(expected)}
def fail(msg):
    print(f'taskalong: incompatible Python runtime: {msg}', file=sys.stderr)
    print(f'Install Python >=3.11,<3.15 and run: python -m pip install "taskalong=={EXPECTED}"', file=sys.stderr)
    print('Or set TASKALONG_PYTHON to one Python executable with that runtime.', file=sys.stderr)
    raise SystemExit(78)
if not (3, 11) <= sys.version_info[:2] < (3, 15):
    fail(f'Python {sys.version_info.major}.{sys.version_info.minor} unsupported; need >=3.11,<3.15')
try:
    dist = importlib.metadata.distribution('taskalong')
    if dist.version != EXPECTED:
        fail(f'found taskalong {dist.version}, need exactly {EXPECTED}')
    eps = [e for e in dist.entry_points if e.group == 'console_scripts' and e.name == 'taskalong']
    if len(eps) != 1 or eps[0].value != 'taskalong.cli:main':
        fail('need exactly one console entry point taskalong=taskalong.cli:main')
    spec = importlib.util.find_spec('taskalong')
    if spec is None or not spec.origin:
        fail('installed taskalong package not locatable')
    origin = Path(spec.origin).resolve()
    root = Path(dist.locate_file('taskalong')).resolve()
    files = {Path(dist.locate_file(f)).resolve() for f in dist.files or []}
    if origin not in files and origin.parent != root:
        fail('taskalong location does not match its installed distribution')
except SystemExit:
    raise
except importlib.metadata.PackageNotFoundError:
    fail(f'taskalong {EXPECTED} not installed for the selected Python')
except Exception as exc:
    fail(f'validation failed ({type(exc).__name__})')
sys.argv = sys.argv[1:] if len(sys.argv) > 1 else ['taskalong']
raise SystemExit(eps[0].load()())`;
}

function hint(write, expected, reason) {
  write(`taskalong: ${reason}\n`);
  write(`Install Python >=3.11,<3.15 and run: python -m pip install "taskalong==${expected}"\n`);
  write('Or set TASKALONG_PYTHON to one Python executable with that runtime.\n');
}

function main(argv, options) {
  const opts = options || {};
  const args = argv === undefined ? process.argv.slice(2) : [].concat(argv);
  const env = opts.env === undefined ? process.env : opts.env;
  const write = opts.writeStderr || ((s) => process.stderr.write(s));
  let expected;
  try {
    expected = expectedPythonVersion(opts.packageJson === undefined ? require('../package.json') : opts.packageJson);
  } catch {
    write('taskalong: invalid package metadata; refusing to guess the Python runtime version.\nReinstall @taskalong/cli.\n');
    return 78;
  }
  let result;
  try {
    // -I isolates Python config; it cannot make an untrusted interpreter safe.
    result = (opts.spawnSync || spawnSync)(
      resolvePython(env, opts.platform || process.platform),
      ['-I', '-c', buildPythonCode(expected), 'taskalong', ...args],
      { shell: false, stdio: 'inherit', env },
    );
  } catch {
    hint(write, expected, 'could not start the selected Python interpreter.');
    return 127;
  }
  if (!result || result.error) {
    hint(write, expected, 'could not start the selected Python interpreter.');
    return result && result.error && result.error.code === 'EACCES' ? 126 : 127;
  }
  if (result.signal) {
    try { (opts.kill || ((s) => process.kill(process.pid, s)))(result.signal); } catch {}
    const signo = constants.signals[result.signal];
    return signo ? 128 + signo : 1;
  }
  return Number.isInteger(result.status) ? result.status : 1;
}

module.exports = { main, pythonVersionFromNpm, expectedPythonVersion, resolvePython, buildPythonCode };

if (require.main === module) process.exitCode = main();
