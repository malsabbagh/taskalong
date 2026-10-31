# Pure source check; not proof of signed source, CI, or registry trust.
import argparse, ast, json, re, sys, tomllib
from pathlib import Path

_MAX = 1024 * 1024
_RE = re.compile('(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(?:(a|b|rc)([1-9][0-9]*))?')
_PRE = {'a': 'alpha', 'b': 'beta', 'rc': 'rc'}
_MSG = 'invalid version (ASCII X.Y.Z[a|b|rcN], <=64 bytes)'

def release_versions(value):
  if not isinstance(value, str):
    raise ValueError('version must be a string')
  try:
    size = len(value.encode('ascii'))
  except UnicodeEncodeError:
    raise ValueError(_MSG) from None
  m = _RE.fullmatch(value) if size <= 64 else None
  if m is None:
    raise ValueError(_MSG)
  base = '.'.join(m.groups()[:3])
  npm = base if m.group(4) is None else f'{base}-{_PRE[m.group(4)]}.{m.group(5)}'
  return {'python': value, 'npm': npm, 'tag': 'v' + value}

def _read(root, rel):
  try:
    with (root / rel).open('rb') as f:
      data = f.read(_MAX + 1)
  except FileNotFoundError:
    raise ValueError(f'missing {rel}') from None
  except OSError as e:
    raise ValueError(f'unreadable {rel}: {e.strerror or e}') from None
  if len(data) > _MAX:
    raise ValueError(f'{rel} exceeds 1 MiB')
  return data

def _init_version(data):
  try:
    tree = ast.parse(data)
  except (SyntaxError, ValueError) as e:
    raise ValueError(f'invalid src/taskalong/__init__.py: {e}') from None
  found = []
  for n in ast.walk(tree):
    ts = n.targets if isinstance(n, ast.Assign) else [n.target] if isinstance(n, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)) else []
    if any(isinstance(x, ast.Name) and x.id == '__version__' for t in ts for x in ast.walk(t)):
      found.append(n)
  if len(found) != 1:
    raise ValueError('need exactly one __version__ assignment in __init__.py')
  n = found[0]
  if not (n in tree.body and isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
      and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)):
    raise ValueError('__version__ must be a plain literal string')
  return n.value.value

def _pairs(pairs):
  out = {}
  for k, v in pairs:
    if k in out:
      raise ValueError(f'duplicate package.json key: {k!r}')
    out[k] = v
  return out

def check_tree(root, tag):
  if not isinstance(tag, str):
    raise ValueError('tag must be a string')
  try:
    root = Path(root)
  except (TypeError, ValueError):
    raise ValueError('root must be a path') from None
  try:
    doc = tomllib.loads(_read(root, 'pyproject.toml').decode())
  except (UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
    raise ValueError(f'invalid pyproject.toml: {e}') from None
  proj = doc.get('project')
  if not isinstance(proj, dict) or 'version' not in proj:
    raise ValueError('pyproject.toml missing project.version')
  try:
    v = release_versions(proj['version'])
  except ValueError as e:
    raise ValueError(f'pyproject.toml project.version: {e}') from None
  py, npm, want = v['python'], v['npm'], v['tag']
  if tag != want:
    raise ValueError(f'tag: expected {want}, got {tag!r}')
  init = _init_version(_read(root, 'src/taskalong/__init__.py'))
  if init != py:
    raise ValueError(f'__version__: expected {py}, got {init!r}')
  try:
    pkg = json.loads(_read(root, 'packages/npm/cli/package.json').decode(), object_pairs_hook=_pairs)
  except (UnicodeDecodeError, json.JSONDecodeError) as e:
    raise ValueError(f'invalid package.json: {e}') from None
  if not isinstance(pkg, dict):
    raise ValueError('package.json must be an object')
  name, pver = pkg.get('name'), pkg.get('version')
  if name != '@taskalong/cli':
    raise ValueError(f'package.json name: expected @taskalong/cli, got {name!r}')
  if pver != npm:
    raise ValueError(f'package.json version: expected {npm}, got {pver!r}')
  return v

def main(argv=None):
  p = argparse.ArgumentParser()
  p.add_argument('--root', required=True)
  p.add_argument('--tag', required=True)
  a = p.parse_args(argv)
  try:
    r = check_tree(a.root, a.tag)
  except ValueError as e:
    print(f'error: {e}', file=sys.stderr)
    return 1
  print(json.dumps(r, sort_keys=True, separators=(',', ':')))
  return 0

if __name__ == '__main__':
  raise SystemExit(main())
