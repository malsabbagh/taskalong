'''Pure deterministic candidate-manifest planning validator.

A valid result is only a declaration/planning object built from unverified
caller declarations. It is NEVER proof that CI was fetched or authenticated,
that source or artifacts are genuine, or that publication or tag creation is
allowed. A later integration must fetch and recheck external identities,
actual source and artifacts, signatures, and environments before gating any
future publication. This module performs no network, subprocess, file-write,
signing, credential, publisher, or tag operation.
'''
import hashlib
import json
import math
import re

try:
    from release_version import release_versions
except ImportError:
    try:
        from tools.release_version import release_versions
    except ImportError:
        import importlib.util
        from pathlib import Path
        _spec = importlib.util.spec_from_file_location(
            'release_version', Path(__file__).with_name('release_version.py'))
        _module = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_module)
        release_versions = _module.release_versions


class ManifestError(ValueError):
    pass


_REPO = 'malsabbagh/taskalong'
_VERSIONS = {'python': '0.1.0a1', 'npm': '0.1.0-alpha.1', 'tag': 'v0.1.0a1'}
_MAX_INT = 2 ** 53 - 1
_MAX_MANIFEST = 1024 * 1024
_HEX40 = re.compile('[0-9a-f]{40}')
_HEX64 = re.compile('[0-9a-f]{64}')
_ARTIFACT_DIGEST = re.compile('sha256:[0-9a-f]{64}')
_SOURCE_KEYS = frozenset(('repository', 'sha', 'tree'))
_RUN_KEYS = frozenset(('id', 'attempt', 'repository', 'workflow', 'event', 'ref',
                       'head_sha', 'status', 'conclusion', 'jobs'))
_JOB_KEYS = frozenset(('id', 'name', 'run_id', 'attempt', 'status', 'conclusion'))
_ARTIFACT_KEYS = frozenset(('filename', 'sha256', 'bytes', 'source_sha', 'run_id',
                            'attempt', 'artifact_id', 'artifact_digest'))
_CORE_JOBS = (
    'producer / ubuntu-24.04 / Python 3.14',
    'producer / macos-15 / Python 3.14',
    'installed shard / ubuntu-24.04 / Python 3.14 / wheel-core',
    'installed shard / ubuntu-24.04 / Python 3.14 / sdist',
    'installed shard / macos-15 / Python 3.14 / wheel-core',
    'installed shard / macos-15 / Python 3.14 / sdist',
    'Windows portable package contracts',
    'Complete qualification',
)
_DISTRIBUTION_JOBS = (
    'distribution / ubuntu-24.04 / Python 3.14 / Node 24',
    'distribution / macos-15 / Python 3.14 / Node 24',
    'distribution / windows-2022 / Python 3.14 / Node 24',
)
_WHEEL = 'taskalong-0.1.0a1-py3-none-any.whl'
_SDIST = 'taskalong-0.1.0a1.tar.gz'
_NPM = 'taskalong-cli-0.1.0-alpha.1.tgz'
_ARTIFACT_LIMITS = {_WHEEL: 64 * 1024 * 1024, _SDIST: 64 * 1024 * 1024,
                    _NPM: 1024 * 1024}


def _json_check(value, seen):
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ManifestError('JSON numbers must be finite')
        return
    if isinstance(value, (list, tuple, dict)):
        marker = id(value)
        if marker in seen:
            raise ManifestError('JSON value must not be circular')
        seen.add(marker)
        try:
            if isinstance(value, dict):
                for key, item in value.items():
                    if not isinstance(key, str):
                        raise ManifestError('JSON object keys must be strings')
                    _json_check(item, seen)
            else:
                for item in value:
                    _json_check(item, seen)
        finally:
            seen.remove(marker)
        return
    raise ManifestError('unsupported JSON value')


def manifest_bytes(value):
    try:
        _json_check(value, set())
        data = json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False).encode('utf-8')
    except ManifestError:
        raise
    except (TypeError, ValueError, RecursionError, UnicodeEncodeError):
        raise ManifestError('unsupported or non-finite JSON value') from None
    if len(data) > _MAX_MANIFEST:
        raise ManifestError('manifest exceeds 1 MiB')
    return data


def _closed(value, keys, label):
    if not isinstance(value, dict) or set(value) != keys:
        raise ManifestError(label + ' must have exactly the required keys')
    return value


def _pos_int(value, label, limit=_MAX_INT):
    if type(value) is not int or not 1 <= value <= limit:
        raise ManifestError(label + ' must be a positive bounded exact int')
    return value


def _equal(value, expected, label):
    if type(value) is not str or value != expected:
        raise ManifestError(label + ' mismatch')
    return value


def _hex(value, pattern, label):
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise ManifestError(label + ' must be a lowercase hex digest')
    return value


def _run(value, label, workflow, job_names, source_sha):
    _closed(value, _RUN_KEYS, label)
    run_id = _pos_int(value['id'], label + '.id')
    attempt = _pos_int(value['attempt'], label + '.attempt')
    result = {
        'id': run_id,
        'attempt': attempt,
        'repository': _equal(value['repository'], _REPO, label + '.repository'),
        'workflow': _equal(value['workflow'], workflow, label + '.workflow'),
        'event': _equal(value['event'], 'push', label + '.event'),
        'ref': _equal(value['ref'], 'refs/heads/main', label + '.ref'),
        'head_sha': _equal(value['head_sha'], source_sha, label + '.head_sha'),
        'status': _equal(value['status'], 'completed', label + '.status'),
        'conclusion': _equal(value['conclusion'], 'success', label + '.conclusion'),
    }
    jobs = value['jobs']
    if not isinstance(jobs, list) or len(jobs) != len(job_names):
        raise ManifestError(label + '.jobs must contain exactly the required jobs')
    expected = set(job_names)
    names = set()
    job_ids = set()
    normalized = []
    for job in jobs:
        _closed(job, _JOB_KEYS, label + ' job')
        name = job['name']
        if type(name) is not str or name not in expected or name in names:
            raise ManifestError(label + '.jobs has a missing, extra, or duplicate job')
        names.add(name)
        job_id = _pos_int(job['id'], label + ' job.id')
        if job_id in job_ids:
            raise ManifestError('job ids must be unique')
        job_ids.add(job_id)
        if _pos_int(job['run_id'], label + ' job.run_id') != run_id:
            raise ManifestError(label + ' job.run_id mismatch')
        if _pos_int(job['attempt'], label + ' job.attempt') != attempt:
            raise ManifestError(label + ' job.attempt mismatch')
        normalized.append({
            'id': job_id,
            'name': name,
            'run_id': run_id,
            'attempt': attempt,
            'status': _equal(job['status'], 'completed', label + ' job.status'),
            'conclusion': _equal(job['conclusion'], 'success', label + ' job.conclusion'),
        })
    if names != expected:
        raise ManifestError(label + '.jobs must contain exactly the required jobs')
    normalized.sort(key=lambda item: item['name'])
    result['jobs'] = normalized
    return result, job_ids


def _artifacts(value, source_sha, core):
    if not isinstance(value, list) or len(value) != len(_ARTIFACT_LIMITS):
        raise ManifestError('artifacts must contain exactly three artifacts')
    seen = set()
    normalized = []
    for record in value:
        _closed(record, _ARTIFACT_KEYS, 'artifact')
        filename = record['filename']
        if type(filename) is not str or filename not in _ARTIFACT_LIMITS or filename in seen:
            raise ManifestError('artifacts must be exactly the required filenames')
        seen.add(filename)
        normalized.append({
            'filename': filename,
            'sha256': _hex(record['sha256'], _HEX64, 'artifact.sha256'),
            'bytes': _pos_int(record['bytes'], 'artifact.bytes', _ARTIFACT_LIMITS[filename]),
            'source_sha': _equal(record['source_sha'], source_sha, 'artifact.source_sha'),
            'run_id': _pos_int(record['run_id'], 'artifact.run_id'),
            'attempt': _pos_int(record['attempt'], 'artifact.attempt'),
            'artifact_id': _pos_int(record['artifact_id'], 'artifact.artifact_id'),
            'artifact_digest': _hex(record['artifact_digest'], _ARTIFACT_DIGEST,
                                    'artifact.artifact_digest'),
        })
    if seen != set(_ARTIFACT_LIMITS):
        raise ManifestError('artifacts must be exactly the required filenames')
    normalized.sort(key=lambda item: item['filename'])
    by_name = {item['filename']: item for item in normalized}
    wheel = by_name[_WHEEL]
    sdist = by_name[_SDIST]
    if wheel['artifact_id'] != sdist['artifact_id']:
        raise ManifestError('Python artifacts must bind the same artifact_id')
    for item in (wheel, sdist):
        if item['run_id'] != core['id'] or item['attempt'] != core['attempt']:
            raise ManifestError('Python artifacts must bind the core run and attempt')
    return normalized


def plan_candidate(*, version, source, core, distribution, artifacts):
    try:
        versions = release_versions(version)
    except Exception:
        raise ManifestError('invalid version') from None
    if versions != _VERSIONS:
        raise ManifestError('only the 0.1.0a1 candidate is supported')
    _closed(source, _SOURCE_KEYS, 'source')
    source_out = {
        'repository': _equal(source['repository'], _REPO, 'source.repository'),
        'sha': _hex(source['sha'], _HEX40, 'source.sha'),
        'tree': _hex(source['tree'], _HEX40, 'source.tree'),
    }
    core_out, core_job_ids = _run(core, 'core', '.github/workflows/ci.yml',
                                  _CORE_JOBS, source_out['sha'])
    distribution_out, distribution_job_ids = _run(
        distribution, 'distribution', '.github/workflows/npm-consumer.yml',
        _DISTRIBUTION_JOBS, source_out['sha'])
    if core_out['id'] == distribution_out['id']:
        raise ManifestError('core and distribution run ids must differ')
    if core_job_ids & distribution_job_ids:
        raise ManifestError('job ids must be unique across both runs')
    result = {
        'format': 'taskalong-release-manifest/1',
        'versions': dict(_VERSIONS),
        'source': source_out,
        'core': core_out,
        'distribution': distribution_out,
        'artifacts': _artifacts(artifacts, source_out['sha'], core_out),
        'evidence_provenance': 'unverified_input_declarations',
        'publication_allowed': False,
        'tag_creation_allowed': False,
    }
    result['digest'] = hashlib.sha256(manifest_bytes(result)).hexdigest()
    manifest_bytes(result)
    return result
