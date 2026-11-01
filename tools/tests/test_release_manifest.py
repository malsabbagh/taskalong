'''Synthetic tests only; they do not qualify or authenticate a live release.'''
import copy
import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from release_manifest import ManifestError, manifest_bytes, plan_candidate

SHA = 'a' * 40
TREE = 'b' * 40
H64 = 'c' * 64
CORE_JOBS = (
    'producer / ubuntu-24.04 / Python 3.14',
    'producer / macos-15 / Python 3.14',
    'installed shard / ubuntu-24.04 / Python 3.14 / wheel-core',
    'installed shard / ubuntu-24.04 / Python 3.14 / sdist',
    'installed shard / macos-15 / Python 3.14 / wheel-core',
    'installed shard / macos-15 / Python 3.14 / sdist',
    'Windows portable package contracts',
    'Complete qualification',
)
DIST_JOBS = (
    'distribution / ubuntu-24.04 / Python 3.14 / Node 24',
    'distribution / macos-15 / Python 3.14 / Node 24',
    'distribution / windows-2022 / Python 3.14 / Node 24',
)


def _run(run_id, attempt, workflow, names, start):
    return {
        'id': run_id, 'attempt': attempt, 'repository': 'malsabbagh/taskalong',
        'workflow': workflow, 'event': 'push', 'ref': 'refs/heads/main',
        'head_sha': SHA, 'status': 'completed', 'conclusion': 'success',
        'jobs': [{'id': start + i, 'name': name, 'run_id': run_id,
                  'attempt': attempt, 'status': 'completed',
                  'conclusion': 'success'} for i, name in enumerate(names)],
    }


def _artifact(filename, size, run_id, attempt, artifact_id):
    return {'filename': filename, 'sha256': H64, 'bytes': size, 'source_sha': SHA,
            'run_id': run_id, 'attempt': attempt, 'artifact_id': artifact_id,
            'artifact_digest': 'sha256:' + 'd' * 64}


def _kwargs():
    return {
        'version': '0.1.0a1',
        'source': {'repository': 'malsabbagh/taskalong', 'sha': SHA, 'tree': TREE},
        'core': _run(101, 2, '.github/workflows/ci.yml', CORE_JOBS, 1000),
        'distribution': _run(202, 3, '.github/workflows/npm-consumer.yml', DIST_JOBS, 2000),
        'artifacts': [
            _artifact('taskalong-cli-0.1.0-alpha.1.tgz', 10, 303, 1, 900),
            _artifact('taskalong-0.1.0a1.tar.gz', 20, 101, 2, 500),
            _artifact('taskalong-0.1.0a1-py3-none-any.whl', 30, 101, 2, 500),
        ],
    }


class ReleaseManifestTests(unittest.TestCase):
    def assert_bad(self, mutate):
        data = _kwargs()
        mutate(data)
        with self.assertRaises(ManifestError):
            plan_candidate(**data)

    def test_valid_candidate_has_no_authority(self):
        result = plan_candidate(**_kwargs())
        self.assertEqual(result['format'], 'taskalong-release-manifest/1')
        self.assertEqual(result['versions'], {'python': '0.1.0a1', 'npm': '0.1.0-alpha.1', 'tag': 'v0.1.0a1'})
        self.assertEqual(result['evidence_provenance'], 'unverified_input_declarations')
        self.assertIs(result['publication_allowed'], False)
        self.assertIs(result['tag_creation_allowed'], False)
        self.assertEqual([j['name'] for j in result['core']['jobs']], sorted(CORE_JOBS))
        self.assertEqual([j['name'] for j in result['distribution']['jobs']], sorted(DIST_JOBS))
        names = [a['filename'] for a in result['artifacts']]
        self.assertEqual(names, sorted(names))
        payload = dict(result)
        digest = payload.pop('digest')
        self.assertEqual(digest, hashlib.sha256(manifest_bytes(payload)).hexdigest())
        self.assertLessEqual(len(manifest_bytes(result)), 1024 * 1024)

    def test_deterministic_reordering_and_detachment(self):
        first = _kwargs()
        second = _kwargs()
        second['core']['jobs'].reverse()
        second['distribution']['jobs'].reverse()
        second['artifacts'].reverse()
        left = plan_candidate(**first)
        right = plan_candidate(**second)
        self.assertEqual(left, right)
        self.assertEqual(manifest_bytes(left), manifest_bytes(right))
        first['source']['sha'] = 'f' * 40
        first['core']['jobs'][0]['name'] = 'mutated'
        first['artifacts'][0]['bytes'] = 999
        self.assertEqual(left, right)

    def test_manifest_bytes_canonical_and_strict(self):
        self.assertEqual(manifest_bytes({'b': 1, 'a': [True, None]}), b'{\"a\":[true,null],\"b\":1}')
        bad = (float('nan'), float('inf'), {'x': object()}, {'x': {1, 2}}, {1: 'x'}, b'x', 'x' * (1024 * 1024))
        for value in bad:
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(ManifestError):
                    manifest_bytes(value)

    def test_closed_shapes_reject_unknown_and_missing_keys(self):
        mutations = (
            lambda d: d['source'].__setitem__('extra', 1),
            lambda d: d['core'].__setitem__('extra', 1),
            lambda d: d['distribution'].__setitem__('digest', 'x'),
            lambda d: d['core']['jobs'][0].__setitem__('extra', 1),
            lambda d: d['artifacts'][0].__setitem__('path', 'dist/x'),
            lambda d: d['source'].pop('tree'),
            lambda d: d['core'].pop('jobs'),
            lambda d: d['distribution'].pop('status'),
            lambda d: d['distribution']['jobs'][0].pop('id'),
            lambda d: d['artifacts'][0].pop('sha256'),
        )
        for i, mutate in enumerate(mutations):
            with self.subTest(case=i):
                self.assert_bad(mutate)

    def test_source_version_and_run_mismatches(self):
        mutations = (
            lambda d: d.__setitem__('version', '0.1.0a2'),
            lambda d: d.__setitem__('version', '0.1.0'),
            lambda d: d.__setitem__('version', 'v0.1.0a1'),
            lambda d: d.__setitem__('version', 1),
            lambda d: d['source'].__setitem__('repository', 'other/taskalong'),
            lambda d: d['source'].__setitem__('sha', 'A' * 40),
            lambda d: d['source'].__setitem__('sha', 'a' * 39),
            lambda d: d['source'].__setitem__('tree', 'g' * 40),
            lambda d: d['core'].__setitem__('repository', 'other/taskalong'),
            lambda d: d['distribution'].__setitem__('repository', 'malsabbagh/other'),
            lambda d: d['core'].__setitem__('workflow', '.github/workflows/npm-consumer.yml'),
            lambda d: d['distribution'].__setitem__('workflow', '.github/workflows/ci.yml'),
            lambda d: d['core'].__setitem__('event', 'pull_request'),
            lambda d: d['distribution'].__setitem__('ref', 'refs/tags/v0.1.0a1'),
            lambda d: d['core'].__setitem__('head_sha', 'f' * 40),
            lambda d: d['distribution'].__setitem__('status', 'in_progress'),
            lambda d: d['core'].__setitem__('conclusion', 'failure'),
            lambda d: d['core']['jobs'][0].__setitem__('run_id', 999),
            lambda d: d['core']['jobs'][0].__setitem__('attempt', 999),
            lambda d: d['distribution']['jobs'][0].__setitem__('status', 'queued'),
            lambda d: d['distribution']['jobs'][0].__setitem__('conclusion', 'cancelled'),
        )
        for i, mutate in enumerate(mutations):
            with self.subTest(case=i):
                self.assert_bad(mutate)
        def same_run(data):
            data['distribution']['id'] = data['core']['id']
            for job in data['distribution']['jobs']:
                job['run_id'] = data['core']['id']
        self.assert_bad(same_run)

    def test_exact_bounded_integers(self):
        for value in (True, 0, -1, 2 ** 53, 1.0, '1', None):
            with self.subTest(value=repr(value)):
                data = _kwargs()
                data['artifacts'][0]['bytes'] = value
                with self.assertRaises(ManifestError):
                    plan_candidate(**data)
        mutations = (
            lambda d: d['core'].__setitem__('id', True),
            lambda d: d['core'].__setitem__('attempt', 0),
            lambda d: d['distribution']['jobs'][0].__setitem__('id', -1),
            lambda d: d['artifacts'][0].__setitem__('artifact_id', 2 ** 53),
            lambda d: d['artifacts'][0].__setitem__('attempt', False),
        )
        for i, mutate in enumerate(mutations):
            with self.subTest(case=i):
                self.assert_bad(mutate)

    def test_jobs_and_artifacts_structure(self):
        mutations = (
            lambda d: d['core']['jobs'].pop(),
            lambda d: d['distribution']['jobs'].pop(),
            lambda d: d['core']['jobs'].append(copy.deepcopy(d['core']['jobs'][0])),
            lambda d: d['core']['jobs'][1].__setitem__('name', d['core']['jobs'][0]['name']),
            lambda d: d['core']['jobs'][0].__setitem__('name', 'foreign job'),
            lambda d: d['distribution']['jobs'][0].__setitem__('id', d['core']['jobs'][0]['id']),
            lambda d: d['core']['jobs'][1].__setitem__('id', d['core']['jobs'][0]['id']),
            lambda d: d['artifacts'].pop(),
            lambda d: d['artifacts'].append(copy.deepcopy(d['artifacts'][0])),
            lambda d: d['artifacts'][1].__setitem__('filename', d['artifacts'][0]['filename']),
            lambda d: d['artifacts'][0].__setitem__('filename', '../taskalong-cli-0.1.0-alpha.1.tgz'),
            lambda d: d['artifacts'][0].__setitem__('filename', 'dist/taskalong-cli-0.1.0-alpha.1.tgz'),
            lambda d: d['artifacts'][0].__setitem__('filename', 'foreign.tgz'),
            lambda d: d['artifacts'][0].__setitem__('sha256', 'C' * 64),
            lambda d: d['artifacts'][0].__setitem__('sha256', 'c' * 63),
            lambda d: d['artifacts'][0].__setitem__('artifact_digest', 'sha256:' + 'D' * 64),
            lambda d: d['artifacts'][0].__setitem__('artifact_digest', 'd' * 64),
            lambda d: d['artifacts'][0].__setitem__('source_sha', 'f' * 40),
            lambda d: d['artifacts'][0].__setitem__('bytes', 1024 * 1024 + 1),
            lambda d: d['artifacts'][1].__setitem__('bytes', 64 * 1024 * 1024 + 1),
        )
        for i, mutate in enumerate(mutations):
            with self.subTest(case=i):
                self.assert_bad(mutate)

    def test_python_bundle_pairing(self):
        mutations = (
            lambda d: d['artifacts'][1].__setitem__('artifact_id', 501),
            lambda d: d['artifacts'][2].__setitem__('artifact_id', 501),
            lambda d: d['artifacts'][1].__setitem__('run_id', 202),
            lambda d: d['artifacts'][2].__setitem__('run_id', 999),
            lambda d: d['artifacts'][1].__setitem__('attempt', 3),
            lambda d: d['artifacts'][2].__setitem__('attempt', 1),
        )
        for i, mutate in enumerate(mutations):
            with self.subTest(case=i):
                self.assert_bad(mutate)


if __name__ == '__main__':
    unittest.main()
