"""Explicit format-10 migration, complete histories, and inherited resource bytes."""
import hashlib
import importlib.util
from importlib import resources
import json
from pathlib import Path
import tempfile
import unittest

from taskalong.errors import TaskAlongError
from taskalong.store import Store
from taskalong.maintenance import verify_backup, verify_restored
from taskalong.muse_handoff import MuseConfiguration
from taskalong.trial import TrialDriverConfig
from taskalong.validation import schema, schema_names, seal_versioned
from jsonschema import Draft202012Validator
from test_antigravity_store import upgrade_through
from test_contracts import example_spec
from test_trial_contracts import example_trial_config, example_trial_spec


class OrderedStoreTests(unittest.TestCase):
    def test_all_73_inherited_resources_and_new_closed_schemas(self):
        inventory=json.loads((Path(__file__).parent/'fixtures/pre-ordered-resources.json').read_bytes())
        self.assertEqual(len(inventory),73)
        root=resources.files('taskalong.resources')
        for name,expected in inventory.items():
            self.assertEqual(hashlib.sha256(root.joinpath(name.removeprefix('src/taskalong/resources/')).read_bytes()).hexdigest(),expected,name)
        self.assertEqual(set(schema_names(version='2.7')),{'task-spec','task-run','step-receipt','result-view'})
        for name in schema_names(version='2.7'):
            Draft202012Validator.check_schema(schema(name,version='2.7'))

    def test_8_to_9_to_10_preserves_e1_muse_and_old_run_with_verified_restores(self):
        config=TrialDriverConfig.from_dict(seal_versioned('driver-config',example_trial_config(),version='2.8'))
        task=seal_versioned('task-spec',example_trial_spec(),version='2.8')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();state=root/'state'
            with Store(state) as store:
                legacy=store.create_run(example_spec(),'legacy')
                artifact=store.put_blob(b'original retained checkpoint')
            with Store.maintenance(state) as store:
                upgrade_through(store,root,8)
                store.record_document(config,operation_key='e1-history')
                trial=store.create_run(task,'trial-history')
                histories=store.document_history('driver_config',config.digest)
                for version in (9,10):
                    if version==10:
                        # This is immutable historical data; no executable or
                        # actual registration is inferred from its syntax.
                        muse=seal_versioned('capture-config',{'config_id':'retained-muse','qualification':'synthetic',
                            'projection':'muse-plain-fixture/1','transport':'operator_registered_original_fixture',
                            'executable':{'path':'/opt/example/original-fixture','sha256':'a'*64},'build':'1.4.10-R6427.1',
                            'requested_model':'synthetic-muse-model','permission_profile':'synthetic-profile','max_model_steps':1,
                            'inference_destination_id':'synthetic-local-muse','check_profile_digest':'b'*64,'checks_digest':'c'*64,
                            'review_config_digest':'d'*64,'command_sandbox_digest':'e'*64,'extensions':{}},version='2.9')
                        muse=MuseConfiguration.from_dict(muse)
                        store.record_document(muse,operation_key='muse-history')
                    request=dict(operation_key='ordered-'+str(version),target_version=version,
                        backup_dir=root/('backup-'+str(version)),restore_dir=root/('restore-'+str(version)))
                    receipt=store.upgrade(**request);self.assertEqual(store.upgrade(**request),receipt)
                    backup=verify_backup(request['backup_dir'],expected_digest=receipt['backup_manifest_digest'])
                    self.assertEqual(backup['database']['user_version'],version-1)
                    self.assertTrue(verify_restored(request['backup_dir'],request['restore_dir'],expected_digest=backup['digest'])['quarantined'])
                    self.assertEqual(store.run(legacy['run_id']),legacy)
                    self.assertEqual(store.spec(trial),task)
                    self.assertEqual(store.document_history('driver_config',config.digest),histories)
                self.assertEqual(store.document_history('capture_config',muse.digest),(muse,))
            for version,expected in [(8,'c3c8c18e9eb8b5cbb041bf322ff3ba09fa433c6f04f56a2dea82dcb84bae081e'),(9,'53dceaca13b10eea2414d361fb89c5c911fd2e9082a44d2c6f29b47b2028c3cf')]:
                fixture=Path(__file__).parent/f'fixtures/legacy_store_v{version}.py'
                self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(),expected)
                spec=importlib.util.spec_from_file_location(f'taskalong._ordered_predecessor_{version}',fixture)
                module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
                before={p.name:p.read_bytes() for p in state.glob('state.sqlite3*')}
                with self.assertRaises(TaskAlongError) as error:module.Store(state)
                self.assertEqual(error.exception.code,'unsupported_store_version')
                self.assertEqual({p.name:p.read_bytes() for p in state.glob('state.sqlite3*')},before)
            with Store(state) as store:
                self.assertEqual(store.get_blob(artifact['sha256']),b'original retained checkpoint')
                self.assertEqual(store.document_history('capture_config',muse.digest),(muse,))


if __name__=='__main__':unittest.main()
