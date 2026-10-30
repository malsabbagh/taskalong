"""Offline public pilot contracts; local responses never qualify a provider."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from taskalong import supervised_pilot as pilot
from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes


def request():
    return {"base_commit":"a"*40,"task":"Change greeting and add a note.","provider":"muse","model":"wonder-full","reasoning_effort":"high",
            "files":{"hello.txt":"hello\n","note.txt":None,"obsolete.txt":"old\n"}}


@unittest.skipUnless(os.name == "posix", "Private artifact staging requires POSIX descriptors")
class SupervisedPilotTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.bundle=self.root/'bundle';self.output=self.root/'review'

    def prepare(self, value=None):
        return pilot.prepare(request() if value is None else value,output=str(self.bundle))

    def response(self):
        return {"bundle_digest":self.prepare()["bundle_digest"],"changes":{"hello.txt":"hello world\n","note.txt":"note\n","obsolete.txt":None}}

    def test_prepare_is_bound_private_and_has_no_dispatch_or_repository_claim(self):
        result=self.prepare();_,manifest=pilot._bundle(str(self.bundle))
        self.assertEqual(manifest['digest'],result['bundle_digest'])
        self.assertEqual(manifest['snapshot_provenance'],'operator_supplied_unverified')
        self.assertFalse(manifest['repository_observed']);self.assertFalse(manifest['provider_account_observed'])
        for name in ('prompt.txt','bundle.json'):
            self.assertEqual((self.bundle/name).stat().st_mode&0o777,0o400)
        self.assertIn(result['bundle_digest'],(self.bundle/'prompt.txt').read_text())
        self.assertEqual(self.bundle.stat().st_mode&0o777,0o700)
        for name in ('live_dispatch_allowed','production_dispatch_allowed','acceptance_allowed','automatic_retry_allowed'):
            self.assertIs(result[name],False)

    @unittest.skipUnless(shutil.which('git'), 'Git is needed only to verify manual patch applicability')
    def test_public_staging_emits_applicable_add_edit_delete_patch_without_touching_source(self):
        response=self.response()
        source=self.root/'disposable';source.mkdir()
        (source/'hello.txt').write_text('hello\n');(source/'obsolete.txt').write_text('old\n')
        result=pilot.stage(bundle=str(self.bundle),response=response,output=str(self.output))
        self.assertFalse(result['patch_applied']);self.assertFalse(result['tests_run'])
        self.assertEqual(result['response_provenance'],'unverified_local_content')
        self.assertEqual((source/'hello.txt').read_text(),'hello\n');self.assertFalse((source/'note.txt').exists())
        proposed=(self.output/'proposed.patch').read_bytes()
        self.assertIn(b'--- /dev/null\n+++ b/note.txt',proposed)
        # The human application seam is exercised only against this disposable
        # fixture, never by pilot production code.
        checked=subprocess.run(['git','apply','--check','-'],cwd=source,input=proposed,capture_output=True,timeout=10)
        self.assertEqual(checked.returncode,0,checked.stderr)
        applied=subprocess.run(['git','apply','-'],cwd=source,input=proposed,capture_output=True,timeout=10)
        self.assertEqual(applied.returncode,0,applied.stderr)
        self.assertEqual((source/'hello.txt').read_text(),'hello world\n')
        self.assertEqual((source/'note.txt').read_text(),'note\n');self.assertFalse((source/'obsolete.txt').exists())

    @unittest.skipUnless(shutil.which('git'), 'Git verifies Unicode patch applicability')
    def test_unicode_line_separators_are_content_and_patch_applies(self):
        for separator in ('\u0085', '\u2028', '\u2029'):
            with self.subTest(separator=ord(separator)):
                self.bundle=self.root/f'bundle-{ord(separator)}'
                self.output=self.root/f'review-{ord(separator)}'
                before='a'+separator+'b\n';after='a'+separator+'c\n'
                binding=self.prepare(request()|{'files':{'unicode.txt':before}})
                response={'bundle_digest':binding['bundle_digest'],'changes':{'unicode.txt':after}}
                pilot.stage(bundle=str(self.bundle),response=response,output=str(self.output))
                source=self.root/f'source-{ord(separator)}';source.mkdir()
                (source/'unicode.txt').write_bytes(before.encode())
                applied=subprocess.run(['git','apply','-'],cwd=source,input=(self.output/'proposed.patch').read_bytes(),capture_output=True,timeout=10)
                self.assertEqual(applied.returncode,0,applied.stderr)
                self.assertEqual((source/'unicode.txt').read_bytes(),after.encode())

    def test_scope_binding_noop_and_extra_receipt_claims_refuse_before_claim(self):
        response=self.response()
        bad=[response|{'bundle_digest':'f'*64},response|{'authentic':True},response|{'changes':{'outside.txt':'x\n'}},
             response|{'changes':{'hello.txt':'hello\n'}},response|{'changes':{}}]
        for value in bad:
            with self.subTest(value=value),self.assertRaises(TaskAlongError):
                pilot.stage(bundle=str(self.bundle),response=value,output=str(self.output))
        self.assertFalse((self.bundle/'response-claim.json').exists());self.assertFalse(self.output.exists())

    def test_protected_traversal_case_and_ancestor_conflicts_refuse(self):
        bad=[{'.git/config':'x\n'},{'AGENTS.md':'x\n'},{'../escape':'x\n'},{'a b':'x\n'},
             {'A':'x\n','a':'y\n'},{'A':'x\n','a/child':'y\n'}]
        for files in bad:
            with self.subTest(files=files),self.assertRaises(TaskAlongError):self.prepare(request()|{'files':files})
        self.assertFalse(self.bundle.exists())

    def test_text_and_total_bounds_refuse(self):
        for content in ('missing newline','windows\r\n','nul\0\n','\x1b[31m\n','x'*65536+'\n'):
            with self.subTest(content=content[:20]),self.assertRaises(TaskAlongError):
                self.prepare(request()|{'files':{'a':content}})
        with self.assertRaises(TaskAlongError):self.prepare(request()|{'files':{f'f{i}':'x'*65535+'\n' for i in range(5)}})
        self.assertFalse(self.bundle.exists())

    def test_existing_directory_and_symlink_refuse_without_overwrite(self):
        self.bundle.mkdir();(self.bundle/'keep').write_text('original')
        with self.assertRaises(TaskAlongError):self.prepare()
        self.assertEqual((self.bundle/'keep').read_text(),'original')
        alias=self.root/'alias';alias.symlink_to(self.bundle,target_is_directory=True)
        with self.assertRaises(TaskAlongError):pilot.prepare(request(),output=str(alias/'new'))
        self.assertFalse((self.bundle/'new').exists())

    def test_tampered_manifest_or_prompt_refuses(self):
        response=self.response()
        prompt=self.bundle/'prompt.txt';prompt.chmod(0o600);prompt.write_text('changed');prompt.chmod(0o400)
        with self.assertRaises(TaskAlongError):pilot.stage(bundle=str(self.bundle),response=response,output=str(self.output))
        self.assertFalse(self.output.exists())

    def test_response_claim_prevents_second_staging_and_never_replays(self):
        response=self.response();pilot.stage(bundle=str(self.bundle),response=response,output=str(self.output))
        second=self.root/'second'
        with self.assertRaises(TaskAlongError) as exc:pilot.stage(bundle=str(self.bundle),response=response,output=str(second))
        self.assertEqual(exc.exception.code,'pilot_response_already_claimed');self.assertFalse(second.exists())

    def test_interrupted_staging_retains_claim_and_partial_bytes_without_success(self):
        response=self.response();original=pilot._write
        def fail_review(root,name,data):
            if name=='review.json':raise OSError('fixture disk failure')
            return original(root,name,data)
        with patch.object(pilot,'_write',side_effect=fail_review),self.assertRaises(TaskAlongError) as exc:
            pilot.stage(bundle=str(self.bundle),response=response,output=str(self.output))
        self.assertEqual(exc.exception.effect_outcome,'uncertain')
        self.assertTrue((self.bundle/'response-claim.json').exists());self.assertTrue((self.output/'proposed.patch').exists())
        self.assertFalse((self.output/'review.json').exists())
        with self.assertRaises(TaskAlongError):pilot.stage(bundle=str(self.bundle),response=response,output=str(self.root/'retry'))

    def test_empty_file_creation_is_explicitly_unsupported(self):
        response=self.response();response['changes']={'note.txt':''}
        with self.assertRaises(TaskAlongError) as exc:pilot.stage(bundle=str(self.bundle),response=response,output=str(self.output))
        self.assertEqual(exc.exception.code,'pilot_empty_file_change_unsupported')

    def test_cli_roundtrip_opens_no_store_and_live_run_always_refuses(self):
        from taskalong.cli import main
        req=self.root/'request.json';req.write_bytes(canonical_bytes(request()))
        def call(argv):
            stream=io.StringIO()
            with contextlib.redirect_stdout(stream),patch('taskalong.api.RunService',side_effect=AssertionError('Store opened')):
                code=main(['--json',*argv])
            return code,json.loads(stream.getvalue())
        code,result=call(['supervised-pilot-prepare','--request',str(req),'--output',str(self.bundle)])
        self.assertEqual(code,0)
        response=self.root/'response.json';response.write_bytes(canonical_bytes({'bundle_digest':result['data']['bundle_digest'],'changes':{'hello.txt':'hello world\n'}}))
        code,result=call(['supervised-pilot-stage','--bundle',str(self.bundle),'--response',str(response),'--output',str(self.output)])
        self.assertEqual(code,0);self.assertFalse(result['data']['production_dispatch_allowed'])
        code,result=call(['supervised-pilot-run','--bundle',str(self.bundle)])
        self.assertEqual(code,3);self.assertEqual(result['errors'][0]['code'],'supervised_pilot_live_disabled')
        self.assertEqual(result['errors'][0]['effect_outcome'],'not_sent')

    def test_cli_document_reader_refuses_symlink_and_duplicate_keys(self):
        file=self.root/'request.json';file.write_text('{"x":1,"x":2}')
        with self.assertRaises(TaskAlongError):pilot.read_document(str(file))
        alias=self.root/'alias';alias.symlink_to(file)
        with self.assertRaises(TaskAlongError):pilot.read_document(str(alias))
