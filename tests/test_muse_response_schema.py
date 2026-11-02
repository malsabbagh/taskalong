"""Versioned schema transport uses synthetic source only; no provider calls."""
import json
import unittest
from taskalong import muse_response_schema as schema
from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes


class ResponseSchemaTests(unittest.TestCase):
    def setUp(self):
        self.request = {'files': {'one.py': 'old', 'two.py': None}}
        self.bundle = 'a' * 64

    def test_closed_schema_requires_every_property_and_binds_scope(self):
        value = schema.document(self.request, self.bundle, 32768)
        self.assertEqual(value['required'], ['bundle_digest', 'changes'])
        self.assertFalse(value['additionalProperties'])
        item = value['properties']['changes']['items']
        self.assertEqual(item['required'], ['path', 'content'])
        self.assertFalse(item['additionalProperties'])
        self.assertEqual(item['properties']['path']['enum'], ['one.py', 'two.py'])
        self.assertEqual(value['properties']['bundle_digest']['enum'], [self.bundle])
        self.assertLess(len(canonical_bytes(value)), 65536)

    def test_lossless_normalization_of_escapes_unicode_null(self):
        content = 'literal \\x42 \\u0001, actual \x01, é 😃\n'
        wire = {'bundle_digest': self.bundle, 'changes': [{'path': 'one.py', 'content': content}, {'path': 'two.py', 'content': None}]}
        result = schema.normalize(json.loads(json.dumps(wire)), self.request, self.bundle, 32768)
        self.assertEqual(result, {'bundle_digest': self.bundle, 'changes': {'one.py': content, 'two.py': None}})

    def test_rejects_duplicate_unknown_path_digest_type_and_extra_fields(self):
        item = {'path': 'one.py', 'content': 'new'}
        bad = [ {'bundle_digest': self.bundle, 'changes': [item, item]},
                {'bundle_digest': self.bundle, 'changes': [{'path': 'other', 'content': 'new'}]},
                {'bundle_digest': 'b'*64, 'changes': [item]},
                {'bundle_digest': self.bundle, 'changes': [dict(item, content=3)]},
                {'bundle_digest': self.bundle, 'changes': [dict(item, extra=True)]},
                {'bundle_digest': self.bundle, 'changes': [item], 'extra': True}]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(TaskAlongError):
                schema.normalize(value, self.request, self.bundle, 32768)

    def test_native_envelope_and_utf8_byte_limit_are_independent(self):
        value = {'bundle_digest': self.bundle, 'changes': [{'path':'one.py', 'content':'é'*1000}]}
        size = len(canonical_bytes(value))
        schema.normalize(value, self.request, self.bundle, size)
        with self.assertRaises(TaskAlongError): schema.normalize(value, self.request, self.bundle, size-1)

    def test_transport_prompt_is_explicit_and_deterministic(self):
        original = b'legacy map contract'
        prompt = schema.prompt(original)
        self.assertTrue(prompt.startswith(original))
        self.assertIn(b'json-schema-file-changes/1', prompt)
        self.assertIn(b'array', prompt)
        self.assertEqual(prompt, schema.prompt(original))

    def test_syntax_diagnostic_never_accepts_truncated_or_otherwise_invalid_json(self):
        complete = '{"changes":[{"path":"one.py","content":"bad \\x01"}]}'
        self.assertTrue(schema.escaping_failure(complete))
        self.assertTrue(schema.escaping_failure(complete.replace('\\x01',chr(1))))
        self.assertFalse(schema.escaping_failure(json.dumps({'content':'valid literal \\x01'})))
        for text in (complete[:-1],complete[:-3],complete+' extra', complete.replace(']}',',]}'),
                     '{"x":"bad \\x01","y":undefined}', '{"x":"bad \\x01","y":"\\uZZZZ"}',
                     '{"x":"bad \\x01","y":"\\ud800"}', '{"x":"bad \\x01","y":NaN}', '{"x":"bad \\x01","y":-Infinity}',
                     '{"x":"bad \\x01","y":Infinity}', '{"x":"bad \\x01","y":1e999}',
                     '{"x":"bad \\x01","y":[1,]}', '{"x":"bad \\x01","y":01}'):
            with self.subTest(text=text): self.assertFalse(schema.escaping_failure(text))

    def test_schema_is_valid_and_native_validator_rejects_extra_and_wrong_shape(self):
        from jsonschema import Draft202012Validator
        document=schema.document(self.request,self.bundle,32768)
        Draft202012Validator.check_schema(document)
        validator=Draft202012Validator(document)
        valid={'bundle_digest':self.bundle,'changes':[{'path':'one.py','content':'new\n'}]}
        validator.validate(valid)
        self.assertTrue(list(validator.iter_errors({'bundle_digest':self.bundle,'changes':{'one.py':'new\n'}})))
        self.assertTrue(list(validator.iter_errors({'bundle_digest':self.bundle,'changes':[{'path':'other','content':'new'}]})))
