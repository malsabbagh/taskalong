"""Synthetic provider transport boundaries never enlarge authority documents."""
import json
import unittest

from taskalong.errors import TaskAlongError
from taskalong.provider_wire import loads_wire
from taskalong.validation import canonical_bytes, loads


class ProviderWireTests(unittest.TestCase):
    def test_transport_escaping_can_exceed_authority_size(self):
        value = {"text": "é" * 300000}
        raw = json.dumps(value, ensure_ascii=True).encode()
        self.assertGreater(len(raw), 1048576)
        self.assertEqual(loads_wire(raw), value)
        self.assertLess(len(canonical_bytes(value)), 1048576)
        with self.assertRaises(TaskAlongError):
            loads(raw, max_bytes=4194304)

    def test_exact_wire_boundary_and_unchanged_authority_ceiling(self):
        raw = b'{"text":"' + b"x" * (4194304 - 11) + b'"}'
        self.assertEqual(len(raw), 4194304)
        value = loads_wire(raw)
        with self.assertRaises(TaskAlongError):
            canonical_bytes(value)
        for data in (raw + b" ", raw):
            with self.assertRaises(TaskAlongError):
                loads_wire(data, max_bytes=4194303)

    def test_strict_malformed_duplicate_unicode_and_numeric_bounds(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1.2}',
                    b'{"x":9007199254740992}', b'{"x":"\\ud800"}', b'[]',
                    b'{"x":"\xff"}', b'{"x":', b'{"x":' + b'['*65 + b'0' + b']'*65 + b'}'):
            with self.subTest(raw=raw[:40]), self.assertRaises(TaskAlongError):
                loads_wire(raw)
        for limit in (True, 0, 16777217):
            with self.assertRaises(TaskAlongError):
                loads_wire(b"{}", max_bytes=limit)

    def test_transport_node_and_container_budgets_are_finite(self):
        for value in ({"x": [0]*4097}, {"x": [[0]*4096 for _ in range(17)]}):
            with self.assertRaises(TaskAlongError):
                loads_wire(json.dumps(value))
