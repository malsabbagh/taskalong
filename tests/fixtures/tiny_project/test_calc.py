import unittest

from calc import add_one


class AdditionTests(unittest.TestCase):
    def test_add_one(self):
        self.assertEqual(add_one(4), 5)
