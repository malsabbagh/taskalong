"""Direct milestone-command alias for the accepted ordered-step regressions.

Discovery already includes test_ordered_tasks; do not duplicate that suite in
installed inventories. Explicit ``python -m unittest test_steps`` runs it once.
"""
import unittest


def load_tests(loader, suite, pattern):
    return suite if pattern is not None else loader.loadTestsFromName("test_ordered_tasks")


if __name__ == "__main__":
    unittest.main()
