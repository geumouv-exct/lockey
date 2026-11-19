import unittest
from app import DEBUG

class TestDeployment(unittest.TestCase):
    def test_debug_disabled(self):
        self.assertFalse(DEBUG)
