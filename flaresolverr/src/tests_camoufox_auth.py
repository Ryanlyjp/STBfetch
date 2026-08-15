import unittest

from camoufox_auth import code_collection_allowed


class CamoufoxLoginAuthTests(unittest.TestCase):
    def test_code_collection_requires_confirmed_login(self):
        self.assertFalse(code_collection_allowed({"success": False}, True))
        self.assertTrue(code_collection_allowed({"success": True}, True))
        self.assertFalse(code_collection_allowed({"success": True}, False))


if __name__ == "__main__":
    unittest.main()
