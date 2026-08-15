import json
import tempfile
import unittest
from pathlib import Path

from sbeans.secure_store import SecureStore


class SecureStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "secure_store.json"
        self.store = SecureStore(self.path, "panel-old")

    def tearDown(self):
        self.temporary.cleanup()

    def test_record_lifecycle_uses_encrypted_storage(self):
        record = self.store.add_record("panel-old", "user@example.com", "secret-value", "2026-08")
        self.assertEqual(
            self.store.list_records("panel-old"),
            [{"id": record["id"], "email": "user@example.com", "time": "2026-08"}],
        )
        self.assertEqual(
            self.store.selected_accounts("panel-old", [record["id"]]),
            [("user@example.com", "secret-value")],
        )
        stored = json.loads(self.path.read_text())
        self.assertNotIn("user@example.com", json.dumps(stored))
        self.assertNotIn("secret-value", json.dumps(stored))
        self.assertTrue(self.store.delete_record("panel-old", record["id"]))
        self.assertEqual(self.store.list_records("panel-old"), [])

    def test_password_change_reencrypts_records(self):
        record = self.store.add_record("panel-old", "user@example.com", "secret-value", "manual time")
        self.store.change_password("panel-old", "panel-new")
        self.assertFalse(self.store.authenticate("panel-old"))
        self.assertTrue(self.store.authenticate("panel-new"))
        reloaded = SecureStore(self.path, "panel-old")
        self.assertFalse(reloaded.authenticate("panel-old"))
        self.assertTrue(reloaded.authenticate("panel-new"))
        self.assertEqual(
            reloaded.selected_accounts("panel-new", [record["id"]]),
            [("user@example.com", "secret-value")],
        )

    def test_record_time_updates_by_email(self):
        self.store.add_record("panel-old", "User@example.com", "secret-value", "首次手动输入")
        self.assertEqual(
            self.store.update_record_time("panel-old", "user@example.com", "2026-09-14 12:12"),
            1,
        )
        self.assertEqual(self.store.list_records("panel-old")[0]["time"], "2026-09-14 12:12")
        self.assertEqual(
            self.store.update_record_time("panel-old", "user@example.com", "2026-09-14 12:12"),
            0,
        )

    def test_wrong_password_is_rejected(self):
        with self.assertRaises(ValueError):
            self.store.list_records("wrong")

    def test_code_library_is_encrypted_and_survives_password_change(self):
        codes = [
            {"ok": True, "planId": str(index), "code": f"CODE-{index}", "endDate": "2026-09-01"}
            for index in range(4)
        ]
        entry = self.store.add_code_library("panel-old", "user@example.com", codes, "2026-09-01")
        self.assertEqual(entry["email"], "user@example.com")
        self.assertEqual(len(self.store.list_code_library("panel-old")), 1)
        stored = json.dumps(json.loads(self.path.read_text()))
        self.assertNotIn("CODE-0", stored)
        self.store.change_password("panel-old", "panel-new")
        library = self.store.list_code_library("panel-new")
        self.assertEqual(library[0]["email"], "user@example.com")
        self.assertEqual(library[0]["codes"][0]["code"], "CODE-0")

    def test_code_library_rejects_partial_results(self):
        with self.assertRaisesRegex(ValueError, "完整的四组"):
            self.store.add_code_library(
                "panel-old",
                "user@example.com",
                [{"ok": True, "code": "ONLY-ONE", "endDate": "2026-09-01"}],
                "2026-09-01",
            )


if __name__ == "__main__":
    unittest.main()
