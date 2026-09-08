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

    def test_blank_record_password_uses_encrypted_default_after_password_change(self):
        self.store.set_default_account_password("panel-old", "shared-secret")
        record = self.store.add_record("panel-old", "user@example.com", "", "2026-09")
        stored = json.dumps(json.loads(self.path.read_text()))
        self.assertNotIn("shared-secret", stored)
        self.assertTrue(self.store.has_default_account_password("panel-old"))

        self.store.change_password("panel-old", "panel-new")

        self.assertTrue(self.store.has_default_account_password("panel-new"))
        self.assertEqual(
            self.store.selected_accounts("panel-new", [record["id"]]),
            [("user@example.com", "shared-secret")],
        )

    def test_blank_record_password_without_default_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "尚未设置默认账号密码"):
            self.store.add_record("panel-old", "user@example.com", "", "2026-09")

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

    def test_repeated_successes_append_distinct_code_library_entries(self):
        codes = [
            {"ok": True, "planId": str(index), "code": f"CODE-{index}", "endDate": "2026-09-01"}
            for index in range(4)
        ]
        first = self.store.add_code_library("panel-old", "user@example.com", codes, "2026-09-01")
        second = self.store.add_code_library("panel-old", "user@example.com", codes, "2026-10-01")

        library = self.store.list_code_library("panel-old")
        self.assertEqual([entry["id"] for entry in library], [second["id"], first["id"]])
        self.assertEqual([entry["email"] for entry in library], ["user@example.com", "user@example.com"])

    def test_code_library_bulk_delete_removes_only_selected_entries(self):
        codes = [
            {"ok": True, "planId": str(index), "code": f"CODE-{index}", "endDate": "2026-09-01"}
            for index in range(4)
        ]
        first = self.store.add_code_library("panel-old", "first@example.com", codes, "2026-09-01")
        middle = self.store.add_code_library("panel-old", "middle@example.com", codes, "2026-09-01")
        last = self.store.add_code_library("panel-old", "last@example.com", codes, "2026-09-01")

        self.assertEqual(
            self.store.delete_code_library_entries("panel-old", [first["id"], last["id"]]),
            2,
        )
        self.assertEqual(
            [entry["id"] for entry in self.store.list_code_library("panel-old")],
            [middle["id"]],
        )


if __name__ == "__main__":
    unittest.main()
