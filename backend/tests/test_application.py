import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException


class ApplicationLogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        with patch.dict(
            os.environ,
            {
                "SBEANS_ADMIN_PASSWORD": "test-panel-password",
                "SBEANS_STORE_PATH": str(Path(cls.temporary.name) / "secure_store.json"),
            },
        ):
            from sbeans import application

        cls.application = application

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_solver_steps_and_non_error_solver_summaries_are_filtered(self):
        application = self.application
        self.assertFalse(application._is_important_log("FlareSolverr步骤：aws-waf-solve status=success"))
        self.assertFalse(application._is_important_log("FlareSolverr：开始同一 Camoufox 会话求解并提交登录"))
        self.assertFalse(application._is_important_log("FlareSolverr：进入 VOXI 后等待 10 秒"))

    def test_failure_summary_keeps_detailed_error(self):
        message = "FlareSolverr：求解失败，本次账号尝试失败 - Vision API request failed: TimeoutError"
        self.assertTrue(self.application._is_important_log(message))

    def test_record_without_time_uses_singapore_time(self):
        application = self.application
        with patch.object(application.STORE, "add_record", return_value={"time": "2026-09-04 12:34"}) as add_record, patch(
            "sbeans.application.current_singapore_time", return_value="2026-09-04 12:34"
        ):
            application.add_record(
                application.RecordRequest(email="user@example.com", password="secret", time=""),
                "test-panel-password",
            )
        self.assertEqual(add_record.call_args.args[-1], "2026-09-04 12:34")

    def test_record_without_account_password_is_resolved_by_store(self):
        application = self.application
        with patch.object(
            application.STORE,
            "add_record",
            return_value={"id": "record-id", "email": "user@example.com", "time": "2026-09-04 12:34"},
        ) as add_record:
            application.add_record(
                application.RecordRequest(email="user@example.com", password="", time="2026-09-04 12:34"),
                "test-panel-password",
            )
        self.assertEqual(add_record.call_args.args[2], "")

    def test_missing_default_account_password_is_a_validation_error(self):
        application = self.application
        with patch.object(application.STORE, "add_record", side_effect=ValueError("尚未设置默认账号密码")):
            with self.assertRaises(HTTPException) as raised:
                application.add_record(
                    application.RecordRequest(email="user@example.com", password="", time="2026-09-04 12:34"),
                    "test-panel-password",
                )
        self.assertEqual(raised.exception.status_code, 422)
        self.assertEqual(raised.exception.detail, "尚未设置默认账号密码")

    def test_default_account_password_setting_does_not_return_secret(self):
        application = self.application
        with patch.object(application.STORE, "set_default_account_password") as setter:
            result = application.set_default_account_password(
                application.DefaultAccountPasswordRequest(password="shared-secret"),
                "test-panel-password",
            )
        setter.assert_called_once_with("test-panel-password", "shared-secret")
        self.assertEqual(result, {"changed": True, "has_default_account_password": True})
        self.assertNotIn("shared-secret", result.values())

    def test_settings_only_returns_default_password_presence(self):
        application = self.application
        with patch.object(application.STORE, "has_default_account_password", return_value=True):
            result = application.settings("test-panel-password")
        self.assertEqual(result, {"has_default_account_password": True})

    def test_code_library_delete_forwards_unique_selected_ids(self):
        application = self.application
        with patch.object(application.STORE, "delete_code_library_entries", return_value=2) as delete_entries:
            result = application.delete_code_library(
                application.CodeLibraryDeleteRequest(entry_ids=["first", "second", "first"]),
                "test-panel-password",
            )
        delete_entries.assert_called_once_with("test-panel-password", ["first", "second"])
        self.assertEqual(result, {"deleted": 2})

    def test_code_library_delete_rejects_empty_selection(self):
        application = self.application
        with self.assertRaises(HTTPException) as raised:
            application.delete_code_library(
                application.CodeLibraryDeleteRequest(entry_ids=[]),
                "test-panel-password",
            )
        self.assertEqual(raised.exception.status_code, 422)

    def test_waf_retry_defaults_off(self):
        self.assertFalse(self.application.LoginRequest().retry_waf)
        self.assertTrue(self.application.LoginRequest(retry_waf=True).retry_waf)


if __name__ == "__main__":
    unittest.main()
