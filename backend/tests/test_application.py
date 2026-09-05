import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


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


if __name__ == "__main__":
    unittest.main()
