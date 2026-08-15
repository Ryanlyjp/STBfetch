import os
import unittest
from unittest.mock import patch

from sbeans.flaresolverr_client import solve_turnstile


class FlareSolverrClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_solver_returns_redacted_solution_and_cleans_session(self):
        token = "t" * 96
        responses = [
            {
                "status": "ok",
                "solution": {
                    "turnstile_token": token,
                    "userAgent": "solver-agent",
                    "cookies": [
                        {
                            "name": "cf_clearance",
                            "value": "cookie-value",
                            "domain": ".studentbeans.com",
                            "path": "/",
                            "secure": True,
                        }
                    ],
                },
            },
            {"status": "ok"},
        ]
        logs = []

        async def log(message):
            logs.append(message)

        with patch.dict(os.environ, {"SBEANS_FLARESOLVERR_URL": "http://solver:8191"}), patch(
            "sbeans.flaresolverr_client._post_json", side_effect=responses
        ) as post:
            solution = await solve_turnstile(
                "https://accounts.studentbeans.com/uk/authorisation/log-in",
                "http://user:pass@proxy.example:8080",
                log,
            )

        self.assertIsNotNone(solution)
        self.assertEqual(solution.token, token)
        self.assertEqual(solution.user_agent, "solver-agent")
        self.assertEqual(solution.cookies[0]["domain"], ".studentbeans.com")
        self.assertEqual(post.call_count, 1)
        request_payload = post.call_args_list[0].args[1]
        self.assertEqual(request_payload["browser"], "camoufox")
        self.assertEqual(request_payload["proxy"]["username"], "user")
        self.assertEqual(request_payload["tabs_till_verify"], 1)
        self.assertTrue(any("求解完成" in message for message in logs))
        self.assertFalse(any(token in message for message in logs))

    async def test_solver_can_submit_login_in_same_camoufox_context(self):
        token = "s" * 96
        responses = [
            {
                "status": "ok",
                "solution": {
                    "turnstile_token": token,
                    "userAgent": "solver-agent",
                    "cookies": [],
                    "sbeans_login_success": True,
                    "sbeans_login_message": "登录成功",
                    "sbeans_login_response_status": 200,
                    "sbeans_login_elapsed": 12.5,
                    "sbeans_login_auth_confirmed": True,
                    "sbeans_login_graphql_logged_in": True,
                    "sbeans_login_viewer_token_present": True,
                    "sbeans_login_register_visible": False,
                    "sbeans_login_login_visible": False,
                    "sbeans_login_account_marker_visible": True,
                    "sbeans_login_auth_cookie_names": ["viewer_token"],
                    "sbeans_code_collection_success": True,
                    "sbeans_code_collection_message": "代码采集完成",
                    "sbeans_code_collection_elapsed": 8.5,
                    "sbeans_code_results": [
                        {"ok": True, "planId": "121296", "code": "TEST", "endDate": "2026-01-01T00:00:00Z"}
                    ],
                    "sbeans_debug_screenshots": [
                        {"stage": "login-submit-finished", "image": "c2NyZWVuc2hvdA=="}
                    ],
                    "screenshot": "c2NyZWVuc2hvdA==",
                },
            }
        ]
        logs = []

        async def log(message):
            logs.append(message)

        with patch.dict(os.environ, {"SBEANS_FLARESOLVERR_URL": "http://solver:8191"}), patch(
            "sbeans.flaresolverr_client._post_json", side_effect=responses
        ) as post:
            solution = await solve_turnstile(
                "https://accounts.studentbeans.com/uk/authorisation/log-in",
                "http://user:pass@proxy.example:8080",
                log,
                email="first@example.com",
                password="secret",
                return_screenshot=True,
                collect_codes=True,
                collect_url="https://www.studentbeans.com/student-discount/uk/voxi",
            )

        self.assertIsNotNone(solution)
        self.assertTrue(solution.login_success)
        self.assertEqual(solution.login_response_status, 200)
        self.assertTrue(solution.login_auth_confirmed)
        self.assertTrue(solution.login_graphql_logged_in)
        self.assertTrue(solution.login_viewer_token_present)
        self.assertFalse(solution.login_register_visible)
        self.assertEqual(solution.login_auth_cookie_names, ["viewer_token"])
        self.assertEqual(solution.screenshot, "c2NyZWVuc2hvdA==")
        self.assertEqual(solution.debug_screenshots[0]["stage"], "login-submit-finished")
        self.assertTrue(solution.code_collection_success)
        self.assertEqual(solution.code_results[0]["code"], "TEST")
        request_payload = post.call_args.args[1]
        self.assertTrue(request_payload["sbeans_login"])
        self.assertEqual(request_payload["sbeans_email"], "first@example.com")
        self.assertEqual(request_payload["sbeans_password"], "secret")
        self.assertFalse(request_payload["returnOnlyCookies"])
        self.assertTrue(request_payload["returnScreenshot"])
        self.assertTrue(request_payload["sbeans_collect_codes"])
        self.assertIn("student-discount/uk/voxi", request_payload["sbeans_collect_url"])
        self.assertTrue(any("同一 Camoufox" in message for message in logs))
        self.assertTrue(any("登录成功=True" in message for message in logs))
        self.assertFalse(any("secret" in message for message in logs))


if __name__ == "__main__":
    unittest.main()
