import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch
from tempfile import TemporaryDirectory

from playwright.async_api import async_playwright

from sbeans.login_flow import (
    LOGIN_URL,
    MAX_ACCOUNT_ATTEMPTS,
    Account,
    _apply_solver_token,
    _dismiss_cookie_consent,
    _is_login_result_url,
    _wait_for_submit_enabled,
    _turnstile_state,
    current_singapore_time,
    proxy_attempts,
    parse_accounts,
    parse_proxies,
    playwright_proxy,
    run_logins,
)
from sbeans.flaresolverr_client import (
    AWS_WAF_VISUAL_FAILURE_LOCATION,
    FlareSolverFailure,
    FlareSolverSolution,
)


class LoginFlowParsingTests(unittest.TestCase):
    def test_account_lines(self):
        accounts = parse_accounts("first@example.com one\nsecond@example.com two with spaces")
        self.assertEqual(accounts[1].password, "two with spaces")

    def test_proxy_formats(self):
        proxies = parse_proxies(
            "user:pass@proxy.example:7778\nproxy.example:3000:user:pass\n127.0.0.1:7890\n127.0.0.1:7890"
        )
        self.assertEqual(len(proxies), 3)
        self.assertEqual(proxies[0], "http://user:pass@proxy.example:7778")
        self.assertEqual(playwright_proxy(proxies[1])["server"], "http://proxy.example:3000")
        self.assertEqual(proxies[2], "http://127.0.0.1:7890")

    def test_invalid_account_line(self):
        with self.assertRaises(ValueError):
            parse_accounts("missing-password")

    def test_login_result_url_predicate_accepts_playwright_string(self):
        self.assertFalse(_is_login_result_url("https://accounts.studentbeans.com/uk/authorisation/log-in"))
        self.assertFalse(_is_login_result_url("https://accounts.studentbeans.com/uk/authorisation/log-in/"))
        self.assertTrue(_is_login_result_url("https://accounts.studentbeans.com/uk/"))

    def test_login_url_preserves_oauth_context(self):
        self.assertIn("client_id=", LOGIN_URL)
        self.assertIn("user_return_to=https%3A%2F%2Fwww.studentbeans.com%2Fuk", LOGIN_URL)

    def test_account_proxy_attempts_use_one_attempt(self):
        self.assertEqual(
            proxy_attempts(["proxy-a", "proxy-b", "proxy-c", "proxy-d"], 0),
            ["proxy-a"],
        )
        self.assertEqual(
            proxy_attempts(["proxy-a", "proxy-b"], 1),
            ["proxy-b"],
        )
        self.assertEqual(proxy_attempts([], 0), [""] * MAX_ACCOUNT_ATTEMPTS)

    def test_current_singapore_time_uses_automatic_record_format(self):
        self.assertRegex(current_singapore_time(), r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$")


class SolverRequiredTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _successful_solution():
        return FlareSolverSolution(
            token="t" * 96,
            cookies=[],
            user_agent="camoufox-agent",
            login_success=True,
            login_message="登录成功",
            login_response_status=200,
            login_elapsed=0.1,
            code_collection_success=True,
            code_collection_message="代码采集完成",
            code_collection_elapsed=0.1,
            code_results=[{"ok": True, "planId": "121296", "code": "TEST", "endDate": "2026-01-01T00:00:00Z"}],
        )

    async def test_solver_failure_does_not_launch_browser(self):
        class FakePlaywright:
            def __init__(self):
                self.chromium = Mock()

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, traceback):
                return False

        logs = []
        fake_playwright = FakePlaywright()

        async def log(message):
            logs.append(message)

        with TemporaryDirectory() as screenshot_dir, patch(
            "sbeans.login_flow.async_playwright", return_value=fake_playwright
        ), patch(
            "sbeans.login_flow.solve_turnstile", new=AsyncMock(return_value=None)
        ):
            results = await run_logins(
                [Account("first@example.com", "password")],
                [],
                screenshot_dir,
                False,
                log,
            )

        self.assertFalse(results[0]["success"])
        self.assertEqual(results[0]["message"], "FlareSolverr 未完成同页登录")
        fake_playwright.chromium.launch.assert_not_called()
        self.assertTrue(any("FlareSolverr 未完成同页登录" in message for message in logs))

    async def test_run_logins_does_not_launch_second_browser(self):
        logs = []

        async def log(message):
            logs.append(message)

        solution = FlareSolverSolution(
            token="t" * 96,
            cookies=[],
            user_agent="camoufox-agent",
            login_success=True,
            login_message="登录成功",
            login_response_status=200,
            login_elapsed=2.5,
            code_collection_success=True,
            code_results=[{"ok": True, "planId": "121296", "code": "TEST", "endDate": "2026-01-01T00:00:00Z"}],
        )
        with TemporaryDirectory() as screenshot_dir, patch(
            "sbeans.login_flow.solve_turnstile", new=AsyncMock(return_value=solution)
        ), patch("sbeans.login_flow.async_playwright") as playwright:
            results = await run_logins(
                [Account("first@example.com", "password")],
                ["http://proxy.example:8080"],
                screenshot_dir,
                False,
                log,
            )

        self.assertTrue(results[0]["success"])
        playwright.assert_not_called()
        self.assertTrue(any("同一 Camoufox 会话登录完成" in message for message in logs))

    async def test_waf_failure_retries_once_when_enabled_and_second_session_succeeds(self):
        logs = []

        async def log(message):
            logs.append(message)

        failure = FlareSolverFailure(
            AWS_WAF_VISUAL_FAILURE_LOCATION,
            "AWS WAF Confirm did not produce a browser voucher",
        )
        with TemporaryDirectory() as screenshot_dir, patch(
            "sbeans.login_flow.solve_turnstile",
            new=AsyncMock(side_effect=[failure, self._successful_solution()]),
        ) as solve:
            results = await run_logins(
                [Account("first@example.com", "password")],
                ["http://proxy-a.example:8080", "http://proxy-b.example:8080"],
                screenshot_dir,
                False,
                log,
                retry_waf=True,
            )

        self.assertTrue(results[0]["success"])
        self.assertEqual(solve.await_count, 2)
        self.assertTrue(solve.await_args_list[0].kwargs["raise_on_failure"])
        self.assertTrue(any("重试开关已开启" in message for message in logs))
        self.assertTrue(any("第 2/2 次尝试" in message for message in logs))

    async def test_waf_failure_retries_only_once_when_second_session_fails(self):
        failure = FlareSolverFailure(
            AWS_WAF_VISUAL_FAILURE_LOCATION,
            "AWS WAF Confirm did not produce a browser voucher",
        )
        second_failure = FlareSolverFailure(
            AWS_WAF_VISUAL_FAILURE_LOCATION,
            "AWS WAF Confirm did not produce a browser voucher again",
        )
        with TemporaryDirectory() as screenshot_dir, patch(
            "sbeans.login_flow.solve_turnstile",
            new=AsyncMock(side_effect=[failure, second_failure]),
        ) as solve:
            results = await run_logins(
                [Account("first@example.com", "password")],
                [],
                screenshot_dir,
                False,
                retry_waf=True,
            )

        self.assertFalse(results[0]["success"])
        self.assertEqual(results[0]["message"], str(second_failure))
        self.assertEqual(solve.await_count, 2)

    async def test_waf_failure_does_not_retry_when_switch_is_off(self):
        failure = FlareSolverFailure(
            AWS_WAF_VISUAL_FAILURE_LOCATION,
            "AWS WAF Confirm did not produce a browser voucher",
        )
        with TemporaryDirectory() as screenshot_dir, patch(
            "sbeans.login_flow.solve_turnstile", new=AsyncMock(side_effect=failure)
        ) as solve:
            results = await run_logins(
                [Account("first@example.com", "password")],
                [],
                screenshot_dir,
                False,
            )

        self.assertFalse(results[0]["success"])
        self.assertEqual(solve.await_count, 1)

    async def test_non_waf_failure_does_not_retry_when_switch_is_on(self):
        failure = FlareSolverFailure("Turnstile", "Camoufox Turnstile token timeout")
        with TemporaryDirectory() as screenshot_dir, patch(
            "sbeans.login_flow.solve_turnstile", new=AsyncMock(side_effect=failure)
        ) as solve:
            results = await run_logins(
                [Account("first@example.com", "password")],
                [],
                screenshot_dir,
                False,
                retry_waf=True,
            )

        self.assertFalse(results[0]["success"])
        self.assertEqual(solve.await_count, 1)

    async def test_parallel_accounts_never_share_proxy(self):
        active = set()
        observed = []
        max_active = 0

        async def solve(url, proxy, log, **kwargs):
            nonlocal max_active
            self.assertNotIn(proxy, active)
            active.add(proxy)
            observed.append(proxy)
            max_active = max(max_active, len(active))
            await asyncio.sleep(0.05)
            active.remove(proxy)
            return self._successful_solution()

        with TemporaryDirectory() as screenshot_dir, patch(
            "sbeans.login_flow.solve_turnstile", new=solve
        ):
            results = await run_logins(
                [Account("first@example.com", "one"), Account("second@example.com", "two")],
                ["http://proxy-a.example:8080", "http://proxy-b.example:8080"],
                screenshot_dir,
                False,
            )

        self.assertEqual([result["email"] for result in results], ["first@example.com", "second@example.com"])
        self.assertEqual(set(observed), {"http://proxy-a.example:8080", "http://proxy-b.example:8080"})
        self.assertEqual(max_active, 2)

    async def test_code_collection_failure_does_not_issue_retry(self):
        solution = self._successful_solution()
        solution = FlareSolverSolution(
            token=solution.token,
            cookies=solution.cookies,
            user_agent=solution.user_agent,
            login_success=True,
            login_message="登录成功",
            login_response_status=200,
            login_elapsed=0.1,
            code_collection_success=False,
            code_collection_message="部分代码采集失败",
            code_collection_elapsed=0.1,
            code_results=[{"ok": False, "planId": "121296", "error": "HTTP 500"}],
        )
        with TemporaryDirectory() as screenshot_dir, patch(
            "sbeans.login_flow.solve_turnstile", new=AsyncMock(return_value=solution)
        ) as solve:
            results = await run_logins(
                [Account("first@example.com", "password")],
                ["http://proxy-a.example:8080", "http://proxy-b.example:8080"],
                screenshot_dir,
                False,
            )

        self.assertFalse(results[0]["success"])
        self.assertTrue(results[0]["login_success"])
        self.assertEqual(results[0]["codes"][0]["error"], "HTTP 500")
        self.assertEqual(solve.await_count, MAX_ACCOUNT_ATTEMPTS)


class TurnstileTests(unittest.IsolatedAsyncioTestCase):
    async def test_submit_wait_logs_actual_enable_time(self):
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.set_content(
                '<form aria-label="form"><button disabled>Log in</button></form>'
                '<script>setTimeout(() => document.querySelector("button").disabled = false, 120);</script>'
            )
            logs = []

            async def log(message):
                logs.append(message)

            await _wait_for_submit_enabled(page, timeout_ms=1000, log=log, email="test@example.com")
            self.assertTrue(any("按钮已启用" in message for message in logs))
            self.assertTrue(any("实际等待" in message for message in logs))
            await browser.close()

    async def test_submit_wait_reports_timeout(self):
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.set_content('<form aria-label="form"><button disabled>Log in</button></form>')
            logs = []

            async def log(message):
                logs.append(message)

            with self.assertRaisesRegex(RuntimeError, "登录按钮在"):
                await _wait_for_submit_enabled(page, timeout_ms=100, log=log, email="test@example.com")
            self.assertTrue(any("启用等待超时" in message for message in logs))
            await browser.close()

    async def test_flaresolverr_token_is_rehydrated_without_builtin_solver(self):
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.set_content(
                '<div id="cf-turnstile"><input name="cf-turnstile-response" /></div>'
                '<button id="login" disabled>Log in</button>'
            )
            await page.evaluate(
                """
                () => {
                    const widget = document.querySelector('#cf-turnstile');
                    widget.__reactFiberTest = {
                        return: {
                            memoizedProps: {
                                onSuccess: (value) => {
                                    window.__turnstileSuccess = value;
                                    document.querySelector('#login').disabled = false;
                                },
                            },
                        },
                    };
                }
                """
            )
            token = "s" * 96
            logs = []

            async def log(message):
                logs.append(message)

            await _apply_solver_token(page, token, log)
            state = await _turnstile_state(page)
            self.assertEqual(state["source"], "hidden-input")
            self.assertEqual(len(state["token"]), 96)
            self.assertTrue(any("触发页面回调" in message for message in logs))
            self.assertFalse(any(token in message for message in logs))
            self.assertEqual(await page.locator("#login").is_disabled(), False)
            self.assertEqual(await page.evaluate("window.__turnstileSuccess.length"), 96)
            await browser.close()

    async def test_cookie_consent_is_dismissed_before_challenge(self):
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.set_content(
                '<button id="cookie" onclick="this.dataset.clicked=\'yes\'">Accept All Cookies</button>'
                '<div id="overlay">blocked</div>'
            )
            logs = []
            async def log(message):
                logs.append(message)

            await _dismiss_cookie_consent(page, log)
            self.assertTrue(await page.locator("#cookie").evaluate("node => node.dataset.clicked || ''"))
            self.assertTrue(any("Cookie" in message for message in logs))
            await browser.close()

    async def test_delayed_cookie_consent_is_dismissed(self):
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.set_content(
                '<script>setTimeout(() => { '
                'document.body.innerHTML = \'<button id="onetrust-accept-btn-handler" '
                'onclick="this.style.display=\\\'none\\\'">'
                'Accept All Cookies</button>\'; }, 200);</script>'
            )
            logs = []

            async def log(message):
                logs.append(message)

            await _dismiss_cookie_consent(page, log)
            self.assertTrue(any("已关闭 Cookie" in message for message in logs))
            self.assertFalse(await page.locator("#onetrust-accept-btn-handler").is_visible())
            await browser.close()

    async def test_turnstile_state_reads_existing_values_without_logging_value(self):
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            page = await browser.new_page()
            token = "t" * 96
            await page.set_content(
                '<input name="cf-turnstile-response" />'
                '<script>window.turnstile = {getResponse: () => ""};</script>'
            )
            await page.locator('input[name="cf-turnstile-response"]').fill(token)
            state = await _turnstile_state(page)
            self.assertEqual(state["source"], "hidden-input")
            self.assertEqual(len(state["token"]), 96)
            logs = []
            async def log(message):
                logs.append(message)

            self.assertFalse(logs)
            self.assertFalse(any(token in message for message in logs))
            await page.set_content(
                '<script>window.turnstile = {getResponse: () => "' + token + '"};</script>'
            )
            response_state = await _turnstile_state(page)
            self.assertEqual(response_state["source"], "turnstile.getResponse")
            self.assertEqual(len(response_state["token"]), 96)
            await browser.close()


if __name__ == "__main__":
    unittest.main()
