from __future__ import annotations

import asyncio
import base64
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable
from urllib.parse import quote, urlsplit
from zoneinfo import ZoneInfo

from playwright.async_api import (
    Browser,
    Page,
    ProxySettings,
    TimeoutError as PlaywrightTimeoutError,
    async_playwright,
)

from .flaresolverr_client import FlareSolverSolution, solve_turnstile

LOGIN_URL = (
    "https://accounts.studentbeans.com/uk/authorisation/log-in"
    "?client_id=e55920fd-5410-4534-b926-b1214c85f64a"
    "&user_return_to=https%3A%2F%2Fwww.studentbeans.com%2Fuk"
)
CODE_COLLECTION_URL = (
    "https://www.studentbeans.com/student-discount/uk/voxi"
    "?source=promoboxes&offer=0-student-discount-voxi"
)
LOGIN_PATH = "/uk/authorisation/log-in"
LOGIN_SUBMIT_PATH = "/uk/authorisation/login"
PAGE_TIMEOUT_MS = 180_000
FORM_TIMEOUT_MS = 120_000
TURNSTILE_APPEAR_TIMEOUT_MS = 120_000
TURNSTILE_POLL_INTERVAL_SECONDS = 2
TURNSTILE_TOKEN_MIN_LENGTH = 80
LOGIN_RESULT_TIMEOUT_MS = 120_000
MAX_ACCOUNT_ATTEMPTS = 1
COOKIE_CONSENT_WAIT_MS = 8_000
SINGAPORE_TIMEZONE = ZoneInfo("Asia/Singapore")
LogCallback = Callable[[str], Awaitable[None]]


@dataclass(frozen=True)
class Account:
    email: str
    password: str


def _is_login_result_url(value: object) -> bool:
    return urlsplit(str(value)).path.rstrip("/") != LOGIN_PATH.rstrip("/")


def parse_accounts(value: str) -> list[Account]:
    accounts: list[Account] = []
    for line_number, raw_line in enumerate(value.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            raise ValueError(f"第 {line_number} 行格式错误，应为 邮箱 密码")
        email, password = parts
        if not email or not password:
            raise ValueError(f"第 {line_number} 行邮箱或密码为空")
        accounts.append(Account(email=email, password=password))
    if not accounts:
        raise ValueError("至少需要一个账号")
    return accounts


def normalize_proxy(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if "://" in value:
        return value
    if "@" in value:
        return f"http://{value}"

    parts = value.split(":", 3)
    if len(parts) == 4 and parts[1].isdigit():
        host, port, username, password = parts
        return f"http://{quote(username)}:{quote(password)}@{host}:{port}"
    if len(parts) == 2 and parts[1].isdigit():
        return f"http://{value}"
    raise ValueError("代理格式无效")


def parse_proxies(value: str) -> list[str]:
    proxies: list[str] = []
    seen: set[str] = set()
    for line in value.splitlines():
        if not line.strip():
            continue
        proxy = normalize_proxy(line)
        if proxy not in seen:
            seen.add(proxy)
            proxies.append(proxy)
    return proxies


def format_singapore_time(value: object) -> str:
    """Format an ISO date/time as Singapore local time for logs and UI data."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        return f"{raw} 00:00"
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return raw.replace("T", " ")[:16]
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(SINGAPORE_TIMEZONE).strftime("%Y-%m-%d %H:%M")


def _first_code_date(codes: object) -> str:
    if not isinstance(codes, list):
        return ""
    for item in codes:
        if isinstance(item, dict) and item.get("endDate"):
            return str(item["endDate"])
    return ""


def proxy_attempts(proxies: list[str], account_index: int) -> list[str]:
    """Return the proxy sequence for one account's bounded retry cycle."""
    if not proxies:
        return [""] * MAX_ACCOUNT_ATTEMPTS
    return [
        proxies[(account_index + offset) % len(proxies)]
        for offset in range(MAX_ACCOUNT_ATTEMPTS)
    ]


class _ProxyPool:
    """Lease one distinct proxy per active account attempt."""

    def __init__(self, proxies: list[str]) -> None:
        self._proxies = list(dict.fromkeys(proxies))
        self._in_use: set[int] = set()
        self._condition = asyncio.Condition()
        self._direct_lock = asyncio.Lock()

    def __len__(self) -> int:
        return len(self._proxies)

    async def acquire(self, preferred_index: int) -> tuple[str, int | None]:
        if not self._proxies:
            await self._direct_lock.acquire()
            return "", None
        async with self._condition:
            while True:
                for offset in range(len(self._proxies)):
                    index = (preferred_index + offset) % len(self._proxies)
                    if index not in self._in_use:
                        self._in_use.add(index)
                        return self._proxies[index], index
                await self._condition.wait()

    async def release(self, index: int | None) -> None:
        if index is None:
            if self._direct_lock.locked():
                self._direct_lock.release()
            return
        async with self._condition:
            self._in_use.discard(index)
            self._condition.notify_all()


def playwright_proxy(value: str) -> ProxySettings | None:
    if not value:
        return None
    parsed = urlsplit(value)
    if not parsed.hostname or not parsed.port:
        raise ValueError("代理缺少主机或端口")
    settings: ProxySettings = {"server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"}
    if parsed.username:
        settings["username"] = parsed.username
    if parsed.password:
        settings["password"] = parsed.password
    return settings


async def _emit(log: LogCallback | None, message: str) -> None:
    if log:
        await log(message)


async def _dismiss_cookie_consent(page: Page, log: LogCallback | None = None) -> None:
    started = time.monotonic()
    deadline = started + COOKIE_CONSENT_WAIT_MS / 1000
    accepted = {
        'accept', 'accept all', 'accept all cookies', 'agree',
        '全部接受', '接受', '同意',
    }
    while time.monotonic() < deadline:
        dismissed = ''
        direct = page.locator('#onetrust-accept-btn-handler, #accept-recommended-btn-handler')
        for index in range(await direct.count()):
            target = direct.nth(index)
            try:
                if await target.is_visible() and await target.is_enabled():
                    await target.click(timeout=2_000)
                    dismissed = 'OneTrust'
                    break
            except Exception:
                continue
        if not dismissed:
            candidates = page.locator('button, a, [role="button"]')
            for index in range(await candidates.count()):
                target = candidates.nth(index)
                try:
                    if not await target.is_visible() or not await target.is_enabled():
                        continue
                    if await target.get_attribute('aria-disabled') == 'true':
                        continue
                    text = (await target.inner_text()).replace('\n', ' ').strip().lower()
                    if text in accepted:
                        await target.click(timeout=2_000)
                        dismissed = text
                        break
                except Exception:
                    continue
        if dismissed:
            try:
                await page.wait_for_function(
                    """
                    () => {
                        const visible = (node) => {
                            if (!node) return false;
                            const style = window.getComputedStyle(node);
                            const rect = node.getBoundingClientRect();
                            return style.display !== 'none' && style.visibility !== 'hidden'
                                && style.opacity !== '0' && rect.width > 0 && rect.height > 0;
                        };
                        return !visible(document.querySelector(
                            '#onetrust-accept-btn-handler, #accept-recommended-btn-handler'
                        ));
                    }
                    """,
                    timeout=1_500,
                )
            except PlaywrightTimeoutError:
                await _emit(log, "Cookie 同意弹窗点击后仍可见，继续重试")
                await page.wait_for_timeout(250)
                continue
            await _emit(log, f"已关闭 Cookie 同意弹窗：{dismissed}，耗时 {time.monotonic() - started:.1f}s")
            return
        await page.wait_for_timeout(250)
    await _emit(log, f"Cookie 同意弹窗检查完成：未发现可点击弹窗，等待 {time.monotonic() - started:.1f}s")


async def _turnstile_state(page: Page) -> dict[str, str | bool | int]:
    return await page.evaluate(
        """
        () => {
            try {
                const input = document.querySelector('input[name="cf-turnstile-response"]');
                const inputToken = String(input?.value || '').trim();
                if (inputToken) return {present: true, token: inputToken, source: 'hidden-input'};
                if (window.turnstile && typeof window.turnstile.getResponse === 'function') {
                    const response = String(window.turnstile.getResponse() || '').trim();
                    if (response) return {present: true, token: response, source: 'turnstile.getResponse'};
                }
                return {
                    present: !!input || !!document.querySelector(
                        'iframe[src*="challenges.cloudflare.com"], iframe[src*="turnstile"], div.cf-turnstile, [data-sitekey], script[src*="turnstile"]'
                    ),
                    token: '',
                    source: 'none',
                };
            } catch (error) {
                return {present: false, token: '', source: 'read-error'};
            }
        }
        """
    )


async def _fill_turnstile_token(page: Page, token: str) -> int:
    return int(
        await page.evaluate(
            """
            (value) => {
                const input = document.querySelector('input[name="cf-turnstile-response"]');
                if (!input || !value) return 0;
                const setter = Object.getOwnPropertyDescriptor(
                    window.HTMLInputElement.prototype, 'value'
                )?.set;
                if (setter) setter.call(input, value);
                else input.value = value;
                input.dispatchEvent(new Event('input', {bubbles: true}));
                input.dispatchEvent(new Event('change', {bubbles: true}));
                return String(input.value || '').trim().length;
            }
            """,
            token,
        )
        or 0
    )


async def _notify_turnstile_success(page: Page, token: str) -> bool:
    """Notify Student Beans' Turnstile component after rehydrating a token."""
    return bool(
        await page.evaluate(
            """
            (value) => {
                const widget = document.querySelector('#cf-turnstile');
                if (!widget) return false;
                const fiberKey = Object.keys(widget).find((key) =>
                    key.startsWith('__reactFiber') || key.startsWith('__reactInternalInstance')
                );
                let fiber = fiberKey ? widget[fiberKey] : null;
                for (let depth = 0; fiber && depth < 8; depth += 1, fiber = fiber.return) {
                    const props = fiber.memoizedProps || {};
                    if (typeof props.onSuccess === 'function') {
                        props.onSuccess(value);
                        return true;
                    }
                }
                return false;
            }
            """,
            token,
        )
        or False
    )


async def _apply_solver_token(
    page: Page,
    solver_token: str,
    log: LogCallback | None = None,
) -> None:
    if len(solver_token) < TURNSTILE_TOKEN_MIN_LENGTH:
        raise RuntimeError("FlareSolverr token 长度不足")
    wait_started = time.monotonic()
    timeout_seconds = TURNSTILE_APPEAR_TIMEOUT_MS / 1000
    await _emit(log, f"等待页面加载 FlareSolverr token 回填位置（最长 {timeout_seconds:.0f} 秒）")
    appear_deadline = wait_started + timeout_seconds
    last_state_log = 0.0
    while time.monotonic() < appear_deadline:
        state = await _turnstile_state(page)
        token = str(state.get("token") or "").strip()
        if len(token) >= TURNSTILE_TOKEN_MIN_LENGTH:
            if await _notify_turnstile_success(page, token):
                await _emit(log, f"页面已有有效 token，来源={state.get('source', 'unknown')}，长度={len(token)}，已触发页面回调")
                return
        filled = await _fill_turnstile_token(page, solver_token)
        if filled >= TURNSTILE_TOKEN_MIN_LENGTH:
            if await _notify_turnstile_success(page, solver_token):
                await _emit(log, f"FlareSolverr token 已回填并触发页面回调，长度={filled}")
                return
            await _emit(log, "FlareSolverr token 已回填，等待页面 Turnstile 回调")
        now = time.monotonic()
        if now - last_state_log >= 5:
            remaining = max(0.0, appear_deadline - now)
            await _emit(
                log,
                "Turnstile 状态："
                f"present={bool(state.get('present'))} "
                f"source={state.get('source', 'unknown')} "
                f"token长度={len(token)} "
                f"已等待={now - wait_started:.1f}s 剩余={remaining:.1f}s",
            )
            last_state_log = now
        await asyncio.sleep(TURNSTILE_POLL_INTERVAL_SECONDS)
    elapsed = time.monotonic() - wait_started
    await _emit(log, f"Turnstile 回填等待超时：实际等待 {elapsed:.1f}s，未触发页面回调")
    raise RuntimeError("FlareSolverr token 无法触发登录页面 Turnstile 回调")


def _login_form_inputs(page: Page):
    return (
        page.locator(
            'input[type="email"], input[name="user[email]"], input[name="email"]'
        ).first,
        page.locator(
            'input[type="password"], input[name="user[password]"], input[name="password"]'
        ).first,
    )


def _page_url(page: Page) -> str:
    try:
        value = str(page.url or "")
        parsed = urlsplit(value)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return parsed.path or "<unavailable>"
    except Exception:
        return "<unavailable>"


async def _login_form_matches(page: Page, account: Account) -> bool:
    email, password = _login_form_inputs(page)
    try:
        return (
            await email.input_value() == account.email
            and await password.input_value() == account.password
        )
    except Exception:
        return False


async def _fill_login_form(page: Page, account: Account) -> None:
    email, password = _login_form_inputs(page)
    await email.wait_for(state="visible", timeout=FORM_TIMEOUT_MS)
    await password.wait_for(state="visible", timeout=FORM_TIMEOUT_MS)
    for attempt in range(3):
        await email.fill(account.email)
        await password.fill(account.password)
        if await _login_form_matches(page, account):
            return
        if attempt < 2:
            await page.wait_for_timeout(500)
            email, password = _login_form_inputs(page)
            await email.wait_for(state="visible", timeout=FORM_TIMEOUT_MS)
            await password.wait_for(state="visible", timeout=FORM_TIMEOUT_MS)
    raise RuntimeError("登录表单填充后内容未保持")


async def _wait_for_submit_enabled(
    page: Page,
    timeout_ms: int = FORM_TIMEOUT_MS,
    log: LogCallback | None = None,
    email: str = "",
) -> None:
    """Wait for the React form to enable Log in after Turnstile success."""
    started = time.monotonic()
    timeout_seconds = timeout_ms / 1000
    await _emit(log, f"{email}：等待 Log in 按钮启用（最长 {timeout_seconds:.0f} 秒）")
    try:
        await page.wait_for_function(
            """
            () => {
                const buttons = Array.from(
                    document.querySelectorAll('form[aria-label="form"] button')
                );
                const button = buttons.reverse().find(
                    (node) => String(node.innerText || '').trim() === 'Log in'
                );
                return !!button && !button.disabled
                    && button.getAttribute('aria-disabled') !== 'true';
            }
            """,
            timeout=timeout_ms,
        )
    except PlaywrightTimeoutError as exc:
        elapsed = time.monotonic() - started
        await _emit(log, f"{email}：Log in 按钮启用等待超时，实际等待 {elapsed:.1f}s")
        raise RuntimeError(f"登录按钮在 {timeout_seconds:.0f} 秒内未启用") from exc
    except Exception as exc:
        elapsed = time.monotonic() - started
        await _emit(
            log,
            f"{email}：Log in 按钮启用等待提前异常，实际等待 {elapsed:.1f}s，"
            f"异常={type(exc).__name__}: {str(exc).splitlines()[0][:160]}",
        )
        raise
    elapsed = time.monotonic() - started
    await _emit(log, f"{email}：Log in 按钮已启用，实际等待 {elapsed:.1f}s")


async def _login_once(
    browser: Browser,
    account: Account,
    screenshot_dir: Path,
    debug: bool,
    solver_solution: FlareSolverSolution,
    log: LogCallback | None = None,
) -> dict[str, str | bool]:
    attempt_started = time.monotonic()
    context_options: dict[str, str] = {"locale": "en-GB"}
    if solver_solution and solver_solution.user_agent:
        context_options["user_agent"] = solver_solution.user_agent
    context = await browser.new_context(**context_options)
    page = await context.new_page()
    result: dict[str, str | bool] = {"email": account.email, "success": False, "message": "登录失败"}
    stage = "初始化"
    stage_started = attempt_started
    try:
        if solver_solution and solver_solution.cookies:
            try:
                await context.add_cookies(solver_solution.cookies)
                await _emit(log, f"FlareSolverr cookies 已注入：{len(solver_solution.cookies)} 条")
            except Exception as exc:
                await _emit(log, f"FlareSolverr cookies 注入失败：{type(exc).__name__}")
        stage = "加载登录页面"
        stage_started = time.monotonic()
        await _emit(log, f"{account.email}：阶段开始={stage}，最长 {PAGE_TIMEOUT_MS / 1000:.0f} 秒")
        await page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
        await _emit(log, f"{account.email}：登录页面已加载，阶段耗时 {time.monotonic() - stage_started:.1f}s，等待表单")
        stage = "填写账号"
        stage_started = time.monotonic()
        await _emit(log, f"{account.email}：阶段开始={stage}，最长 {FORM_TIMEOUT_MS / 1000:.0f} 秒")
        await _dismiss_cookie_consent(page, log)
        await _fill_login_form(page, account)
        await _dismiss_cookie_consent(page, log)
        if not await _login_form_matches(page, account):
            await _emit(log, f"{account.email}：Cookie 弹窗处理后表单被重置，重新填写")
            await _fill_login_form(page, account)
        await _emit(log, f"{account.email}：账号信息已填写，阶段耗时 {time.monotonic() - stage_started:.1f}s")
        stage = "Turnstile 回填"
        stage_started = time.monotonic()
        await _emit(log, f"{account.email}：阶段开始={stage}，最长 {TURNSTILE_APPEAR_TIMEOUT_MS / 1000:.0f} 秒")
        await _apply_solver_token(page, solver_solution.token, log)
        if not await _login_form_matches(page, account):
            await _emit(log, f"{account.email}：Turnstile 回调后表单被重置，重新填写")
            await _fill_login_form(page, account)
        await _emit(log, f"{account.email}：Turnstile 回调阶段完成，耗时 {time.monotonic() - stage_started:.1f}s")
        stage = "提交登录"
        stage_started = time.monotonic()
        await _emit(log, f"{account.email}：阶段开始={stage}，按钮启用和结果等待各最长 {FORM_TIMEOUT_MS / 1000:.0f} 秒")
        submit = page.locator('form[aria-label="form"] button').filter(
            has_text=re.compile(r"^\s*Log in\s*$")
        ).last
        await submit.wait_for(state="visible", timeout=FORM_TIMEOUT_MS)
        if not await _login_form_matches(page, account):
            await _emit(log, f"{account.email}：提交前表单被重置，重新填写")
            await _fill_login_form(page, account)
        await _wait_for_submit_enabled(page, FORM_TIMEOUT_MS, log, account.email)
        await _emit(log, f"{account.email}：正在提交登录")
        login_response_started = time.monotonic()
        try:
            async with page.expect_response(
                lambda response: urlsplit(response.url).path == LOGIN_SUBMIT_PATH,
                timeout=FORM_TIMEOUT_MS,
            ) as response_info:
                await submit.click(timeout=FORM_TIMEOUT_MS)
            login_response = await response_info.value
            await _emit(
                log,
                f"{account.email}：登录 API 已响应，status={login_response.status}，"
                f"耗时 {time.monotonic() - login_response_started:.1f}s",
            )
        except PlaywrightTimeoutError:
            await _emit(
                log,
                f"{account.email}：登录 API 响应等待超时，实际等待 {time.monotonic() - login_response_started:.1f}s，"
                "继续检查页面结果",
            )
        result_wait_started = time.monotonic()
        await _emit(log, f"{account.email}：已点击 Log in，等待登录结果（最长 {LOGIN_RESULT_TIMEOUT_MS / 1000:.0f} 秒）")
        try:
            await page.wait_for_url(_is_login_result_url, timeout=LOGIN_RESULT_TIMEOUT_MS)
        except PlaywrightTimeoutError:
            await _emit(
                log,
                f"{account.email}：登录结果等待超时，实际等待 {time.monotonic() - result_wait_started:.1f}s，"
                f"当前 URL={_page_url(page)}",
            )
        except Exception as exc:
            await _emit(
                log,
                f"{account.email}：登录结果等待提前异常，实际等待 {time.monotonic() - result_wait_started:.1f}s，"
                f"异常={type(exc).__name__}: {str(exc).splitlines()[0][:160]}",
            )
        else:
            await _emit(
                log,
                f"{account.email}：检测到登录结果地址，等待耗时 {time.monotonic() - result_wait_started:.1f}s，"
                f"当前 URL={_page_url(page)}",
            )

        still_has_password = await page.locator('input[type="password"]').count() > 0
        current_url = _page_url(page)
        if current_url and urlsplit(current_url).path != LOGIN_PATH and not still_has_password:
            result.update(success=True, message="登录成功")
            await _emit(log, f"{account.email}：登录成功")
        else:
            error = page.locator('[role="alert"], .error, [class*="error"]').first
            message = (await error.inner_text()).strip() if await error.count() else "站点未确认登录成功"
            result["message"] = message[:300]
            await _emit(log, f"{account.email}：登录未成功 - {result['message']}")
    except Exception as exc:
        result["message"] = str(exc).splitlines()[0][:300]
        await _emit(
            log,
            f"{account.email}：执行失败（阶段：{stage}，阶段耗时 {time.monotonic() - stage_started:.1f}s，"
            f"总耗时 {time.monotonic() - attempt_started:.1f}s） - {result['message']}",
        )
    finally:
        await _emit(
            log,
            f"{account.email}：准备截图，阶段={stage}，总耗时 {time.monotonic() - attempt_started:.1f}s，"
            f"当前 URL={_page_url(page)}",
        )
        if debug:
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            safe_email = re.sub(r"[^A-Za-z0-9_.-]", "_", account.email)[:80]
            screenshot_started = time.monotonic()
            screenshot_time = datetime.now(timezone.utc)
            stamp = screenshot_time.strftime("%Y%m%dT%H%M%S%f")[:-3] + "Z"
            path = screenshot_dir / f"{stamp}-{safe_email}.png"
            try:
                await _emit(log, f"{account.email}：截图开始，UTC={screenshot_time.isoformat(timespec='milliseconds')}")
                await page.screenshot(path=str(path), full_page=True)
                result["screenshot"] = path.name
                await _emit(log, f"{account.email}：截图完成，文件={path.name}，耗时 {time.monotonic() - screenshot_started:.1f}s")
            except Exception as exc:
                await _emit(log, f"{account.email}：截图失败，异常={type(exc).__name__}: {str(exc).splitlines()[0][:160]}")
        await context.close()
        await _emit(log, f"{account.email}：浏览器上下文已关闭，总耗时 {time.monotonic() - attempt_started:.1f}s")
    return result


async def run_logins(
    accounts: list[Account],
    proxies: list[str],
    screenshot_dir: Path,
    debug: bool,
    log: LogCallback | None = None,
) -> list[dict[str, str | bool]]:
    await _emit(log, f"任务开始，共 {len(accounts)} 个账号")
    proxy_pool = _ProxyPool(proxies)

    async def run_account(index: int, account: Account) -> dict[str, str | bool]:
        await _emit(log, f"开始处理第 {index + 1}/{len(accounts)} 个账号：{account.email}")
        last_result: dict[str, str | bool] | None = None
        for attempt in range(1, MAX_ACCOUNT_ATTEMPTS + 1):
            attempt_started = time.monotonic()
            preferred_index = (index + attempt - 1) % len(proxy_pool) if proxy_pool else 0
            proxy, proxy_index = await proxy_pool.acquire(preferred_index)
            try:
                if proxy:
                    await _emit(log, f"{account.email}：第 {attempt}/{MAX_ACCOUNT_ATTEMPTS} 次尝试，使用代理 {proxy_index + 1}/{len(proxy_pool)}（已独占）")
                else:
                    await _emit(log, f"{account.email}：第 {attempt}/{MAX_ACCOUNT_ATTEMPTS} 次尝试，使用直连（已独占）")
                try:
                    solver_solution = await solve_turnstile(
                        LOGIN_URL,
                        proxy,
                        log,
                        email=account.email,
                        password=account.password,
                        return_screenshot=debug,
                        collect_codes=True,
                        collect_url=CODE_COLLECTION_URL,
                    )
                    if solver_solution is None:
                        last_result = {
                            "email": account.email,
                            "success": False,
                            "message": "FlareSolverr 未完成同页登录",
                        }
                        await _emit(log, f"{account.email}：FlareSolverr 未完成同页登录，本次尝试失败")
                    else:
                        login_success = solver_solution.login_success is True
                        code_collection_success = solver_solution.code_collection_success is True
                        success = login_success and code_collection_success
                        last_result = {
                            "email": account.email,
                            "success": success,
                            "login_success": login_success,
                            "code_collection_success": code_collection_success,
                            "message": (
                                solver_solution.code_collection_message
                                if login_success and not code_collection_success
                                else solver_solution.login_message
                                or ("登录成功并完成代码采集" if success else "站点未确认登录成功")
                            ),
                        }
                        if solver_solution.code_results:
                            last_result["codes"] = solver_solution.code_results
                        if solver_solution.login_response_status is not None:
                            await _emit(
                                log,
                                f"{account.email}：同一 Camoufox 登录 API status={solver_solution.login_response_status}，"
                                f"登录结果={login_success}，"
                                f"耗时={solver_solution.login_elapsed or 0:.1f}s",
                            )
                        if login_success:
                            await _emit(log, f"{account.email}：登录完成，登录状态已验证")
                            await _emit(log, f"{account.email}：正在访问 VOXI 界面")
                            if code_collection_success:
                                code_count = sum(
                                    1 for item in (solver_solution.code_results or [])
                                    if isinstance(item, dict) and item.get("ok")
                                )
                                next_date = format_singapore_time(
                                    _first_code_date(solver_solution.code_results)
                                )
                                await _emit(
                                    log,
                                    f"{account.email}：已提取 {code_count} 组优惠码，下次时间={next_date or '未知'}",
                                )
                            else:
                                await _emit(log, f"{account.email}：优惠码提取失败")
                        else:
                            await _emit(log, f"{account.email}：登录状态验证失败")
                        if login_success:
                            await _emit(
                                log,
                                f"{account.email}：代码采集结果={code_collection_success}，"
                                f"条数={len(solver_solution.code_results or [])}，"
                                f"耗时={solver_solution.code_collection_elapsed or 0:.1f}s",
                            )
                        if debug and solver_solution.screenshot and not solver_solution.debug_screenshots:
                            try:
                                safe_email = re.sub(r"[^A-Za-z0-9_.-]", "_", account.email)[:80]
                                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")[:-3] + "Z"
                                screenshot_path = screenshot_dir / f"{stamp}-{safe_email}.png"
                                screenshot_path.parent.mkdir(parents=True, exist_ok=True)
                                screenshot_path.write_bytes(base64.b64decode(solver_solution.screenshot, validate=True))
                                last_result["screenshot"] = screenshot_path.name
                                await _emit(log, f"{account.email}：FlareSolverr 同页截图已保存，文件={screenshot_path.name}")
                            except Exception as exc:
                                await _emit(log, f"{account.email}：FlareSolverr 同页截图保存失败，异常={type(exc).__name__}")
                        if debug and solver_solution.debug_screenshots:
                            safe_email = re.sub(r"[^A-Za-z0-9_.-]", "_", account.email)[:80]
                            debug_paths: list[str] = []
                            for screenshot_index, item in enumerate(solver_solution.debug_screenshots, start=1):
                                stage = re.sub(r"[^A-Za-z0-9_.-]", "_", str(item.get("stage") or "stage"))[:48]
                                try:
                                    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")[:-3] + "Z"
                                    screenshot_path = screenshot_dir / (
                                        f"{stamp}-{safe_email}-{screenshot_index:02d}-{stage}.png"
                                    )
                                    screenshot_path.parent.mkdir(parents=True, exist_ok=True)
                                    screenshot_path.write_bytes(
                                        base64.b64decode(str(item.get("image") or ""), validate=True)
                                    )
                                    debug_paths.append(screenshot_path.name)
                                    await _emit(
                                        log,
                                        f"{account.email}：调试截图已保存，阶段={stage}，文件={screenshot_path.name}",
                                    )
                                except Exception as exc:
                                    await _emit(
                                        log,
                                        f"{account.email}：调试截图保存失败，阶段={stage}，异常={type(exc).__name__}",
                                    )
                            if debug_paths:
                                last_result["debug_screenshots"] = debug_paths
                        await _emit(log, f"{account.email}：同一 Camoufox 会话登录完成，成功={success} - {last_result['message']}")
                except Exception as exc:
                    last_result = {
                        "email": account.email,
                        "success": False,
                        "message": str(exc).splitlines()[0][:300],
                    }
                    await _emit(log, f"{account.email}：第 {attempt}/{MAX_ACCOUNT_ATTEMPTS} 次同页登录异常 - {last_result['message']}")
                await _emit(
                    log,
                    f"{account.email}：第 {attempt}/{MAX_ACCOUNT_ATTEMPTS} 次尝试结束，"
                    f"成功={bool(last_result and last_result.get('success'))}，"
                    f"耗时 {time.monotonic() - attempt_started:.1f}s",
                )
            finally:
                await proxy_pool.release(proxy_index)
                await _emit(log, f"{account.email}：已释放当前代理占用")
            if last_result and last_result.get("success"):
                break
            if attempt < MAX_ACCOUNT_ATTEMPTS:
                retry_reason = "登录或代码采集未完成"
                if last_result and last_result.get("login_success") and not last_result.get("code_collection_success"):
                    retry_reason = "登录成功但代码采集未完成"
                await _emit(log, f"{account.email}：第 {attempt + 1}/{MAX_ACCOUNT_ATTEMPTS} 次账号重试（{retry_reason}），FlareSolverr 将创建新的 Camoufox 会话并切换代理")
        return last_result or {"email": account.email, "success": False, "message": "无可用代理"}

    workers = [asyncio.create_task(run_account(index, account)) for index, account in enumerate(accounts)]
    try:
        results = await asyncio.gather(*workers)
    finally:
        for worker in workers:
            if not worker.done():
                worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
    await _emit(log, "任务执行完成")
    return results
