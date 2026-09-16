from __future__ import annotations

import asyncio
import json
import os
import re
from contextlib import suppress
from dataclasses import dataclass
from typing import Awaitable, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import Request, urlopen
from uuid import uuid4


LogCallback = Callable[[str], Awaitable[None]]
AWS_WAF_VISUAL_FAILURE_LOCATION = "AWS WAF视觉识别"
FLARESOLVERR_MAX_CONCURRENCY = 3
FLARESOLVERR_SLOTS = asyncio.Semaphore(FLARESOLVERR_MAX_CONCURRENCY)


class FlareSolverFailure(RuntimeError):
    def __init__(self, location: str, detail: str) -> None:
        super().__init__(detail)
        self.location = location


@dataclass(frozen=True)
class FlareSolverSolution:
    token: str
    cookies: list[dict[str, object]]
    user_agent: str
    login_success: bool | None = None
    login_message: str = ""
    login_response_status: int | None = None
    login_elapsed: float | None = None
    login_auth_confirmed: bool | None = None
    login_graphql_logged_in: bool | None = None
    login_viewer_token_present: bool | None = None
    login_register_visible: bool | None = None
    login_login_visible: bool | None = None
    login_account_marker_visible: bool | None = None
    login_auth_cookie_names: list[str] = None
    login_steps: list[dict[str, object]] = None
    screenshot: str = ""
    debug_screenshots: list[dict[str, str]] = None
    code_results: list[dict[str, object]] = None
    code_collection_success: bool | None = None
    code_collection_message: str = ""
    code_collection_elapsed: float | None = None


def _endpoint() -> str:
    value = os.environ.get("SBEANS_FLARESOLVERR_URL", "").strip().rstrip("/")
    if not value:
        return ""
    return value if value.endswith("/v1") else f"{value}/v1"


def _timeout_ms() -> int:
    try:
        return max(1_000, int(os.environ.get("SBEANS_FLARESOLVERR_TIMEOUT_MS", "180000")))
    except ValueError:
        return 180_000


def _proxy_payload(proxy: str) -> dict[str, str] | None:
    if not proxy:
        return None
    parsed = urlsplit(proxy)
    if not parsed.scheme or not parsed.hostname or not parsed.port:
        raise ValueError("FlareSolverr 代理格式无效")
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    payload: dict[str, str] = {
        "url": f"{parsed.scheme}://{host}:{parsed.port}",
    }
    if parsed.username is not None:
        payload["username"] = unquote(parsed.username)
    if parsed.password is not None:
        payload["password"] = unquote(parsed.password)
    return payload


def _safe_remote_message(value: object) -> str:
    message = str(value or "").replace("\x00", " ").strip()
    if message.lower().startswith("error:"):
        message = message[6:].strip()
    message = re.sub(
        r"(?i)(api[_ -]?key|token|password|secret|authorization|cookie)\s*[:=]\s*[^\s,;]+",
        r"\1=<redacted>",
        message,
    )
    message = re.sub(
        r"(?i)([?&](?:api[_-]?key|key|token|password|secret)=)[^&\s]+",
        r"\1<redacted>",
        message,
    )
    message = re.sub(r"(?i)bearer\s+[^\s,;]+", "Bearer <redacted>", message)
    return " ".join(message.split())[:300]


def _response_message(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    for key in ("message", "error", "detail"):
        message = _safe_remote_message(value.get(key))
        if message:
            return message
    return ""


def _failure_location(message: str) -> str:
    lowered = str(message or "").lower()
    if any(marker in lowered for marker in ("vision api", "aws waf", "captcha")):
        return AWS_WAF_VISUAL_FAILURE_LOCATION
    if "turnstile" in lowered:
        return "Turnstile"
    if any(marker in lowered for marker in ("voxi", "code collection", "graphql")):
        return "VOXI代码采集"
    if any(marker in lowered for marker in ("login", "登录")):
        return "登录提交"
    return "FlareSolverr请求"


def _http_error_message(exc: HTTPError) -> str:
    try:
        raw = exc.read(16_384).decode("utf-8", errors="replace")
    except Exception:
        return ""
    try:
        detail = _response_message(json.loads(raw))
    except json.JSONDecodeError:
        detail = _safe_remote_message(raw)
    return detail


def _post_json(endpoint: str, payload: dict[str, object], timeout_seconds: float) -> dict[str, object]:
    request = Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = _http_error_message(exc)
        message = f"FlareSolverr HTTP {exc.code}"
        if detail:
            message += f": {detail}"
        raise RuntimeError(message) from exc
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"FlareSolverr 请求失败：{type(exc).__name__}") from exc


async def _post_json_async(
    endpoint: str, payload: dict[str, object], timeout_seconds: float
) -> dict[str, object]:
    return await asyncio.to_thread(_post_json, endpoint, payload, timeout_seconds)


async def _cancel_camoufox_request(endpoint: str, request_id: str) -> None:
    with suppress(Exception):
        await asyncio.wait_for(
            _post_json_async(
                endpoint,
                {"cmd": "request.cancel", "requestId": request_id},
                10,
            ),
            timeout=10,
        )


def _cookies(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, object]] = []
    for raw in value:
        if not isinstance(raw, dict) or not raw.get("name") or raw.get("value") is None:
            continue
        domain = raw.get("domain")
        if not domain:
            continue
        item: dict[str, object] = {
            "name": str(raw["name"]),
            "value": str(raw["value"]),
            "domain": str(domain),
            "path": str(raw.get("path") or "/"),
        }
        if isinstance(raw.get("expires"), (int, float)) and raw["expires"] > 0:
            item["expires"] = raw["expires"]
        for key in ("httpOnly", "secure"):
            if isinstance(raw.get(key), bool):
                item[key] = raw[key]
        if raw.get("sameSite") in {"Strict", "Lax", "None"}:
            item["sameSite"] = raw["sameSite"]
        result.append(item)
    return result


async def _emit(log: LogCallback | None, message: str) -> None:
    if log:
        await log(message)


async def solve_turnstile(
    url: str,
    proxy: str,
    log: LogCallback | None = None,
    *,
    email: str = "",
    password: str = "",
    return_screenshot: bool = False,
    collect_codes: bool = False,
    collect_url: str = "",
    raise_on_failure: bool = False,
) -> FlareSolverSolution | None:
    endpoint = _endpoint()
    if not endpoint:
        return None

    timeout_ms = _timeout_ms()
    request_id = uuid4().hex
    same_browser_login = bool(email and password)
    # One wall-clock limit covers the complete Camoufox session.
    request_timeout = timeout_ms / 1000
    if same_browser_login:
        await _emit(log, "FlareSolverr：开始同一 Camoufox 会话求解并提交登录")
        if collect_codes:
            await _emit(log, "FlareSolverr：进入 VOXI 后等待 10 秒；每个计划 POST 当前只尝试 1 次")
    else:
        await _emit(log, "FlareSolverr：开始请求 Turnstile solver")
    try:
        proxy_data = _proxy_payload(proxy)
        try:
            async with FLARESOLVERR_SLOTS:
                solved = await _post_json_async(
                    endpoint,
                    {
                        "cmd": "request.get",
                        "requestId": request_id,
                        "url": url,
                        "browser": "camoufox",
                        "proxy": proxy_data,
                        "maxTimeout": timeout_ms,
                        "tabs_till_verify": 1,
                        "waitInSeconds": 1,
                        "returnOnlyCookies": not same_browser_login,
                        "returnScreenshot": return_screenshot,
                        "sbeans_login": same_browser_login,
                        "sbeans_email": email if same_browser_login else None,
                        "sbeans_password": password if same_browser_login else None,
                        "sbeans_login_timeout_ms": 120_000 if same_browser_login else None,
                        "sbeans_collect_codes": bool(same_browser_login and collect_codes),
                        "sbeans_collect_url": collect_url if same_browser_login and collect_codes else None,
                        "sbeans_collect_timeout_ms": 120_000 if same_browser_login and collect_codes else None,
                    },
                    request_timeout,
                )
        except asyncio.CancelledError:
            await asyncio.shield(_cancel_camoufox_request(endpoint, request_id))
            raise
        except Exception:
            await _cancel_camoufox_request(endpoint, request_id)
            raise
        if solved.get("status") != "ok":
            detail = _response_message(solved)
            raise RuntimeError(f"FlareSolverr 返回错误：{detail or '未完成页面求解'}")
        solution = solved.get("solution")
        if not isinstance(solution, dict):
            raise RuntimeError("FlareSolverr 返回内容缺少 solution")
        token = str(solution.get("turnstile_token") or "").strip()
        if not token:
            raise RuntimeError("FlareSolverr 未返回 Turnstile token")
        cookies = _cookies(solution.get("cookies"))
        user_agent = str(solution.get("userAgent") or "").strip()
        has_aws_waf_token = any(cookie.get("name") == "aws-waf-token" for cookie in cookies)
        login_success = solution.get("sbeans_login_success")
        if not isinstance(login_success, bool):
            login_success = None
        login_response_status = solution.get("sbeans_login_response_status")
        if not isinstance(login_response_status, int):
            login_response_status = None
        login_elapsed = solution.get("sbeans_login_elapsed")
        if not isinstance(login_elapsed, (int, float)):
            login_elapsed = None
        login_auth_confirmed = solution.get("sbeans_login_auth_confirmed")
        if not isinstance(login_auth_confirmed, bool):
            login_auth_confirmed = None
        login_graphql_logged_in = solution.get("sbeans_login_graphql_logged_in")
        if not isinstance(login_graphql_logged_in, bool):
            login_graphql_logged_in = None
        login_viewer_token_present = solution.get("sbeans_login_viewer_token_present")
        if not isinstance(login_viewer_token_present, bool):
            login_viewer_token_present = None
        login_register_visible = solution.get("sbeans_login_register_visible")
        if not isinstance(login_register_visible, bool):
            login_register_visible = None
        login_login_visible = solution.get("sbeans_login_login_visible")
        if not isinstance(login_login_visible, bool):
            login_login_visible = None
        login_account_marker_visible = solution.get("sbeans_login_account_marker_visible")
        if not isinstance(login_account_marker_visible, bool):
            login_account_marker_visible = None
        raw_auth_cookie_names = solution.get("sbeans_login_auth_cookie_names")
        login_auth_cookie_names = (
            [str(name) for name in raw_auth_cookie_names if name]
            if isinstance(raw_auth_cookie_names, list)
            else []
        )
        code_results = solution.get("sbeans_code_results")
        if not isinstance(code_results, list):
            code_results = []
        code_results = [item for item in code_results if isinstance(item, dict)]
        code_attempts = ",".join(
            f"{item.get('planId', 'unknown')}:{item.get('attempts', '?')}"
            for item in code_results
        ) or "无"
        code_collection_success = solution.get("sbeans_code_collection_success")
        if not isinstance(code_collection_success, bool):
            code_collection_success = None
        code_collection_elapsed = solution.get("sbeans_code_collection_elapsed")
        if not isinstance(code_collection_elapsed, (int, float)):
            code_collection_elapsed = None
        raw_debug_screenshots = solution.get("sbeans_debug_screenshots")
        debug_screenshots = []
        if isinstance(raw_debug_screenshots, list):
            for item in raw_debug_screenshots:
                if not isinstance(item, dict):
                    continue
                stage = str(item.get("stage") or "").strip()
                image = str(item.get("image") or "").strip()
                if stage and image:
                    debug_screenshots.append({"stage": stage, "image": image})
        raw_login_steps = solution.get("sbeans_login_steps")
        login_steps: list[dict[str, object]] = []
        if isinstance(raw_login_steps, list):
            for item in raw_login_steps:
                if not isinstance(item, dict):
                    continue
                stage = str(item.get("stage") or "").strip()
                status = str(item.get("status") or "").strip()
                if not stage or not status:
                    continue
                step: dict[str, object] = {
                    "stage": stage,
                    "status": status,
                    "url": str(item.get("url") or ""),
                }
                for key in ("response_status", "redirect", "elapsed", "reason", "error", "target", "viewer_token", "ready_state", "attempts"):
                    if key in item and item[key] not in (None, ""):
                        step[key] = item[key]
                login_steps.append(step)
        for step in login_steps:
            details = " ".join(
                f"{key}={value}" for key, value in step.items()
                if key not in {"stage", "status", "url"}
            )
            await _emit(
                log,
                f"FlareSolverr步骤：{step['stage']} status={step['status']} "
                f"url={step['url']} {details}".rstrip(),
            )
        await _emit(
            log,
            (
                f"FlareSolverr：同一 Camoufox 会话完成，登录成功={login_success}，"
                f"API status={login_response_status if login_response_status is not None else '未观测'}，"
                f"登录耗时={login_elapsed:.1f}s，代码采集成功={code_collection_success}，"
                f"代码条数={len(code_results)}，POST尝试={code_attempts}，token长度={len(token)}，cookies={len(cookies)}，"
                f"AWS WAF={'已获取' if has_aws_waf_token else '未获取'}，"
                f"调试截图={','.join(item['stage'] for item in debug_screenshots) or '无'}"
            ) if same_browser_login else (
                f"FlareSolverr：求解完成，token长度={len(token)}，cookies={len(cookies)}，"
                f"AWS WAF={'已获取' if has_aws_waf_token else '未获取'}"
            ),
        )
        return FlareSolverSolution(
            token=token,
            cookies=cookies,
            user_agent=user_agent,
            login_success=login_success,
            login_message=str(solution.get("sbeans_login_message") or ""),
            login_response_status=login_response_status,
            login_elapsed=float(login_elapsed) if login_elapsed is not None else None,
            login_auth_confirmed=login_auth_confirmed,
            login_graphql_logged_in=login_graphql_logged_in,
            login_viewer_token_present=login_viewer_token_present,
            login_register_visible=login_register_visible,
            login_login_visible=login_login_visible,
            login_account_marker_visible=login_account_marker_visible,
            login_auth_cookie_names=login_auth_cookie_names,
            login_steps=login_steps,
            screenshot=str(solution.get("screenshot") or ""),
            debug_screenshots=debug_screenshots,
            code_results=code_results,
            code_collection_success=code_collection_success,
            code_collection_message=str(solution.get("sbeans_code_collection_message") or ""),
            code_collection_elapsed=(
                float(code_collection_elapsed) if code_collection_elapsed is not None else None
            ),
        )
    except Exception as exc:
        detail = str(exc).splitlines()[0][:300]
        location = _failure_location(detail)
        await _emit(
            log,
            f"FlareSolverr：求解失败，位置={location}，错误={detail}，本次账号尝试失败",
        )
        if raise_on_failure:
            raise FlareSolverFailure(location, detail) from exc
        return None
