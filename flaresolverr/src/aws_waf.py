from __future__ import annotations

import base64
import json
import logging
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlsplit, urlunsplit
from urllib.request import Request, urlopen


GEMINI_MODEL = "gemini-3.6-flash"
VISION_MODE_CHAT_COMPLETIONS = "chat_completions"
VISION_MODE_RESPONSES = "responses"
VISION_TIMEOUT_SECONDS = 45
VISION_MIN_INTERVAL_SECONDS = 20.0
VISION_RATE_LIMIT_RETRY_SECONDS = 30.0
AWS_WAF_DETECT_TIMEOUT_MS = 15_000
AWS_WAF_TOKEN_MIN_LENGTH = 80
AWS_WAF_UI_TIMEOUT_MS = 30_000

_SENSITIVE_RESPONSE_FIELDS = (
    "api_key",
    "apikey",
    "token",
    "voucher",
    "secret",
    "password",
    "cookie",
    "authorization",
)

_VISION_REQUEST_LOCK = Lock()
_VISION_LAST_REQUEST_FINISHED = 0.0


@dataclass(frozen=True)
class VisionConfig:
    api_url: str
    api_key: str
    model: str
    mode: str
    auth_header: str
    auth_prefix: str


class AwsWafError(RuntimeError):
    """Raised when the AWS WAF challenge cannot be completed."""


class AwsWafNetworkState:
    """Capture AWS WAF browser requests without logging sensitive values."""

    def __init__(self) -> None:
        self.problem_urls: list[str] = []
        self.problem_payloads: list[tuple[str, dict[str, object]]] = []
        self.voucher_urls: list[str] = []
        self.verify_statuses: list[int] = []
        self.voucher_statuses: list[int] = []
        self.verify_diagnostics: list[dict[str, object]] = []
        self.voucher_diagnostics: list[dict[str, object]] = []
        self._page = None

    def attach(self, page) -> None:
        self._page = page
        page.on("request", self._on_request)
        page.on("response", self._on_response)

    def detach(self) -> None:
        if self._page is not None:
            self._page.remove_listener("request", self._on_request)
            self._page.remove_listener("response", self._on_response)
            self._page = None

    def _on_request(self, request) -> None:
        try:
            parsed = urlsplit(str(request.url or ""))
            host = (parsed.hostname or "").lower()
            path = parsed.path.rstrip("/")
            if path.endswith("/problem") and ".captcha.awswaf.com" in host:
                if parsed.query and "api_key=" in parsed.query:
                    self.problem_urls.append(str(request.url))
                return
            if path.endswith("/voucher") and ".token.awswaf.com" in host:
                self.voucher_urls.append(str(request.url))
                return
        except Exception:
            logging.debug("AWS WAF request capture skipped", exc_info=True)

    def _on_response(self, response) -> None:
        try:
            parsed = urlsplit(str(response.url or ""))
            host = (parsed.hostname or "").lower()
            path = parsed.path.rstrip("/")
            if path.endswith("/problem") and ".captcha.awswaf.com" in host:
                if not parse_qs(parsed.query).get("api_key"):
                    return
                try:
                    payload = json.loads(response.body().decode("utf-8"))
                except (AttributeError, UnicodeDecodeError, json.JSONDecodeError):
                    logging.info(
                        "AWS WAF problem response body was unavailable status=%s",
                        response.status,
                    )
                    return
                if isinstance(payload, dict):
                    self.problem_payloads.append((str(response.url), payload))
                return
            if path.endswith("/verify") and ".captcha.awswaf.com" in host:
                self.verify_statuses.append(int(response.status))
                diagnostic = _response_diagnostic(response)
                self.verify_diagnostics.append(diagnostic)
                logging.info(
                    "AWS WAF verify response diagnostics=%s",
                    json.dumps(diagnostic, sort_keys=True, ensure_ascii=True),
                )
                return
            if path.endswith("/voucher") and ".token.awswaf.com" in host:
                self.voucher_statuses.append(int(response.status))
                diagnostic = _response_diagnostic(response)
                self.voucher_diagnostics.append(diagnostic)
                logging.info(
                    "AWS WAF voucher response diagnostics=%s",
                    json.dumps(diagnostic, sort_keys=True, ensure_ascii=True),
                )
        except Exception:
            logging.debug("AWS WAF response capture skipped", exc_info=True)

    def latest_problem_url(self, page) -> str:
        if self.problem_urls:
            return self.problem_urls[-1]
        try:
            return str(
                page.evaluate(
                    """
                    () => performance.getEntriesByType('resource')
                        .map((entry) => String(entry.name || ''))
                        .filter((value) => {
                            try {
                                const url = new URL(value);
                                return url.hostname.includes('.captcha.awswaf.com')
                                    && url.pathname.endsWith('/problem')
                                    && url.searchParams.has('api_key');
                            } catch (_) {
                                return false;
                            }
                        })
                        .pop() || ''
                    """
                )
                or ""
            )
        except Exception:
            return ""

    def latest_problem_payload(self, problem_url: str) -> dict[str, object] | None:
        for captured_url, payload in reversed(self.problem_payloads):
            if captured_url == problem_url:
                return payload
        return None

def wait_for_problem(page, state: AwsWafNetworkState, timeout_ms: int) -> str:
    """Wait for the real AWS WAF visual challenge request after Log in."""
    deadline = time.monotonic() + max(0, timeout_ms) / 1000
    while time.monotonic() < deadline:
        problem_url = state.latest_problem_url(page)
        if problem_url:
            if state.latest_problem_payload(problem_url) is not None:
                return problem_url
        if state.voucher_urls:
            return ""
        page.wait_for_timeout(250)
    return state.latest_problem_url(page)


def _safe_response_text(value: object) -> str:
    message = str(value or "").replace("\x00", " ").strip()
    message = re.sub(
        r"(?i)(api[_ -]?key|token|password|secret|authorization|cookie|voucher)"
        r"\s*[:=]\s*[^\s,;]+",
        r"\1=<redacted>",
        message,
    )
    message = re.sub(r"(?i)bearer\s+[^\s,;]+", "Bearer <redacted>", message)
    return " ".join(message.split())[:120]


def _response_diagnostic(response) -> dict[str, object]:
    """Summarize an AWS WAF response without retaining its sensitive values."""
    diagnostic: dict[str, object] = {
        "status": int(getattr(response, "status", 0)),
        "body_available": False,
    }
    try:
        raw = response.body()
    except Exception as exc:
        diagnostic["body_error"] = type(exc).__name__
        return diagnostic

    diagnostic["body_available"] = True
    diagnostic["body_bytes"] = len(raw)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError):
        diagnostic["body_format"] = "non_json"
        return diagnostic

    if isinstance(payload, dict):
        diagnostic["body_format"] = "json_object"
        diagnostic["json_keys"] = sorted(
            str(key)
            for key in payload
            if not any(marker in str(key).lower() for marker in _SENSITIVE_RESPONSE_FIELDS)
        )[:20]
        for key in ("success", "valid", "solved", "verified", "accepted", "retry"):
            if isinstance(payload.get(key), bool):
                diagnostic[key] = payload[key]
        for key in ("num_solutions_provided", "num_solutions_required"):
            if isinstance(payload.get(key), (int, float)) and not isinstance(payload.get(key), bool):
                diagnostic[key] = payload[key]
        for key in (
            "errorCode", "error_code", "code", "reason", "message", "error", "detail", "problem"
        ):
            value = payload.get(key)
            if value not in (None, "") and not isinstance(value, (dict, list)):
                diagnostic[key] = _safe_response_text(value)
            elif isinstance(value, dict):
                diagnostic[f"{key}_keys"] = sorted(str(item) for item in value)[:8]
            elif isinstance(value, list):
                diagnostic[f"{key}_items"] = len(value)
        for key in ("captcha_voucher", "voucher", "token"):
            if key in payload:
                value = payload[key]
                diagnostic[f"{key}_present"] = bool(value)
                if value:
                    diagnostic[f"{key}_length"] = len(str(value))
    elif isinstance(payload, list):
        diagnostic["body_format"] = "json_array"
        diagnostic["json_items"] = len(payload)
    else:
        diagnostic["body_format"] = "json_scalar"
    return diagnostic


def _format_response_diagnostic(diagnostic: dict[str, object] | None) -> str:
    if not diagnostic:
        return "none"
    parts = [
        f"status={diagnostic.get('status', 0)}",
        f"body={'yes' if diagnostic.get('body_available') else 'no'}",
    ]
    if diagnostic.get("body_bytes") is not None:
        parts.append(f"bytes={diagnostic['body_bytes']}")
    if diagnostic.get("body_format"):
        parts.append(f"format={diagnostic['body_format']}")
    for key in (
        "success", "valid", "solved", "verified", "accepted", "retry",
        "num_solutions_provided", "num_solutions_required",
        "errorCode", "error_code", "code", "reason", "message", "error", "detail", "problem",
    ):
        if key in diagnostic:
            parts.append(f"{key}={diagnostic[key]}")
    for key in ("reason_keys", "reason_items", "problem_keys", "problem_items"):
        if key in diagnostic:
            parts.append(f"{key}={diagnostic[key]}")
    if diagnostic.get("json_keys"):
        parts.append(f"keys={','.join(str(key) for key in diagnostic['json_keys'][:4])}")
    for key in ("captcha_voucher_present", "voucher_present", "token_present"):
        if key in diagnostic:
            parts.append(f"{key}={diagnostic[key]}")
    return " ".join(parts)[:150]


def parse_solution_indices(text: str, image_count: int) -> list[int]:
    """Parse the vision provider's JSON array and validate challenge indexes."""
    cleaned = re.sub(r"```(?:json)?\s*|\s*```", "", str(text or "")).strip()
    match = re.search(r"\[[\s\S]*?\]", cleaned)
    if not match:
        raise AwsWafError("Vision provider did not return a JSON image-index array")
    try:
        values = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        raise AwsWafError("Vision provider returned invalid JSON image indexes") from exc
    if not isinstance(values, list) or any(
        isinstance(value, bool) or not isinstance(value, int) for value in values
    ):
        raise AwsWafError("Vision provider image indexes must be integers")
    if len(set(values)) != len(values) or any(
        value < 0 or value >= image_count for value in values
    ):
        raise AwsWafError("Vision provider returned an image index outside the challenge grid")
    return values


def _image_mime_type(encoded: str) -> str:
    try:
        header = base64.b64decode(encoded, validate=True)[:12]
    except (ValueError, TypeError):
        return "image/jpeg"
    if header.startswith(b"\x89PNG"):
        return "image/png"
    if header.startswith(b"RIFF") and header[8:12] == b"WEBP":
        return "image/webp"
    return "image/jpeg"


def _vision_config(api_key_override: str = "") -> VisionConfig:
    configured_values = (
        os.environ.get("VISION_API_URL", "").strip(),
        os.environ.get("VISION_API_KEY", "").strip(),
        os.environ.get("VISION_MODEL", "").strip(),
    )
    if not any(configured_values):
        api_key = (api_key_override or os.environ.get("GEMINI_API_KEY", "")).strip()
        if not api_key:
            raise AwsWafError(
                "VISION_API_KEY or legacy GEMINI_API_KEY is not configured"
            )
        return VisionConfig(
            api_url="",
            api_key=api_key,
            model=GEMINI_MODEL,
            mode="gemini",
            auth_header="",
            auth_prefix="",
        )

    api_url = os.environ.get("VISION_API_URL", "").strip()
    api_key = (api_key_override or os.environ.get("VISION_API_KEY", "")).strip()
    model = os.environ.get("VISION_MODEL", "").strip()
    if not api_url:
        raise AwsWafError("VISION_API_URL is not configured")
    if not api_key:
        raise AwsWafError("VISION_API_KEY is not configured")
    if not model:
        raise AwsWafError("VISION_MODEL is not configured")
    if not api_url.startswith(("http://", "https://")):
        raise AwsWafError("VISION_API_URL must be an http(s) API base URL")

    mode_aliases = {
        "chat": VISION_MODE_CHAT_COMPLETIONS,
        "completion": VISION_MODE_CHAT_COMPLETIONS,
        "chat_completion": VISION_MODE_CHAT_COMPLETIONS,
        "chat_completions": VISION_MODE_CHAT_COMPLETIONS,
        "response": VISION_MODE_RESPONSES,
        "responses": VISION_MODE_RESPONSES,
    }
    raw_mode = os.environ.get("VISION_API_MODE", VISION_MODE_CHAT_COMPLETIONS)
    mode = mode_aliases.get(raw_mode.strip().lower())
    if mode is None:
        raise AwsWafError(
            "VISION_API_MODE must be chat_completions or responses"
        )
    return VisionConfig(
        api_url=api_url,
        api_key=api_key,
        model=model,
        mode=mode,
        auth_header=os.environ.get("VISION_AUTH_HEADER", "Authorization").strip(),
        auth_prefix=os.environ.get("VISION_AUTH_PREFIX", "Bearer").strip(),
    )


def _vision_prompt(target: str) -> str:
    normalized_target = re.sub(r"^\s*(?:the|a|an)\s+", "", target.strip(), flags=re.IGNORECASE)
    return (
        "The following images are CAPTCHA tiles in zero-based order. "
        f"Select every tile that contains {normalized_target!r}. "
        "Return only a JSON array of zero-based tile indexes, with no explanation."
    )


def _image_data_url(image: str) -> str:
    return f"data:{_image_mime_type(image)};base64,{image}"


def _vision_endpoint(config: VisionConfig) -> str:
    suffix = (
        "/chat/completions"
        if config.mode == VISION_MODE_CHAT_COMPLETIONS
        else "/responses"
    )
    return f"{config.api_url.rstrip('/')}{suffix}"


def _build_vision_request(
    config: VisionConfig,
    images: list[str],
    target: str,
) -> tuple[str, dict[str, str], dict[str, object]]:
    prompt = _vision_prompt(target)
    if config.mode == "gemini":
        parts: list[dict[str, object]] = [{"text": prompt}]
        for index, image in enumerate(images):
            parts.append({"text": f"Tile {index}:"})
            parts.append(
                {
                    "inline_data": {
                        "mime_type": _image_mime_type(image),
                        "data": image,
                    }
                }
            )
        endpoint = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{quote(config.model, safe='')}:generateContent"
            f"?key={quote(config.api_key, safe='')}"
        )
        return (
            endpoint,
            {"Content-Type": "application/json"},
            {
                "contents": [{"role": "user", "parts": parts}],
                "generationConfig": {"temperature": 0},
            },
        )

    data_urls = [_image_data_url(image) for image in images]
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "sbeans-vision-client/1.0",
    }
    if config.auth_header:
        credential = (
            f"{config.auth_prefix} {config.api_key}".strip()
            if config.auth_prefix
            else config.api_key
        )
        headers[config.auth_header] = credential
    if config.mode == VISION_MODE_CHAT_COMPLETIONS:
        content: list[dict[str, object]] = [{"type": "text", "text": prompt}]
        for index, image in enumerate(data_urls):
            content.append({"type": "text", "text": f"Tile {index}:"})
            content.append({"type": "image_url", "image_url": {"url": image}})
        return (
            _vision_endpoint(config),
            headers,
            {
                "model": config.model,
                "messages": [{"role": "user", "content": content}],
                "temperature": 0,
            },
        )

    content = [{"type": "input_text", "text": prompt}]
    for index, image in enumerate(data_urls):
        content.append({"type": "input_text", "text": f"Tile {index}:"})
        content.append({"type": "input_image", "image_url": image})
    return (
        _vision_endpoint(config),
        headers,
        {
            "model": config.model,
            "input": [{"role": "user", "content": content}],
        },
    )


def _content_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, list):
        return ""
    return "".join(
        str(item.get("text", ""))
        for item in value
        if isinstance(item, dict) and isinstance(item.get("text"), str)
    )


def _vision_response_text(payload: dict[str, object], mode: str) -> str:
    if mode == "gemini":
        try:
            return "".join(
                str(part.get("text", ""))
                for candidate in payload["candidates"]
                for part in candidate["content"]["parts"]
                if isinstance(part, dict)
            )
        except (KeyError, TypeError):
            return ""
    if mode == VISION_MODE_CHAT_COMPLETIONS:
        try:
            choice = payload["choices"][0]
        except (IndexError, KeyError, TypeError):
            return ""
        if not isinstance(choice, dict):
            return ""
        message = choice.get("message")
        if isinstance(message, dict):
            text = _content_text(message.get("content"))
            if text:
                return text
        return str(choice.get("text", ""))
    output_text = payload.get("output_text")
    if isinstance(output_text, str) and output_text:
        return output_text
    output = payload.get("output")
    if isinstance(output, list):
        return "".join(
            _content_text(item.get("content"))
            for item in output
            if isinstance(item, dict)
        )
    return ""


def _vision_error_detail(exc: HTTPError) -> str:
    raw = ""
    try:
        raw = exc.read(4_096).decode("utf-8", "replace")
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
        return str(getattr(exc, "reason", "") or "").strip()[:240]

    try:
        payload = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        payload = None

    messages: list[str] = []
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            for key in ("message", "detail", "type", "code"):
                value = error.get(key)
                if isinstance(value, str) and value.strip():
                    messages.append(value)
        elif isinstance(error, str) and error.strip():
            messages.append(error)
        for key in ("message", "detail", "error_description"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                messages.append(value)
    elif isinstance(payload, list):
        messages.extend(str(value) for value in payload if isinstance(value, str))

    if not messages and raw.strip():
        messages.append(re.sub(r"<[^>]+>", " ", raw))
    if messages:
        return re.sub(r"\s+", " ", " ".join(messages)).strip()[:240]
    return str(getattr(exc, "reason", "") or "").strip()[:240]


def _vision_retry_delay(exc: HTTPError) -> float:
    try:
        retry_after = float(exc.headers.get("Retry-After", ""))
    except (AttributeError, TypeError, ValueError):
        retry_after = 0.0
    if retry_after > 0:
        return min(retry_after, 60.0)
    return VISION_RATE_LIMIT_RETRY_SECONDS


def _vision_wait_for_slot() -> None:
    wait_seconds = VISION_MIN_INTERVAL_SECONDS - (
        time.monotonic() - _VISION_LAST_REQUEST_FINISHED
    )
    if wait_seconds > 0:
        logging.info("Vision request throttled; waiting %.1fs", wait_seconds)
        time.sleep(wait_seconds)


def _vision_text(images: list[str], target: str, api_key: str) -> str:
    config = _vision_config(api_key)
    endpoint, headers, payload = _build_vision_request(config, images, target)
    request = Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    global _VISION_LAST_REQUEST_FINISHED
    with _VISION_REQUEST_LOCK:
        for attempt in range(2):
            _vision_wait_for_slot()
            try:
                with urlopen(request, timeout=VISION_TIMEOUT_SECONDS) as response:
                    result = json.loads(response.read().decode("utf-8"))
            except HTTPError as exc:
                detail = _vision_error_detail(exc)
                _VISION_LAST_REQUEST_FINISHED = time.monotonic()
                detail_lower = detail.lower()
                credits_depleted = (
                    "prepayment credits" in detail_lower
                    or "credits are depleted" in detail_lower
                )
                if exc.code == 429 and attempt == 0 and not credits_depleted:
                    delay = _vision_retry_delay(exc)
                    logging.warning(
                        "Vision API HTTP 429; retrying once after %.1fs",
                        delay,
                    )
                    time.sleep(delay)
                    _VISION_LAST_REQUEST_FINISHED = (
                        time.monotonic() - VISION_MIN_INTERVAL_SECONDS
                    )
                    continue
                message = f"Vision API HTTP {exc.code}"
                if detail:
                    message += f": {detail}"
                raise AwsWafError(message) from exc
            except (URLError, TimeoutError, json.JSONDecodeError) as exc:
                _VISION_LAST_REQUEST_FINISHED = time.monotonic()
                raise AwsWafError(f"Vision API request failed: {type(exc).__name__}") from exc
            _VISION_LAST_REQUEST_FINISHED = time.monotonic()
            response_text = _vision_response_text(result, config.mode)
            if response_text:
                return response_text
            raise AwsWafError("Vision API response did not contain text")
    raise AwsWafError("Vision API request retry limit reached")


def solve_captcha_images(
    images: list[str],
    target: str,
    api_key: str,
    request_fn: Callable[[list[str], str, str], str] | None = None,
) -> list[int]:
    if not api_key.strip() and not (
        os.environ.get("VISION_API_KEY", "").strip()
        or os.environ.get("GEMINI_API_KEY", "").strip()
    ):
        raise AwsWafError(
            "VISION_API_KEY or legacy GEMINI_API_KEY is not configured"
        )
    if not images or not target.strip():
        raise AwsWafError("AWS WAF visual challenge did not contain images or a target")
    response_text = (request_fn or _vision_text)(images, target, api_key)
    return parse_solution_indices(response_text, len(images))


class AwsWafAdapter:
    """Solve the Student Beans AWS WAF visual challenge inside the active page."""

    def __init__(self, page, state: AwsWafNetworkState, api_key: str | None = None) -> None:
        self.page = page
        self.state = state
        self._ui_state_before: dict[str, object] = {}
        self._ui_state_after: dict[str, object] = {}
        self._ui_click_mode = ""
        self._ui_clicks: list[object] = []
        if api_key:
            self.api_key = api_key.strip()
        elif any(
            os.environ.get(name, "").strip()
            for name in ("VISION_API_URL", "VISION_API_KEY", "VISION_MODEL")
        ):
            self.api_key = os.environ.get("VISION_API_KEY", "").strip()
        else:
            self.api_key = os.environ.get("GEMINI_API_KEY", "").strip()

    @staticmethod
    def _urls(problem_url: str) -> tuple[str, str, str, str]:
        parsed = urlsplit(problem_url)
        query = parse_qs(parsed.query)
        api_key = str(query.get("api_key", [""])[0]).strip()
        if not api_key:
            raise AwsWafError("AWS WAF problem URL did not contain api_key")
        host = (parsed.hostname or "").lower()
        if ".captcha.awswaf.com" not in host or not parsed.path.endswith("/problem"):
            raise AwsWafError("AWS WAF problem URL has an unexpected host or path")
        token_host = host.replace(".captcha.awswaf.com", ".token.awswaf.com", 1)
        verify_path = parsed.path[:-len("/problem")] + "/verify"
        voucher_path = parsed.path[:-len("/problem")] + "/voucher"
        verify_url = urlunsplit((parsed.scheme, parsed.netloc, verify_path, "", ""))
        voucher_url = urlunsplit((parsed.scheme, token_host, voucher_path, "", ""))
        locale = str(query.get("locale", ["en-gb"])[0])
        return api_key, locale, verify_url, voucher_url

    def _captcha_ui_text(self) -> str:
        try:
            captcha = self.page.locator("awswaf-captcha").last
            return " ".join(captcha.inner_text().split())[:240]
        except Exception:
            return ""

    def _captcha_ui_state(self, captcha, image_count: int) -> dict[str, object]:
        """Collect selection/control metadata without reading image content."""
        state: dict[str, object] = {
            "buttons": 0,
            "numbered_buttons": 0,
            "selected_buttons": 0,
            "selected_labels": [],
            "canvas": 0,
        }
        try:
            buttons = captcha.locator("button")
            state["buttons"] = buttons.count()
            labels: list[str] = []
            selected_labels: list[str] = []
            for index in range(buttons.count()):
                button = buttons.nth(index)
                label = ""
                try:
                    label = " ".join(
                        (
                            button.inner_text()
                            or button.get_attribute("aria-label")
                            or ""
                        ).split()
                    )[:40]
                except Exception:
                    pass
                if re.fullmatch(r"(?:\d+|(?:image|tile)\s+\d+)", label, re.IGNORECASE):
                    state["numbered_buttons"] = int(state["numbered_buttons"]) + 1
                    labels.append(label)
                selected = False
                try:
                    attributes = (
                        button.get_attribute("aria-pressed"),
                        button.get_attribute("aria-selected"),
                        button.get_attribute("data-selected"),
                        button.get_attribute("data-state"),
                        button.get_attribute("checked"),
                    )
                    selected = any(
                        str(value or "").strip().lower() in {"true", "selected", "active", "checked"}
                        for value in attributes
                    )
                    classes = str(button.get_attribute("class") or "").lower()
                    selected = selected or bool(re.search(r"\b(?:selected|active|checked)\b", classes))
                except Exception:
                    pass
                if selected:
                    state["selected_buttons"] = int(state["selected_buttons"]) + 1
                    if label:
                        selected_labels.append(label)
            state["numbered_labels"] = labels[:image_count]
            state["selected_labels"] = selected_labels[:image_count]
        except Exception:
            pass
        try:
            state["canvas"] = captcha.locator("canvas").count()
        except Exception:
            pass
        return state

    def _click_ui_solution(self, solution: list[int], image_count: int) -> None:
        captcha = self.page.locator("awswaf-captcha").last
        if captcha.count() == 0:
            raise AwsWafError("AWS WAF CAPTCHA element was not found")

        grid_size = round(image_count ** 0.5)
        if grid_size * grid_size != image_count:
            raise AwsWafError("AWS WAF CAPTCHA image count is not a square grid")

        self._ui_state_before = self._captcha_ui_state(captcha, image_count)
        logging.info(
            "AWS WAF UI before selection state=%s",
            json.dumps(self._ui_state_before, sort_keys=True),
        )

        # AWS WAF renders one transparent, numbered button per tile over the
        # canvas. Clicking those controls preserves its own index mapping and
        # avoids depending on device-scale or canvas layout rounding.
        buttons = captcha.locator("button[type='button']")
        grid_buttons: dict[int, object] = {}
        for button_index in range(buttons.count()):
            button = buttons.nth(button_index)
            try:
                label = " ".join(button.inner_text().split())
            except Exception:
                continue
            if label.isdigit():
                tile_index = int(label) - 1
                if 0 <= tile_index < image_count:
                    grid_buttons[tile_index] = button

        if len(grid_buttons) == image_count:
            self._ui_click_mode = "numbered-buttons"
            self._ui_clicks = list(solution)
            logging.info("AWS WAF grid controls detected count=%d", len(grid_buttons))
            for index in solution:
                grid_buttons[index].click(timeout=5_000)
                self.page.wait_for_timeout(50)
        else:
            self._ui_click_mode = "canvas"
            canvas = captcha.locator("canvas").last
            if canvas.count() == 0:
                raise AwsWafError("AWS WAF CAPTCHA image grid controls were not found")
            box = canvas.bounding_box()
            if not box or box["width"] <= 0 or box["height"] <= 0:
                raise AwsWafError("AWS WAF CAPTCHA image grid bounds are unavailable")
            gap = 4
            cell_width = (box["width"] - gap * (grid_size - 1)) / grid_size
            cell_height = (box["height"] - gap * (grid_size - 1)) / grid_size
            logging.info(
                "AWS WAF grid controls unavailable; using canvas width=%.1f height=%.1f cell=%.1fx%.1f",
                box["width"],
                box["height"],
                cell_width,
                cell_height,
            )
            click_positions: list[dict[str, int]] = []
            for index in solution:
                column = index % grid_size
                row = index // grid_size
                position = {
                    "x": round(column * (cell_width + gap) + cell_width / 2),
                    "y": round(row * (cell_height + gap) + cell_height / 2),
                }
                canvas.click(
                    position=position,
                    timeout=5_000,
                )
                click_positions.append({"index": index, **position})
                self.page.wait_for_timeout(100)
            self._ui_clicks = click_positions
            logging.info("AWS WAF canvas selection clicks=%s", click_positions)

        self._ui_state_after = self._captcha_ui_state(captcha, image_count)
        logging.info(
            "AWS WAF UI after selection state=%s",
            json.dumps(self._ui_state_after, sort_keys=True),
        )

        confirm = captcha.locator("button[type='submit']").filter(
            has_text=re.compile(r"^\s*Confirm\s*$", re.IGNORECASE)
        )
        if confirm.count() == 0:
            confirm = captcha.get_by_text("Confirm", exact=True)
        if confirm.count() == 0:
            raise AwsWafError("AWS WAF CAPTCHA Confirm button was not found")
        try:
            confirm_enabled: bool | str = confirm.last.is_enabled()
        except Exception:
            confirm_enabled = "unknown"
        logging.info(
            "AWS WAF Confirm control count=%d enabled=%s",
            confirm.count(),
            confirm_enabled,
        )
        confirm.last.click(timeout=AWS_WAF_UI_TIMEOUT_MS)

    def _browser_waf_token_length(self) -> int:
        try:
            for cookie in self.page.context.cookies():
                if cookie.get("name") == "aws-waf-token":
                    return len(str(cookie.get("value") or ""))
        except Exception:
            logging.debug("AWS WAF token cookie lookup skipped", exc_info=True)
        return 0

    def _browser_waf_token(self) -> str:
        try:
            for cookie in self.page.context.cookies():
                if cookie.get("name") == "aws-waf-token":
                    return str(cookie.get("value") or "")
        except Exception:
            logging.debug("AWS WAF token lookup skipped", exc_info=True)
        return ""

    def _wait_for_ui_voucher(self, previous_voucher_count: int, previous_token: str) -> int:
        deadline = time.monotonic() + AWS_WAF_UI_TIMEOUT_MS / 1000
        while time.monotonic() < deadline:
            if len(self.state.voucher_urls) > previous_voucher_count:
                token_length = self._browser_waf_token_length()
                if token_length >= AWS_WAF_TOKEN_MIN_LENGTH and any(
                    status == 200 for status in self.state.voucher_statuses
                ):
                    return token_length
            self.page.wait_for_timeout(250)
        current_token = self._browser_waf_token()
        verify_diagnostic = (
            _format_response_diagnostic(self.state.verify_diagnostics[-1])
            if self.state.verify_diagnostics
            else "none"
        )
        voucher_diagnostic = (
            _format_response_diagnostic(self.state.voucher_diagnostics[-1])
            if self.state.voucher_diagnostics
            else "none"
        )
        token_changed = bool(previous_token or current_token) and previous_token != current_token
        ui_state = self._ui_state_after or self._ui_state_before
        ui_diagnostic = (
            f"mode={self._ui_click_mode or 'unknown'} "
            f"buttons={ui_state.get('buttons', 0)} "
            f"numbered={ui_state.get('numbered_buttons', 0)} "
            f"selected={ui_state.get('selected_buttons', 0)} "
            f"canvas={ui_state.get('canvas', 0)}"
        )
        logging.error(
            "AWS WAF Confirm diagnostics voucher=%d verify=%s voucher_response=%s "
            "token_before=%d token_after=%d token_changed=%s ui_text=%s ui=%s clicks=%s",
            len(self.state.voucher_urls) - previous_voucher_count,
            verify_diagnostic,
            voucher_diagnostic,
            len(previous_token),
            len(current_token),
            token_changed,
            self._captcha_ui_text(),
            ui_diagnostic,
            self._ui_clicks,
        )
        raise AwsWafError(
            "AWS WAF Confirm did not produce a browser voucher; "
            f"voucher={len(self.state.voucher_urls) - previous_voucher_count} "
            f"verify={verify_diagnostic} voucher_response={voucher_diagnostic} "
            f"token_before={len(previous_token)} token_after={len(current_token)} "
            f"token_changed={token_changed} ui={ui_diagnostic}"
        )

    def solve(self, problem_url: str) -> dict[str, int | bool]:
        if not self.api_key:
            raise AwsWafError(
                "VISION_API_KEY or legacy GEMINI_API_KEY is not configured"
            )
        self._urls(problem_url)

        problem = self.state.latest_problem_payload(problem_url)
        if problem is None:
            raise AwsWafError(
                "AWS WAF original problem response was not captured; refusing to request a second challenge"
            )
        assets = problem.get("assets")
        localized_assets = problem.get("localized_assets")
        if not isinstance(assets, dict):
            raise AwsWafError("AWS WAF problem response is missing assets")
        raw_images = assets.get("images")
        if isinstance(raw_images, str):
            try:
                raw_images = json.loads(raw_images)
            except json.JSONDecodeError as exc:
                raise AwsWafError("AWS WAF image list is invalid JSON") from exc
        images = [str(image) for image in raw_images] if isinstance(raw_images, list) else []
        target = ""
        if isinstance(localized_assets, dict):
            target = str(localized_assets.get("target0") or "")
        target = target or str(assets.get("target") or "")
        logging.info(
            "AWS WAF visual challenge received images=%d target=%s",
            len(images),
            target[:80],
        )
        solution = solve_captcha_images(images, target, self.api_key)
        logging.info("AWS WAF vision selected indexes=%s", solution)
        previous_voucher_count = len(self.state.voucher_urls)
        previous_token = self._browser_waf_token()
        logging.info(
            "AWS WAF challenge before Confirm text=%s selected=%d token_length=%d",
            self._captcha_ui_text(),
            len(solution),
            len(previous_token),
        )
        self._click_ui_solution(solution, len(images))
        logging.info("AWS WAF Confirm clicked")
        token_length = self._wait_for_ui_voucher(previous_voucher_count, previous_token)
        return {
            "success": True,
            "images": len(images),
            "selected": len(solution),
            "problem_status": 200,
            "verify_status": 200,
            "voucher_status": 200,
            "token_length": token_length,
        }
