import base64
import logging
import os
import platform
import sys
import time
from datetime import timedelta
from html import escape
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from func_timeout import FunctionTimedOut, func_timeout
from selenium.common import TimeoutException
from selenium.webdriver.chrome.webdriver import WebDriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.expected_conditions import (
    presence_of_element_located, staleness_of, title_is)
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.wait import WebDriverWait

import utils
from dtos import (STATUS_ERROR, STATUS_OK, ChallengeResolutionResultT,
                  ChallengeResolutionT, HealthResponse, IndexResponse,
                  V1RequestBase, V1ResponseBase)
from aws_waf import (AWS_WAF_DETECT_TIMEOUT_MS, AwsWafAdapter,
                     AwsWafError, AwsWafNetworkState, wait_for_problem)
from camoufox_auth import code_collection_allowed
from sessions import SessionsStorage

ACCESS_DENIED_TITLES = [
    # Cloudflare
    'Access denied',
    # Cloudflare http://bitturk.net/ Firefox
    'Attention Required! | Cloudflare'
]
ACCESS_DENIED_SELECTORS = [
    # Cloudflare
    'div.cf-error-title span.cf-code-label span',
    # Cloudflare http://bitturk.net/ Firefox
    '#cf-error-details div.cf-error-overview h1'
]
CHALLENGE_TITLES = [
    # Cloudflare
    'Just a moment...',
    # DDoS-GUARD
    'DDoS-Guard'
]
CHALLENGE_SELECTORS = [
    # Cloudflare
    '#cf-challenge-running', '.ray_id', '.attack-box', '#cf-please-wait', '#challenge-spinner', '#trk_jschal_js', '#turnstile-wrapper', '.lds-ring',
    # Custom CloudFlare for EbookParadijs, Film-Paleis, MuziekFabriek and Puur-Hollands
    'td.info #js_info',
    # Fairlane / pararius.com
    'div.vc div.text-box h2'
]

TURNSTILE_SELECTORS = [
    "input[name='cf-turnstile-response']"
]

SHORT_TIMEOUT = 1
SESSIONS_STORAGE = SessionsStorage()

SBEANS_CODE_ENDPOINT = 'https://graphql.studentbeans.com/graphql/v1/query'
SBEANS_CODE_OFFERS = (
    {'planId': '121296', 'offerUid': '4520cff4-0038-4da7-a2d0-9d31a0c5e17f'},
    {'planId': '121301', 'offerUid': '83bb6f56-bfdf-4818-b2c3-13e4e030b23e'},
    {'planId': '122550', 'offerUid': 'ce817d2a-22f8-4bba-8715-1535e43a2202'},
    {'planId': '122552', 'offerUid': '0d46f03e-50f4-4a3c-bc0d-aa94d0567944'},
)
SBEANS_CODE_QUERY = '''mutation createIssuanceMutation($input: CreateIssuanceInput!) {
  createIssuance(input: $input) {
    issuance {
      uid
      code { code endDate barcodeContent barcodeStandard __typename }
      sbidNumber
      affiliateLink
      affiliateNetwork
      __typename
    }
    __typename
  }
}'''
SBEANS_CODE_PAGE_SETTLE_MS = 10_000
SBEANS_CODE_RETRY_WAIT_MS = 10_000
SBEANS_CODE_MAX_POST_ATTEMPTS = 1
SBEANS_GRAPHQL_ENDPOINT = 'https://graphql.studentbeans.com/graphql/v1/query'
SBEANS_ACCOUNT_PASSTHROUGH_URL = 'https://accounts.studentbeans.com/uk/authorisation/passthrough'
SBEANS_OAUTH_AUTHORIZE_URL = (
    'https://accounts.studentbeans.com/oauth/authorize'
    '?auth_path=log-in&clear_brand_data=1'
    '&client_id=e55920fd-5410-4534-b926-b1214c85f64a'
    '&consumer_group=student&country=uk'
    '&redirect_uri=https%3A%2F%2Fwww.studentbeans.com%2Fusers%2Fauth%2Fstudentbeans%2Fcallback'
    '&response_type=code&user_return_to=https%3A%2F%2Fwww.studentbeans.com%2Fuk'
)
SBEANS_STUDENTBEANS_HOME_HOST = 'www.studentbeans.com'
SBEANS_DEBUG_SCREENSHOT_LIMIT = 3


def _redact_url(value: object) -> str:
    """Keep navigation diagnostics useful without exposing OAuth credentials."""
    raw = str(value or '')
    try:
        parsed = urlsplit(raw)
        if not parsed.scheme or not parsed.netloc:
            return raw
        sensitive = {
            'api_key', 'auth', 'code', 'captcha_voucher', 'id_token',
            'token', 'access_token',
        }
        query = [
            (key, '<redacted>' if key.lower() in sensitive else item)
            for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ''))
    except Exception:
        return '<unavailable>'


def _camoufox_step(
    steps: list[dict[str, object]] | None,
    stage: str,
    status: str,
    page,
    **details: object,
) -> None:
    if steps is None:
        return
    item: dict[str, object] = {
        'stage': stage,
        'status': status,
        'url': _redact_url(str(page.url or '')),
    }
    item.update(details)
    steps.append(item)
    logging.info(
        'Camoufox step stage=%s status=%s url=%s details=%s',
        stage,
        status,
        item['url'],
        ' '.join(f'{key}={value}' for key, value in details.items()),
    )


def dismiss_cookie_consent(driver: WebDriver):
    try:
        dismissed = driver.execute_script(
            """
            const visible = (node) => {
                if (!node) return false;
                const style = window.getComputedStyle(node);
                const rect = node.getBoundingClientRect();
                return style.display !== 'none' && style.visibility !== 'hidden'
                    && style.opacity !== '0' && rect.width > 0 && rect.height > 0;
            };
            const direct = document.querySelector(
                '#onetrust-accept-btn-handler, #accept-recommended-btn-handler'
            );
            if (visible(direct)) {
                direct.click();
                return 'OneTrust';
            }
            const accepted = new Set([
                'accept', 'accept all', 'accept all cookies', 'agree'
            ]);
            for (const node of document.querySelectorAll('button, a, [role="button"]')) {
                if (!visible(node) || node.disabled || node.getAttribute('aria-disabled') === 'true') continue;
                const text = String(node.innerText || node.textContent || '')
                    .replace(/\\s+/g, ' ').trim().toLowerCase();
                if (accepted.has(text)) {
                    node.click();
                    return text;
                }
            }
            return '';
            """
        )
        if dismissed:
            logging.info("Cookie consent dismissed: %s", dismissed)
    except Exception:
        logging.debug("Cookie consent dismissal was unavailable")


def test_browser_installation():
    logging.info("Testing web browser installation...")
    logging.info("Platform: " + platform.platform())

    chrome_exe_path = utils.get_chrome_exe_path()
    if chrome_exe_path is None:
        logging.error("Chrome / Chromium web browser not installed!")
        sys.exit(1)
    else:
        logging.info("Chrome / Chromium path: " + chrome_exe_path)

    chrome_major_version = utils.get_chrome_major_version()
    if chrome_major_version == '':
        logging.error("Chrome / Chromium version not detected!")
        sys.exit(1)
    else:
        logging.info("Chrome / Chromium major version: " + chrome_major_version)

    logging.info("Launching web browser...")
    user_agent = utils.get_user_agent()
    logging.info("FlareSolverr User-Agent: " + user_agent)
    logging.info("Test successful!")


def index_endpoint() -> IndexResponse:
    res = IndexResponse({})
    res.msg = "FlareSolverr is ready!"
    res.version = utils.get_flaresolverr_version()
    res.userAgent = utils.get_user_agent()
    return res


def health_endpoint() -> HealthResponse:
    res = HealthResponse({})
    res.status = STATUS_OK
    return res


def controller_v1_endpoint(req: V1RequestBase) -> V1ResponseBase:
    start_ts = int(time.time() * 1000)
    logging.info(
        "Incoming request => POST /v1 cmd=%s url=%s session=%s",
        req.cmd,
        req.url,
        req.session,
    )
    res: V1ResponseBase
    try:
        res = _controller_v1_handler(req)
    except Exception as e:
        res = V1ResponseBase({})
        res.__error_500__ = True
        res.status = STATUS_ERROR
        res.message = "Error: " + str(e)
        logging.error(res.message)

    res.startTimestamp = start_ts
    res.endTimestamp = int(time.time() * 1000)
    res.version = utils.get_flaresolverr_version()
    logging.debug("Response => POST /v1 status=%s message=%s", res.status, res.message)
    logging.info(f"Response in {(res.endTimestamp - res.startTimestamp) / 1000} s")
    return res


def _controller_v1_handler(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.cmd is None:
        raise Exception("Request parameter 'cmd' is mandatory.")
    if req.headers is not None:
        logging.warning("Request parameter 'headers' was removed in FlareSolverr v2.")
    if req.userAgent is not None:
        logging.warning("Request parameter 'userAgent' was removed in FlareSolverr v2.")

    # set default values
    if req.maxTimeout is None or int(req.maxTimeout) < 1:
        req.maxTimeout = 60000

    # execute the command
    res: V1ResponseBase
    if req.cmd == 'sessions.create':
        res = _cmd_sessions_create(req)
    elif req.cmd == 'sessions.list':
        res = _cmd_sessions_list(req)
    elif req.cmd == 'sessions.destroy':
        res = _cmd_sessions_destroy(req)
    elif req.cmd == 'request.get':
        res = _cmd_request_get(req)
    elif req.cmd == 'request.post':
        res = _cmd_request_post(req)
    else:
        raise Exception(f"Request parameter 'cmd' = '{req.cmd}' is invalid.")

    return res


def _cmd_request_get(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.url is None:
        raise Exception("Request parameter 'url' is mandatory in 'request.get' command.")
    if req.postData is not None:
        raise Exception("Cannot use 'postBody' when sending a GET request.")
    if req.returnRawHtml is not None:
        logging.warning("Request parameter 'returnRawHtml' was removed in FlareSolverr v2.")
    if req.download is not None:
        logging.warning("Request parameter 'download' was removed in FlareSolverr v2.")

    challenge_res = _resolve_challenge(req, 'GET')
    res = V1ResponseBase({})
    res.status = challenge_res.status
    res.message = challenge_res.message
    res.solution = challenge_res.result
    return res


def _cmd_request_post(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.postData is None:
        raise Exception("Request parameter 'postData' is mandatory in 'request.post' command.")
    if req.returnRawHtml is not None:
        logging.warning("Request parameter 'returnRawHtml' was removed in FlareSolverr v2.")
    if req.download is not None:
        logging.warning("Request parameter 'download' was removed in FlareSolverr v2.")

    challenge_res = _resolve_challenge(req, 'POST')
    res = V1ResponseBase({})
    res.status = challenge_res.status
    res.message = challenge_res.message
    res.solution = challenge_res.result
    return res


def _cmd_sessions_create(req: V1RequestBase) -> V1ResponseBase:
    logging.debug("Creating new session...")

    session, fresh = SESSIONS_STORAGE.create(session_id=req.session, proxy=req.proxy)
    session_id = session.session_id

    if not fresh:
        return V1ResponseBase({
            "status": STATUS_OK,
            "message": "Session already exists.",
            "session": session_id
        })

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "Session created successfully.",
        "session": session_id
    })


def _cmd_sessions_list(req: V1RequestBase) -> V1ResponseBase:
    session_ids = SESSIONS_STORAGE.session_ids()

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "",
        "sessions": session_ids
    })


def _cmd_sessions_destroy(req: V1RequestBase) -> V1ResponseBase:
    session_id = req.session
    existed = SESSIONS_STORAGE.destroy(session_id)

    if not existed:
        raise Exception("The session doesn't exist.")

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "The session has been removed."
    })


def _resolve_challenge(req: V1RequestBase, method: str) -> ChallengeResolutionT:
    if getattr(req, 'browser', None) == 'camoufox':
        if method != 'GET':
            raise Exception("Camoufox solver only supports GET requests")
        return _resolve_camoufox_challenge(req)

    timeout = int(req.maxTimeout) / 1000
    driver = None
    try:
        if req.session:
            session_id = req.session
            ttl = timedelta(minutes=req.session_ttl_minutes) if req.session_ttl_minutes else None
            session, fresh = SESSIONS_STORAGE.get(session_id, ttl)

            if fresh:
                logging.debug(f"new session created to perform the request (session_id={session_id})")
            else:
                logging.debug(f"existing session is used to perform the request (session_id={session_id}, "
                              f"lifetime={str(session.lifetime())}, ttl={str(ttl)})")

            driver = session.driver
        else:
            driver = utils.get_webdriver(req.proxy)
            logging.debug('New instance of webdriver has been created to perform the request')
        return func_timeout(timeout, _evil_logic, (req, driver, method))
    except FunctionTimedOut:
        raise Exception(f'Error solving the challenge. Timeout after {timeout} seconds.')
    except Exception as e:
        raise Exception('Error solving the challenge. ' + str(e).replace('\n', '\\n'))
    finally:
        if not req.session and driver is not None:
            if utils.PLATFORM_VERSION == "nt":
                driver.close()
            driver.quit()
            logging.debug('A used instance of webdriver has been destroyed')


def _camoufox_proxy(proxy: dict | None) -> dict | None:
    if not proxy or not proxy.get('url'):
        return None
    result = {'server': str(proxy['url'])}
    if proxy.get('username') is not None:
        result['username'] = str(proxy['username'])
    if proxy.get('password') is not None:
        result['password'] = str(proxy['password'])
    return result


def _dismiss_cookie_consent_page(page) -> str:
    deadline = time.monotonic() + 3.0
    accepted = {
        'accept', 'accept all', 'accept all cookies', 'accept recommended cookies',
        'allow all', 'allow all cookies', 'agree',
    }

    def click_target(target) -> bool:
        try:
            target.click(timeout=2_000)
            return True
        except Exception:
            try:
                # A pointer shield can remain above the consent button during
                # fade-in; invoke that button's own DOM click handler.
                target.evaluate("(element) => element.click()")
                return True
            except Exception:
                return False

    def consent_visible() -> bool:
        try:
            return bool(page.evaluate(
                """() => [
                    '#onetrust-banner-sdk', '#onetrust-pc-sdk',
                    '#onetrust-pc-dark-filter', '.onetrust-pc-dark-filter'
                ].some((selector) => Array.from(document.querySelectorAll(selector)).some((node) => {
                    const style = window.getComputedStyle(node);
                    const rect = node.getBoundingClientRect();
                    return style.display !== 'none' && style.visibility !== 'hidden'
                        && style.opacity !== '0' && rect.width > 0 && rect.height > 0;
                }))"""
            ))
        except Exception:
            return True

    while time.monotonic() < deadline:
        dismissed = ''
        direct = page.locator(
            '#onetrust-accept-btn-handler, #accept-recommended-btn-handler'
        )
        for index in range(direct.count()):
            target = direct.nth(index)
            try:
                if target.is_visible() and target.is_enabled():
                    if click_target(target):
                        dismissed = 'OneTrust'
                        break
            except Exception:
                continue
        if not dismissed:
            candidates = page.locator(
                '#onetrust-consent-sdk button, #onetrust-consent-sdk a, '
                '#onetrust-consent-sdk [role="button"]'
            )
            for index in range(candidates.count()):
                target = candidates.nth(index)
                try:
                    if not target.is_visible() or not target.is_enabled():
                        continue
                    if target.get_attribute('aria-disabled') == 'true':
                        continue
                    text = target.inner_text().replace('\n', ' ').strip().lower()
                    if text in accepted:
                        if click_target(target):
                            dismissed = text
                            break
                except Exception:
                    continue
        if dismissed:
            for _ in range(8):
                page.wait_for_timeout(250)
                if not consent_visible():
                    return dismissed
            logging.info('Camoufox Cookie consent click still visible, retrying')
        page.wait_for_timeout(250)
    return ''


def _click_camoufox_turnstile(page) -> str:
    """Click the widget even while its challenge iframe is still mounting."""
    selectors = (
        ("widget", page.locator('#cf-turnstile').first),
        (
            "iframe",
            page.locator(
                'iframe[src*="challenges.cloudflare.com"], iframe[src*="turnstile"]'
            ).first,
        ),
    )
    for strategy, target in selectors:
        try:
            if not target.count():
                continue
            try:
                target.click(position={'x': 24, 'y': 32}, timeout=5_000, force=True)
                return f"{strategy}-locator"
            except Exception:
                box = target.bounding_box()
                if not box or box['width'] <= 0 or box['height'] <= 0:
                    continue
                click_x = box['x'] + min(24, box['width'] / 2)
                click_y = box['y'] + min(32, box['height'] / 2)
                page.mouse.click(click_x, click_y)
                return f"{strategy}-mouse"
        except Exception:
            continue
    return ""


def _camoufox_first_visible(page, selectors):
    for selector in selectors:
        target = page.locator(selector).first
        try:
            if target.count() and target.is_visible() and target.is_enabled():
                return target
        except Exception:
            continue
    return None


def _fill_camoufox_login(page, email: str, password: str, timeout_ms: int) -> None:
    """Fill Student Beans credentials before solving and submitting in this page."""
    email_selectors = (
        'input[type="email"]',
        'input[name="user[email]"]',
        'input[name="email"]',
    )
    password_selectors = (
        'input[type="password"]',
        'input[name="user[password]"]',
        'input[name="password"]',
    )
    deadline = time.monotonic() + max(1.0, timeout_ms / 1000)
    while time.monotonic() < deadline:
        _dismiss_cookie_consent_page(page)
        email_input = _camoufox_first_visible(page, email_selectors)
        password_input = _camoufox_first_visible(page, password_selectors)
        if email_input and password_input:
            for _ in range(3):
                try:
                    email_input.fill(email)
                    password_input.fill(password)
                    if (
                        email_input.input_value() == email
                        and password_input.input_value() == password
                    ):
                        logging.info("Camoufox Student Beans account form filled")
                        return
                except Exception:
                    pass
                page.wait_for_timeout(500)
                email_input = _camoufox_first_visible(page, email_selectors)
                password_input = _camoufox_first_visible(page, password_selectors)
        page.wait_for_timeout(250)
    raise Exception("Student Beans login form did not become ready")


def _camoufox_visible_login_error(page) -> str:
    selectors = (
        '[role="alert"]',
        '[aria-live="assertive"]',
        '[aria-live="polite"]',
        '[class*="error"]',
    )
    for selector in selectors:
        nodes = page.locator(selector)
        for index in range(nodes.count()):
            node = nodes.nth(index)
            try:
                if not node.is_visible():
                    continue
                text = " ".join(node.inner_text().split())
                if text and len(text) <= 300:
                    return text
            except Exception:
                continue
    return ""


def _camoufox_debug_state(page, stage: str) -> None:
    """Log page state without logging credential, token, or cookie values."""
    try:
        state = page.evaluate(
            """
            () => {
              const normalize = (value) => String(value || '').replace(/\\s+/g, ' ').trim();
              const visible = (node) => {
                if (!node) return false;
                const style = window.getComputedStyle(node);
                const rect = node.getBoundingClientRect();
                return style.display !== 'none' && style.visibility !== 'hidden'
                  && style.opacity !== '0' && rect.width > 0 && rect.height > 0;
              };
              const controls = Array.from(document.querySelectorAll('button, a, [role="button"]'))
                .filter(visible)
                .map((node) => normalize(node.innerText || node.textContent));
              const bodyText = document.body ? normalize(document.body.innerText) : '';
              const bodyHtml = document.body ? document.body.innerHTML : '';
              const cookieNames = document.cookie.split(';')
                .map((part) => part.trim().split('=', 1)[0]).filter(Boolean);
              return {
                url: location.href,
                referrer: document.referrer,
                title: document.title,
                readyState: document.readyState,
                bodyTextLength: bodyText.length,
                bodyHtmlLength: bodyHtml.length,
                passwordInputs: document.querySelectorAll('input[type="password"]').length,
                accountSettingsVisible: controls.some((text) => text === 'Account Settings')
                  || bodyText.includes('Account Settings'),
                loginVisible: controls.some((text) => /\\b(?:log in|login|sign in)\\b/i.test(text)),
                registerVisible: controls.some((text) => /\\bregister\\b/i.test(text)),
                viewerTokenCookie: cookieNames.includes('viewer_token'),
                documentCookieNames: cookieNames,
                localStorageKeys: Object.keys(window.localStorage),
                sessionStorageKeys: Object.keys(window.sessionStorage)
              };
            }
            """
        )
        cookies = sorted({
            str(cookie.get('name'))
            for cookie in page.context.cookies()
            if cookie.get('name')
        })
        logging.info(
            "Camoufox debug stage=%s url=%s referrer=%s title=%s ready=%s "
            "body_text=%s body_html=%s password_inputs=%s account_settings=%s "
            "login_visible=%s register_visible=%s viewer_token_cookie=%s "
            "document_cookie_names=%s context_cookie_names=%s local_storage_keys=%s session_storage_keys=%s",
            stage,
            _redact_url(state.get('url', '')),
            _redact_url(state.get('referrer', '')),
            state.get('title', ''),
            state.get('readyState', ''),
            state.get('bodyTextLength', 0),
            state.get('bodyHtmlLength', 0),
            state.get('passwordInputs', 0),
            state.get('accountSettingsVisible', False),
            state.get('loginVisible', False),
            state.get('registerVisible', False),
            state.get('viewerTokenCookie', False),
            ','.join(str(value) for value in state.get('documentCookieNames', [])),
            ','.join(cookies),
            ','.join(str(value) for value in state.get('localStorageKeys', [])),
            ','.join(str(value) for value in state.get('sessionStorageKeys', [])),
        )
    except Exception as exc:
        logging.info('Camoufox debug stage=%s unavailable error=%s', stage, type(exc).__name__)


def _capture_camoufox_screenshot(
    page,
    screenshots: list[dict[str, str]] | None,
    stage: str,
) -> None:
    if screenshots is None:
        return
    try:
        image = base64.b64encode(page.screenshot(full_page=True)).decode('ascii')
        if len(screenshots) >= SBEANS_DEBUG_SCREENSHOT_LIMIT:
            screenshots.pop(0)
        screenshots.append({'stage': stage, 'image': image})
        logging.info(
            'Camoufox debug screenshot captured stage=%s bytes=%d url=%s',
            stage,
            len(image),
            _redact_url(str(page.url or '')),
        )
    except Exception as exc:
        logging.info(
            'Camoufox debug screenshot failed stage=%s error=%s',
            stage,
            type(exc).__name__,
        )


def _submit_camoufox_login(
    page,
    req: V1RequestBase,
    waf_state: AwsWafNetworkState | None = None,
    debug_screenshots: list[dict[str, str]] | None = None,
    login_steps: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    """Submit the credentials in the same Camoufox context that solved Turnstile."""
    started = time.monotonic()
    timeout_ms = max(10_000, int(req.sbeans_login_timeout_ms or 120_000))
    login_path = urlsplit(req.url).path.rstrip("/")
    response_status = None
    response_started = time.monotonic()
    waf_solved = False
    waf_result: dict[str, int | bool] | None = None

    def on_response(response) -> None:
        nonlocal response_status
        try:
            if urlsplit(response.url).path.rstrip("/") == "/uk/authorisation/login":
                response_status = int(response.status)
                logging.info(
                    "Camoufox Student Beans login API responded status=%s elapsed=%.1fs",
                    response_status,
                    time.monotonic() - response_started,
                )
        except Exception:
            logging.debug('Camoufox login response inspection failed', exc_info=True)

    if waf_state is not None:
        page.on("response", on_response)
    try:
        for attempt in range(2):
            dismissed = _dismiss_cookie_consent_page(page)
            if dismissed:
                logging.info('Camoufox Cookie consent dismissed before login submit: %s', dismissed)
            buttons = page.locator('form[aria-label="form"] button')
            try:
                page.wait_for_function(
                    """
                    () => Array.from(document.querySelectorAll('form[aria-label="form"] button'))
                        .some((node) => String(node.innerText || '').trim() === 'Log in'
                            && !node.disabled && node.getAttribute('aria-disabled') !== 'true')
                    """,
                    timeout=timeout_ms,
                )
            except Exception as exc:
                raise Exception("Student Beans Log in button did not become enabled") from exc

            submit = None
            for index in range(buttons.count() - 1, -1, -1):
                target = buttons.nth(index)
                try:
                    if target.is_visible() and target.is_enabled() and target.inner_text().strip() == "Log in":
                        submit = target
                        break
                except Exception:
                    continue
            if submit is None:
                raise Exception("Student Beans Log in button was not found")

            # OneTrust may mount or become visible after the form has already
            # enabled the button, so check immediately before the real click.
            dismissed = _dismiss_cookie_consent_page(page)
            if dismissed:
                logging.info('Camoufox Cookie consent dismissed before login click: %s', dismissed)
            try:
                if waf_solved:
                    submit.evaluate("(element) => element.click()")
                else:
                    submit.click(timeout=timeout_ms)
            except Exception as exc:
                if waf_solved or 'intercepts pointer events' not in str(exc):
                    raise
                dismissed = _dismiss_cookie_consent_page(page)
                if not dismissed:
                    raise
                logging.info('Camoufox Cookie consent dismissed after click interception: %s', dismissed)
                submit.click(timeout=timeout_ms)
            if waf_state is not None and not waf_solved:
                problem_url = wait_for_problem(
                    page,
                    waf_state,
                    min(timeout_ms, AWS_WAF_DETECT_TIMEOUT_MS),
                )
                if problem_url and not waf_state.voucher_urls:
                    try:
                        waf_result = AwsWafAdapter(page, waf_state).solve(problem_url)
                    except AwsWafError as exc:
                        logging.error('Camoufox AWS WAF solve failed: %s', exc)
                        _camoufox_step(
                            login_steps,
                            'aws-waf-solve',
                            'failed',
                            page,
                            reason=str(exc),
                        )
                        raise
                    waf_solved = True
                    logging.info(
                        'Camoufox AWS WAF solved images=%s selected=%s token_length=%s',
                        waf_result.get('images'),
                        waf_result.get('selected'),
                        waf_result.get('token_length'),
                    )
                    _camoufox_debug_state(page, 'aws-waf-solved')
                    _capture_camoufox_screenshot(page, debug_screenshots, 'aws-waf-solved')
                    _camoufox_step(
                        login_steps,
                        'aws-waf-solve',
                        'success',
                        page,
                        images=waf_result.get('images'),
                        selected=waf_result.get('selected'),
                        token_length=waf_result.get('token_length'),
                    )
                    # The AWS WAF widget replays the request that triggered
                    # the challenge after Confirm. A second Log in click
                    # races that native replay and leaves the form disabled.
                    break
            break

        result_deadline = time.monotonic() + timeout_ms / 1000
        message = "站点未确认登录成功"
        success = False
        while time.monotonic() < result_deadline:
            current_url = str(page.url or "")
            current_path = urlsplit(current_url).path.rstrip("/")
            try:
                has_password = page.locator('input[type="password"]').count() > 0
            except Exception:
                has_password = True
            if current_path != login_path and not has_password:
                success = True
                message = "登录成功，已离开登录页"
                break
            error = _camoufox_visible_login_error(page)
            if error:
                message = error
                break
            page.wait_for_timeout(500)

        elapsed = time.monotonic() - started
        if not success and response_status == 405 and not waf_solved:
            message = "登录 API 返回 405，未观测到 AWS WAF challenge"
        logging.info(
            "Camoufox Student Beans login finished success=%s response_status=%s waf_solved=%s elapsed=%.1fs url_path=%s",
            success,
            response_status,
            waf_solved,
            elapsed,
            urlsplit(str(page.url or "")).path,
        )
        return {
            "success": success,
            "message": message,
            "response_status": response_status,
            "elapsed": elapsed,
            "waf_solved": waf_solved,
            "waf_result": waf_result or {},
        }
    finally:
        if waf_state is not None:
            page.remove_listener("response", on_response)


def _wait_for_account_settings(
    page,
    timeout_ms: int,
    screenshots: list[dict[str, str]] | None,
    steps: list[dict[str, object]] | None = None,
) -> bool:
    """Wait for the slow account page before crossing to the www target."""
    started = time.monotonic()
    deadline = started + max(10_000, timeout_ms) / 1000
    while time.monotonic() < deadline:
        try:
            if _is_studentbeans_home_url(page.url):
                _camoufox_debug_state(page, 'studentbeans-home-ready')
                _capture_camoufox_screenshot(page, screenshots, 'studentbeans-home-ready')
                _camoufox_step(steps, 'studentbeans-home-ready', 'success', page)
                return True
            marker = page.get_by_text("Account Settings", exact=True).first
            if marker.count() and marker.is_visible():
                _camoufox_debug_state(page, 'account-settings-ready')
                _capture_camoufox_screenshot(page, screenshots, 'account-settings-ready')
                _camoufox_step(steps, 'account-settings-ready', 'success', page)
                logging.info(
                    "Camoufox Student Beans Account Settings page ready elapsed=%.1fs url_path=%s",
                    time.monotonic() - started,
                    urlsplit(str(page.url or "")).path,
                )
                return True
        except Exception:
            pass
        page.wait_for_timeout(500)
    logging.info(
        "Camoufox Student Beans Account Settings page wait timed out elapsed=%.1fs url_path=%s",
        time.monotonic() - started,
        urlsplit(str(page.url or "")).path,
    )
    _camoufox_debug_state(page, 'account-settings-timeout')
    _capture_camoufox_screenshot(page, screenshots, 'account-settings-timeout')
    _camoufox_step(steps, 'account-settings-ready', 'timeout', page)
    return False


def _is_studentbeans_home_url(value: object) -> bool:
    parsed = urlsplit(str(value or ''))
    return (
        parsed.hostname == SBEANS_STUDENTBEANS_HOME_HOST
        and parsed.path.rstrip('/') == '/uk'
    )


def _camoufox_auth_state(page) -> dict[str, bool]:
    try:
        dom_state = page.evaluate(
            """() => {
              const visible = (node) => {
                if (!node) return false;
                const style = window.getComputedStyle(node);
                const rect = node.getBoundingClientRect();
                return style.display !== 'none' && style.visibility !== 'hidden'
                  && style.opacity !== '0' && rect.width > 0 && rect.height > 0;
              };
              const controls = Array.from(document.querySelectorAll('button, a, [role="button"]'))
                .filter(visible)
                .map((node) => String(node.innerText || node.textContent || '').replace(/\\s+/g, ' ').trim());
              return {
                login_visible: controls.some((text) => /\\b(?:log in|login|sign in)\\b/i.test(text)),
                register_visible: controls.some((text) => /\\bregister\\b/i.test(text)),
              };
            }"""
        )
    except Exception:
        dom_state = {}
    try:
        cookie_names = {
            str(cookie.get('name'))
            for cookie in page.context.cookies()
            if cookie.get('name')
        }
    except Exception:
        cookie_names = set()
    return {
        'viewer_token': 'viewer_token' in cookie_names,
        'login_visible': bool(dom_state.get('login_visible')),
        'register_visible': bool(dom_state.get('register_visible')),
    }


def _complete_camoufox_oauth(
    page,
    timeout_ms: int,
    screenshots: list[dict[str, str]] | None,
    steps: list[dict[str, object]] | None = None,
    referer_url: str = '',
) -> bool:
    """Complete the Student Beans accounts-to-www OAuth handoff in this tab."""
    if _is_studentbeans_home_url(page.url):
        auth_state = _camoufox_auth_state(page)
        auth_deadline = time.monotonic() + min(10_000, max(1_000, timeout_ms)) / 1000
        while (
            not auth_state['viewer_token']
            or auth_state['login_visible']
            or auth_state['register_visible']
        ) and time.monotonic() < auth_deadline:
            page.wait_for_timeout(500)
            auth_state = _camoufox_auth_state(page)
        _camoufox_debug_state(page, 'oauth-already-complete')
        _capture_camoufox_screenshot(page, screenshots, 'oauth-already-complete')
        _camoufox_step(
            steps,
            'oauth-handoff',
            'success' if auth_state['viewer_token'] and not auth_state['login_visible'] and not auth_state['register_visible'] else 'failed',
            page,
            reason='already-on-studentbeans-home',
            viewer_token=auth_state['viewer_token'],
            login_visible=auth_state['login_visible'],
            register_visible=auth_state['register_visible'],
        )
        return bool(auth_state['viewer_token'] and not auth_state['login_visible'] and not auth_state['register_visible'])

    started = time.monotonic()
    _camoufox_step(steps, 'oauth-handoff', 'start', page, target=SBEANS_ACCOUNT_PASSTHROUGH_URL)
    _camoufox_debug_state(page, 'oauth-passthrough-start')
    _capture_camoufox_screenshot(page, screenshots, 'oauth-passthrough-start')

    oauth_paths = {
        '/uk/authorisation/passthrough': 'passthrough',
        '/oauth/authorize': 'authorize',
        '/users/auth/studentbeans/callback': 'callback',
        '/uk': 'studentbeans-home',
    }

    def on_response(response) -> None:
        parsed = urlsplit(response.url)
        if parsed.hostname not in {'accounts.studentbeans.com', SBEANS_STUDENTBEANS_HOME_HOST}:
            return
        stage = oauth_paths.get(parsed.path.rstrip('/'))
        if not stage:
            return
        if stage == 'studentbeans-home' and parsed.hostname != SBEANS_STUDENTBEANS_HOME_HOST:
            return
        redirect = response.headers.get('location', '')
        _camoufox_step(
            steps,
            f'oauth-{stage}',
            'response',
            page,
            url=_redact_url(response.url),
            response_status=response.status,
            redirect=_redact_url(redirect) if redirect else '',
        )

    page.on('response', on_response)
    try:
        response = page.goto(
            SBEANS_ACCOUNT_PASSTHROUGH_URL,
            wait_until='domcontentloaded',
            timeout=max(10_000, timeout_ms),
            referer=referer_url or None,
        )
        settle_deadline = time.monotonic() + min(15_000, max(2_000, timeout_ms)) / 1000
        while not _is_studentbeans_home_url(page.url) and time.monotonic() < settle_deadline:
            page.wait_for_timeout(500)
        if not _is_studentbeans_home_url(page.url) and urlsplit(page.url).path.rstrip('/') == '/uk':
            _camoufox_step(
                steps,
                'oauth-authorize-fallback',
                'start',
                page,
                target=SBEANS_OAUTH_AUTHORIZE_URL,
                reason='passthrough-returned-accounts-home',
            )
            response = page.goto(
                SBEANS_OAUTH_AUTHORIZE_URL,
                wait_until='domcontentloaded',
                timeout=max(10_000, timeout_ms),
                referer=referer_url or None,
            )
            fallback_deadline = time.monotonic() + min(15_000, max(2_000, timeout_ms)) / 1000
            while not _is_studentbeans_home_url(page.url) and time.monotonic() < fallback_deadline:
                page.wait_for_timeout(500)
        if not _is_studentbeans_home_url(page.url):
            _camoufox_debug_state(page, 'oauth-handoff-failed')
            _capture_camoufox_screenshot(page, screenshots, 'oauth-handoff-failed')
            _camoufox_step(
                steps,
                'oauth-handoff',
                'failed',
                page,
                response_status=response.status if response else None,
                elapsed=f'{time.monotonic() - started:.1f}s',
                reason='final-url-not-www-studentbeans-uk',
            )
            return False
        auth_state = _camoufox_auth_state(page)
        auth_deadline = time.monotonic() + min(10_000, max(1_000, timeout_ms)) / 1000
        while (
            not auth_state['viewer_token']
            or auth_state['login_visible']
            or auth_state['register_visible']
        ) and time.monotonic() < auth_deadline:
            page.wait_for_timeout(500)
            auth_state = _camoufox_auth_state(page)
        _camoufox_debug_state(page, 'oauth-final')
        _capture_camoufox_screenshot(page, screenshots, 'oauth-final')
        if not auth_state['viewer_token'] or auth_state['login_visible'] or auth_state['register_visible']:
            _camoufox_step(
                steps,
                'oauth-handoff',
                'failed',
                page,
                elapsed=f'{time.monotonic() - started:.1f}s',
                viewer_token=auth_state['viewer_token'],
                login_visible=auth_state['login_visible'],
                register_visible=auth_state['register_visible'],
                reason='site-domain-home-without-authenticated-state',
            )
            return False
        _camoufox_step(
            steps,
            'oauth-handoff',
            'success',
            page,
            response_status=response.status if response else None,
            elapsed=f'{time.monotonic() - started:.1f}s',
            viewer_token=auth_state['viewer_token'],
            login_visible=auth_state['login_visible'],
            register_visible=auth_state['register_visible'],
        )
        return True
    except Exception as exc:
        _camoufox_debug_state(page, 'oauth-handoff-error')
        _capture_camoufox_screenshot(page, screenshots, 'oauth-handoff-error')
        _camoufox_step(
            steps,
            'oauth-handoff',
            'error',
            page,
            elapsed=f'{time.monotonic() - started:.1f}s',
            error=type(exc).__name__,
        )
        logging.info('Camoufox OAuth handoff failed error=%s', type(exc).__name__)
        return False
    finally:
        page.remove_listener('response', on_response)


def _collect_camoufox_codes(
    page,
    req: V1RequestBase,
    screenshots: list[dict[str, str]] | None,
    steps: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    """Collect VOXI issuance codes without following affiliate navigation."""
    started = time.monotonic()
    target_url = str(req.sbeans_collect_url or '').strip()
    if not target_url:
        raise Exception('Student Beans code collection URL is missing')
    timeout_ms = max(10_000, int(req.sbeans_collect_timeout_ms or 120_000))
    logging.info('Camoufox code collection navigating to offer page')
    page.goto(target_url, wait_until='domcontentloaded', timeout=timeout_ms)
    _camoufox_debug_state(page, 'offer-dom-loaded')
    _capture_camoufox_screenshot(page, screenshots, 'offer-dom-loaded')
    _camoufox_step(steps, 'offer-dom-loaded', 'success', page)
    logging.info(
        'Camoufox code collection offer page DOM loaded; waiting %.1fs for viewer token',
        SBEANS_CODE_PAGE_SETTLE_MS / 1000,
    )
    page.wait_for_timeout(SBEANS_CODE_PAGE_SETTLE_MS)
    for load_attempt in range(1, SBEANS_CODE_MAX_POST_ATTEMPTS + 1):
        try:
            page_state = page.evaluate(
                """() => ({
                    readyState: document.readyState,
                    bodyChildren: document.body ? document.body.children.length : 0,
                    bodyTextLength: document.body ? (document.body.innerText || '').length : 0,
                    bodyHtmlLength: document.body ? document.body.innerHTML.length : 0,
                    hasViewerToken: document.cookie.split(';').some((part) => part.trim().startsWith('viewer_token='))
                })"""
            )
            logging.info(
                'Camoufox offer page state attempt=%d/%d ready=%s body_children=%s body_text=%s body_html=%s viewer_token=%s',
                load_attempt,
                SBEANS_CODE_MAX_POST_ATTEMPTS,
                page_state.get('readyState', 'unknown'),
                page_state.get('bodyChildren', 0),
                page_state.get('bodyTextLength', 0),
                page_state.get('bodyHtmlLength', 0),
                bool(page_state.get('hasViewerToken')),
            )
            _camoufox_debug_state(page, f'offer-attempt-{load_attempt}')
            _capture_camoufox_screenshot(page, screenshots, f'offer-attempt-{load_attempt}')
            _camoufox_step(
                steps,
                f'offer-attempt-{load_attempt}',
                'ready' if page_state.get('hasViewerToken') else 'missing-viewer-token',
                page,
                viewer_token=bool(page_state.get('hasViewerToken')),
                ready_state=page_state.get('readyState', 'unknown'),
            )
            if page_state.get('hasViewerToken'):
                break
        except Exception as exc:
            logging.info(
                'Camoufox offer page state attempt=%d/%d unavailable error=%s',
                load_attempt,
                SBEANS_CODE_MAX_POST_ATTEMPTS,
                type(exc).__name__,
            )
            _camoufox_step(
                steps,
                f'offer-attempt-{load_attempt}',
                'error',
                page,
                error=type(exc).__name__,
            )
        if load_attempt < SBEANS_CODE_MAX_POST_ATTEMPTS:
            logging.info(
                'Camoufox offer page has no viewer token or content; reloading and waiting %.1fs',
                SBEANS_CODE_RETRY_WAIT_MS / 1000,
            )
            page.reload(wait_until='domcontentloaded', timeout=min(timeout_ms, 30_000))
            page.wait_for_timeout(SBEANS_CODE_RETRY_WAIT_MS)
    logging.info('Camoufox code collection offer page settle/reload checks finished')
    payload = page.evaluate(
        """
        async ({endpoint, offers, query, timeoutMs, retryWaitMs, maxAttempts}) => {
          const getViewerToken = () => {
            const cookie = document.cookie.split(';').map((part) => part.trim())
              .find((part) => part.startsWith('viewer_token='));
            if (!cookie) return '';
            const rawToken = cookie.slice('viewer_token='.length);
            try { return decodeURIComponent(rawToken); } catch { return rawToken; }
          };
          const results = [];
          const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
          for (let index = 0; index < offers.length; index += 1) {
            const offer = offers[index];
            let result = null;
            let lastError = 'Code collection did not complete';
            let attempts = 0;
            for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
              attempts = attempt;
              const viewerToken = getViewerToken();
              if (!viewerToken) {
                lastError = 'Login token not found on offer page';
              } else {
                try {
                  const controller = new AbortController();
                  const timer = setTimeout(() => controller.abort(), timeoutMs);
                  const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: {
                      accept: '*/*',
                      authorization: `Bearer ${viewerToken}`,
                      'content-type': 'application/json'
                    },
                    body: JSON.stringify({
                      operationName: 'createIssuanceMutation',
                      variables: {input: {offerUid: offer.offerUid}},
                      query
                    }),
                    mode: 'cors',
                    cache: 'no-store',
                    signal: controller.signal
                  });
                  clearTimeout(timer);
                  const body = await response.json();
                  if (!response.ok) throw new Error(`HTTP ${response.status}`);
                  if (body.errors?.length) throw new Error(body.errors[0].message || 'GraphQL request failed');
                  const issuance = body.data?.createIssuance?.issuance;
                  if (!issuance?.code?.code || !issuance.code.endDate || !issuance.affiliateLink) {
                    throw new Error('Response did not contain a code, end date, and affiliate link');
                  }
                  const affiliate = new URL(issuance.affiliateLink);
                  const destination = affiliate.searchParams.get('ued');
                  const returnedPlanId = destination ? new URL(destination).searchParams.get('planId') : null;
                  if (returnedPlanId !== offer.planId) {
                    throw new Error(`Expected plan ${offer.planId}, received ${returnedPlanId || 'unknown'}`);
                  }
                  result = {
                    ok: true,
                    planId: offer.planId,
                    offerUid: offer.offerUid,
                    code: issuance.code.code,
                    endDate: issuance.code.endDate,
                    issuanceUid: issuance.uid,
                    attempts
                  };
                  break;
                } catch (error) {
                  lastError = error instanceof Error ? error.message : String(error);
                }
              }
              if (attempt < maxAttempts) await sleep(retryWaitMs);
            }
            if (!result) {
              result = {
                ok: false,
                planId: offer.planId,
                offerUid: offer.offerUid,
                error: lastError,
                attempts
              };
            }
            results.push(result);
            if (!result.ok && /invalid token|unauthenticated|unauthorized|login token/i.test(result.error || '')) {
              return {results, fatal: true, message: result.error};
            }
            if (index < offers.length - 1) await sleep(1000 + Math.floor(Math.random() * 501));
          }
          return {results, fatal: false, message: ''};
        }
        """,
        {
            'endpoint': SBEANS_CODE_ENDPOINT,
            'offers': list(SBEANS_CODE_OFFERS),
            'query': SBEANS_CODE_QUERY,
            'timeoutMs': max(1_000, min(timeout_ms, 30_000)),
            'retryWaitMs': SBEANS_CODE_RETRY_WAIT_MS,
            'maxAttempts': SBEANS_CODE_MAX_POST_ATTEMPTS,
        },
    )
    if not isinstance(payload, dict):
        raise Exception('Code collection returned an invalid result')
    results = payload.get('results')
    if not isinstance(results, list):
        results = []
    for item in results:
        if isinstance(item, dict):
            logging.info(
                'Camoufox code collection offer plan=%s success=%s attempts=%s',
                item.get('planId') or 'unknown',
                bool(item.get('ok')),
                item.get('attempts') or 'unknown',
            )
            _camoufox_step(
                steps,
                f"offer-post-{item.get('planId') or 'unknown'}",
                'success' if item.get('ok') else 'failed',
                page,
                attempts=item.get('attempts') or 0,
                error=str(item.get('error') or '')[:160],
            )
    success = (
        len(results) == len(SBEANS_CODE_OFFERS)
        and all(isinstance(item, dict) and item.get('ok') for item in results)
    )
    message = str(payload.get('message') or '')
    if not success and not message:
        failed = next((item for item in results if isinstance(item, dict) and not item.get('ok')), None)
        message = str((failed or {}).get('error') or 'Code collection did not complete')
    elapsed = time.monotonic() - started
    logging.info(
        'Camoufox code collection finished success=%s completed=%d/%d elapsed=%.1fs',
        success,
        sum(1 for item in results if isinstance(item, dict) and item.get('ok')),
        len(SBEANS_CODE_OFFERS),
        elapsed,
    )
    return {
        'success': success,
        'message': message or '代码采集完成',
        'results': results,
        'elapsed': elapsed,
    }


def _resolve_camoufox_challenge(req: V1RequestBase) -> ChallengeResolutionT:
    """Solve the SBeans Turnstile widget with Camoufox in the same browser."""
    from camoufox.sync_api import Camoufox

    timeout_ms = max(1_000, int(req.maxTimeout or 60_000))
    sitekey = str(
        getattr(req, 'turnstile_sitekey', None)
        or os.environ.get('SBEANS_TURNSTILE_SITEKEY', '')
    ).strip()
    if not sitekey:
        raise Exception('Camoufox Turnstile sitekey is not configured')

    utils.start_xvfb_display()
    options = {
        'headless': False,
        'humanize': True,
        'geoip': True,
        'block_webrtc': True,
        'i_know_what_im_doing': True,
        'locale': 'en-GB',
    }
    proxy = _camoufox_proxy(req.proxy)
    if proxy:
        options['proxy'] = proxy

    camoufox = Camoufox(**options)
    context = camoufox.__enter__()
    page = context.new_page()
    waf_state = AwsWafNetworkState()
    waf_state.attach(page)
    debug_screenshots: list[dict[str, str]] | None = [] if req.returnScreenshot else None
    login_steps: list[dict[str, object]] = []
    deadline = time.monotonic() + timeout_ms / 1000
    last_click = 0.0
    last_state_log = 0.0
    token = ''
    login_result: dict[str, object] = {
        "success": False,
        "message": "仅完成 Turnstile 求解",
        "response_status": None,
        "elapsed": 0.0,
    }
    code_result: dict[str, object] = {
        'success': False,
        'message': '未执行代码采集',
        'results': [],
        'elapsed': 0.0,
    }
    try:
        logging.info('Camoufox Turnstile solver started')
        page.goto(req.url, wait_until='domcontentloaded', timeout=timeout_ms)
        page.wait_for_selector(
            "input[name='cf-turnstile-response']",
            state='attached',
            timeout=min(timeout_ms, 30_000),
        )
        _camoufox_debug_state(page, 'login-page-ready')
        _capture_camoufox_screenshot(page, debug_screenshots, 'login-page-ready')
        _camoufox_step(login_steps, 'login-page-ready', 'success', page)
        if req.sbeans_login:
            if not req.sbeans_email or not req.sbeans_password:
                raise Exception('Student Beans login credentials are missing')
            _fill_camoufox_login(
                page,
                str(req.sbeans_email),
                str(req.sbeans_password),
                min(timeout_ms, 120_000),
            )
            _camoufox_debug_state(page, 'login-form-filled')
            _capture_camoufox_screenshot(page, debug_screenshots, 'login-form-filled')
            _camoufox_step(login_steps, 'login-form-filled', 'success', page)
            # Form rendering is separate from the challenge; give Turnstile its
            # full configured window even when the page was slow to mount.
            deadline = time.monotonic() + timeout_ms / 1000
        while time.monotonic() < deadline:
            try:
                token = str(
                    page.locator("input[name='cf-turnstile-response']").first.input_value(timeout=1_000)
                    or ''
                ).strip()
            except Exception:
                token = ''
            if len(token) < 80:
                try:
                    token = str(
                        page.evaluate(
                            """
                            () => window.turnstile && typeof window.turnstile.getResponse === 'function'
                                ? window.turnstile.getResponse() || ''
                                : ''
                            """
                        )
                        or ''
                    ).strip()
                except Exception:
                    token = ''
            if len(token) >= 80:
                logging.info('Camoufox Turnstile token received (length=%d)', len(token))
                break

            now = time.monotonic()
            if now - last_state_log >= 5:
                logging.info(
                    'Camoufox Turnstile waiting token_length=%d elapsed=%.1fs remaining=%.1fs',
                    len(token),
                    now - (deadline - timeout_ms / 1000),
                    max(0.0, deadline - now),
                )
                last_state_log = now
            if now - last_click >= 8:
                dismissed = _dismiss_cookie_consent_page(page)
                if dismissed:
                    logging.info('Camoufox Cookie consent dismissed: %s', dismissed)
                strategy = _click_camoufox_turnstile(page)
                widget_count = page.locator('#cf-turnstile').count()
                frame_count = page.locator(
                    'iframe[src*="challenges.cloudflare.com"], iframe[src*="turnstile"]'
                ).count()
                logging.info(
                    'Camoufox Turnstile click attempted: %s (strategy=%s widget=%d iframe=%d)',
                    'yes' if strategy else 'no',
                    strategy or 'none',
                    widget_count,
                    frame_count,
                )
                last_click = now
            page.wait_for_timeout(1_000)

        if len(token) < 80:
            raise Exception(f'Camoufox Turnstile token timeout after {timeout_ms / 1000:.1f} seconds')

        _camoufox_debug_state(page, 'turnstile-solved-before-login')
        _capture_camoufox_screenshot(page, debug_screenshots, 'turnstile-solved-before-login')
        _camoufox_step(login_steps, 'turnstile-solved-before-login', 'success', page)
        if req.sbeans_login:
            login_result = _submit_camoufox_login(
                page,
                req,
                waf_state,
                debug_screenshots,
                login_steps,
            )
            _camoufox_debug_state(page, 'login-submit-finished')
            _capture_camoufox_screenshot(page, debug_screenshots, 'login-submit-finished')
            _camoufox_step(
                login_steps,
                'login-submit-finished',
                'success' if login_result['success'] else 'failed',
                page,
                response_status=login_result['response_status'],
                elapsed=f"{login_result['elapsed']:.1f}s",
            )
            if login_result['success'] and req.sbeans_collect_codes:
                settings_ready = _wait_for_account_settings(
                    page,
                    max(10_000, int(req.sbeans_login_timeout_ms or 120_000)),
                    debug_screenshots,
                    login_steps,
                )
                if not settings_ready:
                    login_result['success'] = False
                    login_result['message'] = 'Student Beans Account Settings page did not become ready'
                else:
                    oauth_ready = _complete_camoufox_oauth(
                        page,
                        max(10_000, int(req.sbeans_login_timeout_ms or 120_000)),
                        debug_screenshots,
                        login_steps,
                        str(req.url or ''),
                    )
                    if not oauth_ready:
                        login_result['success'] = False
                        login_result['message'] = 'Student Beans OAuth handoff did not reach www.studentbeans.com/uk'
                    else:
                        logging.info('Camoufox Student Beans OAuth handoff completed; opening VOXI target in the same tab')
            if code_collection_allowed(login_result, req.sbeans_collect_codes):
                code_result = _collect_camoufox_codes(page, req, debug_screenshots, login_steps)
            elif req.sbeans_collect_codes:
                logging.info('Camoufox code collection skipped because same-page authentication was not confirmed')

        result = ChallengeResolutionResultT({})
        result.url = page.url
        result.status = 200
        result.cookies = page.context.cookies()
        result.userAgent = page.evaluate('navigator.userAgent')
        result.turnstile_token = token
        result.sbeans_login_success = bool(login_result["success"]) if req.sbeans_login else None
        result.sbeans_login_message = str(login_result["message"])
        result.sbeans_login_response_status = login_result["response_status"]
        result.sbeans_login_elapsed = float(login_result["elapsed"])
        result.sbeans_login_auth_confirmed = bool(login_result["success"]) if req.sbeans_login else None
        result.sbeans_login_graphql_logged_in = None
        result.sbeans_login_viewer_token_present = None
        result.sbeans_login_register_visible = None
        result.sbeans_login_login_visible = None
        result.sbeans_login_account_marker_visible = None
        result.sbeans_login_auth_cookie_names = []
        result.sbeans_login_steps = login_steps
        result.sbeans_debug_screenshots = debug_screenshots or []
        result.sbeans_code_results = code_result['results']
        result.sbeans_code_collection_success = bool(code_result['success']) if req.sbeans_collect_codes else None
        result.sbeans_code_collection_message = str(code_result['message'])
        result.sbeans_code_collection_elapsed = float(code_result['elapsed'])
        if req.returnScreenshot:
            result.screenshot = base64.b64encode(
                page.screenshot(full_page=True)
            ).decode('ascii')
        response = ChallengeResolutionT({})
        response.status = STATUS_OK
        response.message = 'Challenge solved!'
        response.result = result
        return response
    finally:
        waf_state.detach()
        camoufox.__exit__(None, None, None)


def click_turnstile_frame(driver: WebDriver) -> bool:
    try:
        driver.switch_to.default_content()
        frames = driver.find_elements(By.TAG_NAME, "iframe")
        candidates = []
        for frame in frames:
            src = (frame.get_attribute("src") or "").lower()
            title = (frame.get_attribute("title") or "").lower()
            if "cloudflare" in src or "turnstile" in src or "captcha" in title:
                candidates.append(frame)
        logging.debug(
            "Turnstile iframe candidates=%d total=%d",
            len(candidates),
            len(frames),
        )
        for frame in candidates:
            size = frame.size
            if size.get("width", 0) <= 0 or size.get("height", 0) <= 0:
                continue
            click_y = int(size["height"] / 2)
            ActionChains(driver).move_to_element_with_offset(
                frame, 24, click_y
            ).click().perform()
            logging.info(
                "Turnstile iframe clicked (x=24, y=%d)",
                click_y,
            )
            return True
    except Exception:
        logging.debug("Turnstile iframe coordinate click failed")
    finally:
        driver.switch_to.default_content()
    return False


def click_verify(driver: WebDriver, num_tabs: int = 1):
    dismiss_cookie_consent(driver)
    if click_turnstile_frame(driver):
        return
    try:
        logging.debug("Try to find the Cloudflare verify checkbox...")
        actions = ActionChains(driver)
        actions.pause(5)
        for _ in range(num_tabs):
            actions.send_keys(Keys.TAB).pause(0.1)
        actions.pause(1)
        actions.send_keys(Keys.SPACE).perform()
        
        logging.debug(f"Cloudflare verify checkbox clicked after {num_tabs} tabs!")
    except Exception:
        logging.debug("Cloudflare verify checkbox not found on the page.")
    finally:
        driver.switch_to.default_content()

    try:
        logging.debug("Try to find the Cloudflare 'Verify you are human' button...")
        button = driver.find_element(
            by=By.XPATH,
            value="//input[@type='button' and @value='Verify you are human']",
        )
        if button:
            actions = ActionChains(driver)
            actions.move_to_element_with_offset(button, 5, 7)
            actions.click(button)
            actions.perform()
            logging.debug("The Cloudflare 'Verify you are human' button found and clicked!")
    except Exception:
        logging.debug("The Cloudflare 'Verify you are human' button not found on the page.")

    time.sleep(2)

def _get_turnstile_token(driver: WebDriver, tabs: int):
    token_input = driver.find_element(By.CSS_SELECTOR, "input[name='cf-turnstile-response']")
    current_value = token_input.get_attribute("value")
    while True:
        click_verify(driver, num_tabs=tabs)
        turnstile_token = token_input.get_attribute("value")
        if turnstile_token:
            if turnstile_token != current_value:
                logging.info("Turnstile token received (length=%d)", len(turnstile_token))
                return turnstile_token
        logging.debug(f"Failed to extract token possibly click failed")        

        # reset focus
        driver.execute_script("""
            let el = document.createElement('button');
            el.style.position='fixed';
            el.style.top='0';
            el.style.left='0';
            document.body.prepend(el);
            el.focus();
        """)
        time.sleep(1)

def _resolve_turnstile_captcha(req: V1RequestBase, driver: WebDriver):
    turnstile_token = None
    if req.tabs_till_verify is not None:
        logging.debug(f'Navigating to... {req.url} in order to pass the turnstile challenge')
        driver.get(req.url)

        turnstile_challenge_found = False
        for selector in TURNSTILE_SELECTORS:
            found_elements = driver.find_elements(By.CSS_SELECTOR, selector)   
            if len(found_elements) > 0:
                turnstile_challenge_found = True
                logging.info("Turnstile challenge detected. Selector found: " + selector)
                break
        if turnstile_challenge_found:
            turnstile_token = _get_turnstile_token(driver=driver, tabs=req.tabs_till_verify)
        else:
            logging.debug(f'Turnstile challenge not found')
    return turnstile_token

def _evil_logic(req: V1RequestBase, driver: WebDriver, method: str) -> ChallengeResolutionT:
    res = ChallengeResolutionT({})
    res.status = STATUS_OK
    res.message = ""

    # optionally block resources like images/css/fonts using CDP
    disable_media = utils.get_config_disable_media()
    if req.disableMedia is not None:
        disable_media = req.disableMedia
    if disable_media:
        block_urls = [
            # Images
            "*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.bmp", "*.svg", "*.ico",
            "*.PNG", "*.JPG", "*.JPEG", "*.GIF", "*.WEBP", "*.BMP", "*.SVG", "*.ICO",
            "*.tiff", "*.tif", "*.jpe", "*.apng", "*.avif", "*.heic", "*.heif",
            "*.TIFF", "*.TIF", "*.JPE", "*.APNG", "*.AVIF", "*.HEIC", "*.HEIF",
            # Stylesheets
            "*.css",
            "*.CSS",
            # Fonts
            "*.woff", "*.woff2", "*.ttf", "*.otf", "*.eot",
            "*.WOFF", "*.WOFF2", "*.TTF", "*.OTF", "*.EOT"
        ]
        try:
            logging.debug("Network.setBlockedURLs: %s", block_urls)
            driver.execute_cdp_cmd("Network.enable", {})
            driver.execute_cdp_cmd("Network.setBlockedURLs", {"urls": block_urls})
        except Exception:
            # if CDP commands are not available or fail, ignore and continue
            logging.debug("Network.setBlockedURLs failed or unsupported on this webdriver")

    # navigate to the page
    logging.debug(f"Navigating to... {req.url}")
    turnstile_token = None

    if method == "POST":
        _post_request(req, driver)
    else:
        if req.tabs_till_verify is None:
            driver.get(req.url)
        else:
            turnstile_token = _resolve_turnstile_captcha(req, driver)

    # set cookies if required
    if req.cookies is not None and len(req.cookies) > 0:
        logging.debug(f'Setting cookies...')
        for cookie in req.cookies:
            driver.delete_cookie(cookie['name'])
            driver.add_cookie(cookie)
        # reload the page
        if method == 'POST':
            _post_request(req, driver)
        else:
            driver.get(req.url)

    # wait for the page
    if utils.get_config_log_html():
        logging.debug(f"Response HTML:\n{driver.page_source}")
    html_element = driver.find_element(By.TAG_NAME, "html")
    page_title = driver.title

    # find access denied titles
    for title in ACCESS_DENIED_TITLES:
        if page_title.startswith(title):
            raise Exception('Cloudflare has blocked this request. '
                            'Probably your IP is banned for this site, check in your web browser.')
    # find access denied selectors
    for selector in ACCESS_DENIED_SELECTORS:
        found_elements = driver.find_elements(By.CSS_SELECTOR, selector)
        if len(found_elements) > 0:
            raise Exception('Cloudflare has blocked this request. '
                            'Probably your IP is banned for this site, check in your web browser.')

    # find challenge by title
    challenge_found = False
    for title in CHALLENGE_TITLES:
        if title.lower() == page_title.lower():
            challenge_found = True
            logging.info("Challenge detected. Title found: " + page_title)
            break
    if not challenge_found:
        # find challenge by selectors
        for selector in CHALLENGE_SELECTORS:
            found_elements = driver.find_elements(By.CSS_SELECTOR, selector)
            if len(found_elements) > 0:
                challenge_found = True
                logging.info("Challenge detected. Selector found: " + selector)
                break

    attempt = 0
    if challenge_found:
        while True:
            try:
                attempt = attempt + 1
                # wait until the title changes
                for title in CHALLENGE_TITLES:
                    logging.debug("Waiting for title (attempt " + str(attempt) + "): " + title)
                    WebDriverWait(driver, SHORT_TIMEOUT).until_not(title_is(title))

                # then wait until all the selectors disappear
                for selector in CHALLENGE_SELECTORS:
                    logging.debug("Waiting for selector (attempt " + str(attempt) + "): " + selector)
                    WebDriverWait(driver, SHORT_TIMEOUT).until_not(
                        presence_of_element_located((By.CSS_SELECTOR, selector)))

                # all elements not found
                break

            except TimeoutException:
                logging.debug("Timeout waiting for selector")

                click_verify(driver)

                # update the html (cloudflare reloads the page every 5 s)
                html_element = driver.find_element(By.TAG_NAME, "html")

        # waits until cloudflare redirection ends
        logging.debug("Waiting for redirect")
        # noinspection PyBroadException
        try:
            WebDriverWait(driver, SHORT_TIMEOUT).until(staleness_of(html_element))
        except Exception:
            logging.debug("Timeout waiting for redirect")

        logging.info("Challenge solved!")
        res.message = "Challenge solved!"
    else:
        logging.info("Challenge not detected!")
        res.message = "Challenge not detected!"

    challenge_res = ChallengeResolutionResultT({})
    challenge_res.url = driver.current_url
    challenge_res.status = 200  # todo: fix, selenium not provides this info
    challenge_res.cookies = driver.get_cookies()
    challenge_res.userAgent = utils.get_user_agent(driver)
    challenge_res.turnstile_token = turnstile_token

    if not req.returnOnlyCookies:
        challenge_res.headers = {}  # todo: fix, selenium not provides this info

        if req.waitInSeconds and req.waitInSeconds > 0:
            logging.info("Waiting " + str(req.waitInSeconds) + " seconds before returning the response...")
            time.sleep(req.waitInSeconds)

        challenge_res.response = driver.page_source

    if req.returnScreenshot:
        challenge_res.screenshot = driver.get_screenshot_as_base64()

    res.result = challenge_res
    return res


def _post_request(req: V1RequestBase, driver: WebDriver):
    post_form = f'<form id="hackForm" action="{req.url}" method="POST">'
    query_string = req.postData if req.postData and req.postData[0] != '?' else req.postData[1:] if req.postData else ''
    pairs = query_string.split('&')
    for pair in pairs:
        parts = pair.split('=', 1)
        # noinspection PyBroadException
        try:
            name = unquote(parts[0])
        except Exception:
            name = parts[0]
        if name == 'submit':
            continue
        # noinspection PyBroadException
        try:
            value = unquote(parts[1]) if len(parts) > 1 else ''
        except Exception:
            value = parts[1] if len(parts) > 1 else ''
        # Protection of " character, for syntax
        value=value.replace('"','&quot;')
        post_form += f'<input type="text" name="{escape(quote(name))}" value="{escape(quote(value))}"><br>'
    post_form += '</form>'
    html_content = f"""
        <!DOCTYPE html>
        <html>
        <body>
            {post_form}
            <script>document.getElementById('hackForm').submit();</script>
        </body>
        </html>"""
    driver.get("data:text/html;charset=utf-8,{html_content}".format(html_content=html_content))
