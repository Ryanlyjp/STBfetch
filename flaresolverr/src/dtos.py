
STATUS_OK = "ok"
STATUS_ERROR = "error"


class ChallengeResolutionResultT:
    url: str = None
    status: int = None
    headers: list = None
    response: str = None
    cookies: list = None
    userAgent: str = None
    screenshot: str | None = None
    turnstile_token: str = None
    sbeans_login_success: bool = None
    sbeans_login_message: str = None
    sbeans_login_response_status: int = None
    sbeans_login_elapsed: float = None
    sbeans_login_auth_confirmed: bool = None
    sbeans_login_graphql_logged_in: bool = None
    sbeans_login_viewer_token_present: bool = None
    sbeans_login_register_visible: bool = None
    sbeans_login_login_visible: bool = None
    sbeans_login_account_marker_visible: bool = None
    sbeans_login_auth_cookie_names: list = None
    sbeans_login_steps: list = None
    sbeans_debug_screenshots: list = None
    sbeans_code_results: list = None
    sbeans_code_collection_success: bool = None
    sbeans_code_collection_message: str = None
    sbeans_code_collection_elapsed: float = None

    def __init__(self, _dict):
        self.__dict__.update(_dict)


class ChallengeResolutionT:
    status: str = None
    message: str = None
    result: ChallengeResolutionResultT = None

    def __init__(self, _dict):
        self.__dict__.update(_dict)
        if self.result is not None:
            self.result = ChallengeResolutionResultT(self.result)


class V1RequestBase(object):
    # V1RequestBase
    cmd: str = None
    cookies: list = None
    maxTimeout: int = None
    proxy: dict = None
    session: str = None
    session_ttl_minutes: int = None
    headers: list = None  # deprecated v2.0.0, not used
    userAgent: str = None  # deprecated v2.0.0, not used

    # V1Request
    url: str = None
    postData: str = None
    returnOnlyCookies: bool = None
    returnScreenshot: bool = None
    download: bool = None   # deprecated v2.0.0, not used
    returnRawHtml: bool = None  # deprecated v2.0.0, not used
    waitInSeconds: int = None
    # Optional resource blocking flag (blocks images, CSS, and fonts)
    disableMedia: bool = None
    # Optional when you've got a turnstile captcha that needs to be clicked after X number of Tab presses
    tabs_till_verify : int = None
    # Optional browser implementation selected by an internal integration.
    browser: str = None
    turnstile_sitekey: str = None
    sbeans_login: bool = None
    sbeans_email: str = None
    sbeans_password: str = None
    sbeans_login_timeout_ms: int = None
    sbeans_collect_codes: bool = None
    sbeans_collect_url: str = None
    sbeans_collect_timeout_ms: int = None

    def __init__(self, _dict):
        self.__dict__.update(_dict)


class V1ResponseBase(object):
    # V1ResponseBase
    status: str = None
    message: str = None
    session: str = None
    sessions: list[str] = None
    startTimestamp: int = None
    endTimestamp: int = None
    version: str = None

    # V1ResponseSolution
    solution: ChallengeResolutionResultT = None

    # hidden vars
    __error_500__: bool = False

    def __init__(self, _dict):
        self.__dict__.update(_dict)
        if self.solution is not None:
            self.solution = ChallengeResolutionResultT(self.solution)


class IndexResponse(object):
    msg: str = None
    version: str = None
    userAgent: str = None

    def __init__(self, _dict):
        self.__dict__.update(_dict)


class HealthResponse(object):
    status: str = None

    def __init__(self, _dict):
        self.__dict__.update(_dict)
