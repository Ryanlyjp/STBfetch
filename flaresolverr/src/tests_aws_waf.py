import unittest
import json
from io import BytesIO
import os
from urllib.error import HTTPError
from unittest.mock import patch

import aws_waf
from aws_waf import (AwsWafAdapter, AwsWafError, AwsWafNetworkState,
                     VisionConfig, _build_vision_request, _vision_response_text,
                     _vision_text, parse_solution_indices, solve_captcha_images)


class _FakeContext:
    def __init__(self):
        self.added = []

    def cookies(self):
        return [{
            "name": "aws-waf-token",
            "value": "e" * 394,
            "domain": "accounts.studentbeans.com",
            "path": "/",
        }]

    def add_cookies(self, cookies):
        self.added.extend(cookies)


class _FakePage:
    def __init__(self):
        self.context = _FakeContext()
        self.url = "https://accounts.studentbeans.com/uk/authorisation/log-in"
        self.calls = []
        self.clicks = []
        self.state = None
        self.mouse = _FakeMouse(self)

    def locator(self, selector):
        if selector == "awswaf-captcha":
            return _FakeLocator(self, "captcha")
        return _FakeLocator(self, "unknown")

    def wait_for_timeout(self, milliseconds):
        return None

    def evaluate(self, script, argument=None):
        if isinstance(argument, dict) and argument.get("url"):
            url = argument["url"]
            self.calls.append((url, argument.get("method"), argument.get("body")))
            if url.endswith("/problem") or "/problem?" in url:
                response = {
                    "state": {"iv": "i", "payload": "p"},
                    "key": "k",
                    "hmac_tag": "h",
                    "assets": {"images": ["a", "b", "c", "d", "e", "f", "g", "h", "i"], "target": "bike"},
                    "localized_assets": {"target0": "bicycle"},
                }
            elif url.endswith("/verify"):
                response = {"success": True, "captcha_voucher": "v" * 501}
            else:
                response = {"token": "t" * 394}
            return {"status": 200, "text": json.dumps(response)}
        return True


class _FakeResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self):
        return self.payload


class _FakeLocator:
    def __init__(self, page, kind, index=None):
        self.page = page
        self.kind = kind
        self.index = index

    @property
    def last(self):
        return self

    def count(self):
        return {
            "captcha": 1,
            "canvas": 1,
            "grid_buttons": 9,
            "tiles": 2,
            "confirm": 1,
        }.get(self.kind, 0)

    def nth(self, index):
        return _FakeLocator(self.page, self.kind, index)

    def click(self, **kwargs):
        self.page.clicks.append((self.kind, self.index))
        if self.kind == "confirm":
            self.page.state.voucher_urls.append("https://w.token.awswaf.com/id/voucher")
            self.page.state.voucher_statuses.append(200)

    def inner_text(self):
        if self.kind == "grid_buttons":
            return str((self.index or 0) + 1)
        if self.kind == "captcha":
            return "Choose all the bike Confirm"
        return ""

    def locator(self, selector):
        if selector == "canvas":
            return _FakeLocator(self.page, "canvas")
        if selector == "button[type='button']":
            return _FakeLocator(self.page, "grid_buttons")
        if selector in {"img", "button"}:
            return _FakeLocator(self.page, "tiles")
        if selector == "button[type='submit']":
            return _FakeLocator(self.page, "confirm")
        return _FakeLocator(self.page, "unknown")

    def get_by_role(self, role, name):
        return _FakeLocator(self.page, "confirm")

    def get_by_text(self, text, exact=False):
        return _FakeLocator(self.page, "confirm")

    def filter(self, **kwargs):
        return self

    def bounding_box(self):
        return {"x": 0, "y": 0, "width": 320, "height": 320}


class _FakeMouse:
    def __init__(self, page):
        self.page = page

    def click(self, x, y):
        self.page.clicks.append(("canvas", round(x), round(y)))


class AwsWafTests(unittest.TestCase):
    def setUp(self):
        aws_waf._VISION_LAST_REQUEST_FINISHED = 0.0
        for name in (
            "VISION_API_URL",
            "VISION_API_KEY",
            "VISION_MODEL",
            "VISION_API_MODE",
            "VISION_AUTH_HEADER",
            "VISION_AUTH_PREFIX",
        ):
            os.environ.pop(name, None)

    def test_parse_solution_indices_accepts_json_code_fence(self):
        self.assertEqual(
            [0, 2, 4],
            parse_solution_indices("```json\n[0, 2, 4]\n```", 6),
        )

    def test_parse_solution_indices_rejects_out_of_range_values(self):
        with self.assertRaises(AwsWafError):
            parse_solution_indices("[0, 6]", 6)

    def test_solve_captcha_images_requires_gemini_key(self):
        with self.assertRaisesRegex(AwsWafError, "GEMINI_API_KEY"):
            solve_captcha_images(["a"], "b", "")

    def test_solve_captcha_images_uses_injected_request(self):
        calls = []

        def request(images, target, api_key):
            calls.append((images, target, api_key))
            return "[1]"

        result = solve_captcha_images(["a", "b"], "bicycle", "secret", request)
        self.assertEqual([1], result)
        self.assertEqual([(["a", "b"], "bicycle", "secret")], calls)

    def test_build_chat_completions_request_uses_full_url_and_bearer_auth(self):
        config = VisionConfig(
            "https://provider.example/v1",
            "provider-key",
            "vision-chat",
            "chat_completions",
            "Authorization",
            "Bearer",
        )
        url, headers, payload = _build_vision_request(config, ["a"], "bicycle")
        self.assertEqual("https://provider.example/v1/chat/completions", url)
        self.assertEqual("Bearer provider-key", headers["Authorization"])
        self.assertEqual("vision-chat", payload["model"])
        self.assertEqual("image_url", payload["messages"][0]["content"][2]["type"])

    def test_build_responses_request_uses_input_image_shape(self):
        config = VisionConfig(
            "https://provider.example/v1/",
            "provider-key",
            "vision-response",
            "responses",
            "x-api-key",
            "",
        )
        url, headers, payload = _build_vision_request(config, ["a"], "bicycle")
        self.assertEqual("https://provider.example/v1/responses", url)
        self.assertEqual("provider-key", headers["x-api-key"])
        self.assertEqual("input_image", payload["input"][0]["content"][2]["type"])

    def test_parse_chat_and_responses_text_shapes(self):
        self.assertEqual(
            "[1]",
            _vision_response_text(
                {"choices": [{"message": {"content": "[1]"}}]},
                "chat_completions",
            ),
        )
        self.assertEqual(
            "[2]",
            _vision_response_text({"output_text": "[2]"}, "responses"),
        )
        self.assertEqual(
            "[3]",
            _vision_response_text(
                {"output": [{"content": [{"type": "output_text", "text": "[3]"}]}]},
                "responses",
            ),
        )

    def test_vision_text_uses_configured_chat_provider(self):
        os.environ.update({
            "VISION_API_URL": "https://provider.example/v1",
            "VISION_API_KEY": "provider-key",
            "VISION_MODEL": "vision-chat",
            "VISION_API_MODE": "chat_completions",
        })
        with patch(
            "aws_waf.urlopen",
            return_value=_FakeResponse({"choices": [{"message": {"content": "[0]"}}]}),
        ) as request:
            result = _vision_text(["a"], "bike", "provider-key")
        self.assertEqual("[0]", result)
        sent = request.call_args.args[0]
        self.assertEqual("https://provider.example/v1/chat/completions", sent.full_url)
        self.assertEqual("Bearer provider-key", sent.get_header("Authorization"))
        self.assertEqual("application/json", sent.get_header("Accept"))
        self.assertEqual("sbeans-vision-client/1.0", sent.get_header("User-agent"))
        body = json.loads(sent.data.decode("utf-8"))
        self.assertEqual("vision-chat", body["model"])

    def test_vision_prepaid_429_is_not_retried_and_keeps_provider_detail(self):
        error = HTTPError(
            "https://generativelanguage.googleapis.com",
            429,
            "Too Many Requests",
            {"Retry-After": "1"},
            BytesIO(b'{"error":{"message":"Your prepayment credits are depleted."}}'),
        )
        with patch("aws_waf.urlopen", side_effect=error) as request:
            with self.assertRaisesRegex(AwsWafError, "prepayment credits are depleted"):
                aws_waf._vision_text(["a"], "bike", "key")
        request.assert_called_once()

    def test_urls_match_student_beans_waf_hosts_and_paths(self):
        api_key, locale, verify_url, voucher_url = AwsWafAdapter._urls(
            "https://w.eu-west-1.captcha.awswaf.com/id/problem"
            "?kind=visual&domain=accounts.studentbeans.com&locale=en-gb&api_key=abc"
        )
        self.assertEqual("abc", api_key)
        self.assertEqual("en-gb", locale)
        self.assertEqual(
            "https://w.eu-west-1.captcha.awswaf.com/id/verify",
            verify_url,
        )
        self.assertEqual(
            "https://w.eu-west-1.token.awswaf.com/id/voucher",
            voucher_url,
        )

    def test_urls_reject_missing_api_key(self):
        with self.assertRaisesRegex(AwsWafError, "api_key"):
            AwsWafAdapter._urls(
                "https://w.eu-west-1.captcha.awswaf.com/id/problem?kind=visual"
            )

    def test_adapter_clicks_ui_solution_and_waits_for_browser_voucher(self):
        page = _FakePage()
        state = AwsWafNetworkState()
        page.state = state
        problem_url = (
            "https://w.eu-west-1.captcha.awswaf.com/id/problem"
            "?kind=visual&domain=accounts.studentbeans.com&locale=en-gb&api_key=waf-key"
        )
        page.state.problem_payloads.append(
            (
                problem_url,
                {
                    "assets": {
                        "images": ["a", "b", "c", "d", "e", "f", "g", "h", "i"],
                        "target": "bike",
                    },
                    "localized_assets": {"target0": "bicycle"},
                },
            )
        )
        with patch("aws_waf.solve_captcha_images", return_value=[1]):
            result = AwsWafAdapter(page, state, "gemini-key").solve(problem_url)
        self.assertTrue(result["success"])
        self.assertEqual(0, len(page.calls))
        self.assertEqual(("grid_buttons", 1), page.clicks[0])
        self.assertEqual(("confirm", None), page.clicks[1])
        self.assertEqual(9, result["images"])
        self.assertEqual(1, result["selected"])


if __name__ == "__main__":
    unittest.main()
