import unittest

from playwright.sync_api import sync_playwright

from camoufox_auth import code_collection_allowed
from dtos import V1RequestBase
from flaresolverr_service import _submit_camoufox_login


class CamoufoxLoginAuthTests(unittest.TestCase):
    def test_code_collection_requires_confirmed_login(self):
        self.assertFalse(code_collection_allowed({"success": False}, True))
        self.assertTrue(code_collection_allowed({"success": True}, True))
        self.assertFalse(code_collection_allowed({"success": True}, False))

    def test_login_submit_dismisses_onetrust_overlay(self):
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, executable_path='/usr/bin/chromium')
            page = browser.new_page()
            page.set_content(
                """
                <form aria-label="form">
                  <input type="password" value="secret">
                  <button type="button" onclick="document.querySelector('input').remove()">Log in</button>
                </form>
                <div id="onetrust-consent-sdk" style="position:fixed;inset:0;z-index:10">
                  <div class="onetrust-pc-dark-filter" style="position:absolute;inset:0;background:#0008"></div>
                  <button id="onetrust-accept-btn-handler" type="button"
                    style="position:absolute;top:20px;left:20px;z-index:11"
                    onclick="document.querySelector('#onetrust-consent-sdk').remove()">
                    Accept All Cookies
                  </button>
                </div>
                """
            )
            request = V1RequestBase({
                "url": "https://accounts.studentbeans.com/uk/authorisation/log-in",
                "sbeans_login_timeout_ms": 10_000,
            })

            result = _submit_camoufox_login(page, request)

            self.assertTrue(result["success"])
            self.assertEqual(page.locator("#onetrust-consent-sdk").count(), 0)
            browser.close()


if __name__ == "__main__":
    unittest.main()
