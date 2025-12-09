#  msauth_browser/core/auth.py

# Built-in imports
import secrets
from urllib.parse import urlencode, parse_qs, urlparse, unquote
from typing import Dict, Optional, Any
import re

# External library imports
import pkce
import httpx
from loguru import logger

from playwright.sync_api import sync_playwright

# Internal imports
from .config import AppConfig

AUTH_TIMEOUT = 5 * 60 * 1000  # 5 minutes

class PlaywrightAuth:
    """
    Microsoft authentication handler using Playwright for interactive browser login.

    This class provides a flexible way to authenticate with Microsoft services
    using the OAuth 2.0 authorization code flow with PKCE.
    """

    def __init__(
        self, config: AppConfig, tenant: str = "common", additional_scope: str = ""
    ) -> None:
        """
        Initialize the PlaywrightAuth instance.
        """
        self._client_id = config.client_id
        self._redirect_uri = config.redirect_uri

        self._tenant = tenant

        scopes = config.default_scopes.copy()

        if additional_scope:
            toRemove = []
            for scope in config.default_scopes:
                if scope.find(".default") != -1:
                    toRemove.append(scope)
            for scope in toRemove:
                logger.warning(
                    f"⚠️ Removing scope '{scope}' as additional scopes are specified."
                )
                scopes.remove(scope)

        # Prepare scope string
        scope_string = " ".join(scopes)
        if "openid" not in scope_string:
            scope_string = f"openid {scope_string}"

        if additional_scope:
            scope_string = f"{scope_string} {additional_scope.strip()}"

        self._scopes = scope_string

    @property
    def client_id(self) -> str:
        return self._client_id

    @property
    def redirect_uri(self) -> str:
        return self._redirect_uri

    @property
    def scopes(self) -> str:
        return self._scopes

    @property
    def tenant(self) -> str:
        return self._tenant

    def get_tokens(
        self,
        prt_cookie: Optional[str] = None,
        headless: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """
        Perform interactive browser authentication and retrieve tokens.

        Args:
            prt_cookie: Optional X-Ms-RefreshTokenCredential PRT cookie for SSO
            headless: Run browser in headless mode (default: False)

        Returns:
            Dictionary containing access_token, refresh_token, and expires_in,
            or None if authentication fails
        """
        response_dict = {
            "refresh_token": None,
            "access_token": None,
            "expires_in": None,
            "scope": None,
        }
        code_verifier, code_challenge = pkce.generate_pkce_pair()
        state = secrets.token_urlsafe(32)

        params = {
            "client_id": self.client_id,
            "scope": self.scopes,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
        }

        auth_url = f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/authorize?{urlencode(params)}"

        logger.info("🔐 Starting authentication process using Playwright")

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=headless,
                args=[
                    "--no-sandbox",
                    "--disable-features=BlockInsecurePrivateNetworkRequests",
                    "--disable-localhost-ipa",
                    "--host-resolver-rules=MAP localhost 0.0.0.0, MAP 127.0.0.1 0.0.0.0, MAP ::1 0.0.0.0",
                ],
            )

            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
                locale="en-US",

                viewport={"width": 1280, "height": 720},
                screen={"width": 1366, "height": 768},
                device_scale_factor=1,

                # Input model
                is_mobile=False,
                has_touch=False,

                # User preferences
                color_scheme="light",
                reduced_motion="no-preference",
                forced_colors="none",

                # Do not auto-grant permissions (matches reality)
                permissions=[],
            )

            if prt_cookie:
                context.add_cookies(
                    [
                        {
                            "name": "x-ms-RefreshTokenCredential",
                            "value": prt_cookie,
                            "domain": "login.microsoftonline.com",
                            "path": "/",
                            "httpOnly": True,
                            "secure": True,
                        }
                    ]
                )

            page = context.new_page()
            logger.info(f"UA in use: {page.evaluate('navigator.userAgent')}")

            logger.info(f"🔗 Opening auth URL: {auth_url}")

            page.goto(auth_url)
            page.wait_for_load_state("load")

            logger.info("🔍 Waiting for authentication to complete")
            logger.info(f"Searching for this pattern in URL: {self.redirect_uri}")
            redirect_uri_pattern = re.compile(rf"^{re.escape(self.redirect_uri)}")
            try:
                page.wait_for_url(
                    redirect_uri_pattern,
                    timeout=AUTH_TIMEOUT,
                    wait_until="domcontentloaded",
                )
            except TimeoutError:
                logger.error("⏱️ Timeout waiting for auth redirect.")
                logger.error(f"Final URL at timeout: {page.url}")
                return None
            except Exception as exc:
                logger.error("❌ Authentication flow interrupted.")
                logger.error(f"Last URL: {page.url}")
                logger.error(f"Exception: {exc}")
                return None
            else:
                final_url = page.url
                logger.success("🔄 Redirection received.")
            finally:
                if 'final_url' in locals():
                    context.close()
                    browser.close()
                    logger.info("🖥️ Browser closed.")

        code = parse_qs(urlparse(final_url).query).get("code", [None])[0]

        if not code:
            logger.error("❌ Authorization code not found in redirect URL.")
            # URL decode the URL for better readability in logs
            decoded_url = unquote(final_url)
            logger.error(f"Redirect URL: {decoded_url}")
            return None

        logger.info("🔑 Exchanging authorization code for tokens")

        with httpx.Client() as client:
            response = client.post(
                f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token",
                data={
                    "client_id": self.client_id,
                    "redirect_uri": self.redirect_uri,
                    "scope": self.scopes,
                    "code": code,
                    "code_verifier": code_verifier,
                    "grant_type": "authorization_code",
                    "claims": '{"access_token":{"xms_cc":{"values":["CP1"]}}}',
                },
                headers={"Origin": urlparse(self.redirect_uri).netloc},
            )

        if response.status_code != 200:
            logger.error(f"❌ Token exchange failed: {response.text}")
            return None

        logger.success("✅ Token exchange successful")

        tokens = response.json()
        response_dict["refresh_token"] = tokens.get("refresh_token")
        response_dict["access_token"] = tokens.get("access_token")
        response_dict["expires_in"] = tokens.get("expires_in")
        response_dict["scope"] = tokens.get("scope")

        return response_dict

    def refresh_tokens(self, refresh_token: str) -> Optional[Dict[str, Any]]:

        response_dict = {
            "refresh_token": None,
            "access_token": None,
            "expires_in": None,
            "scope": None,
        }

        if not refresh_token:
            raise Exception("⛔ No refresh token available to refresh access token.")

        response = httpx.post(
            url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
            data={
                "client_id": self.client_id,
                "scope": self.scopes,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
            headers={"Origin": urlparse(self.redirect_uri).netloc},
            verify=False,
        )

        if response.status_code != 200:
            raise Exception(f"Failed to refresh token: {response.text}.")

        tokens = response.json()
        response_dict["refresh_token"] = tokens.get("refresh_token")
        response_dict["access_token"] = tokens.get("access_token")
        response_dict["expires_in"] = tokens.get("expires_in")
        response_dict["scope"] = tokens.get("scope")

        return response_dict



