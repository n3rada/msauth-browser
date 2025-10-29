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
from msauth_browser.src.config import AppConfig


class PlaywrightAuth:
    """
    Microsoft authentication handler using Playwright for interactive browser login.

    This class provides a flexible way to authenticate with Microsoft services
    using the OAuth 2.0 authorization code flow with PKCE.
    """

    def __init__(self, config: AppConfig, tenant: str = "common") -> None:
        """
        Initialize the PlaywrightAuth instance.
        """
        self.client_id = config.client_id
        self.redirect_uri = config.redirect_uri
        self.scopes = config.default_scopes or [
            "openid",
            "https://graph.microsoft.com/.default",
            "offline_access",
        ]
        self.tenant = tenant

    def get_tokens(
        self, prt_cookie: Optional[str] = None, headless: bool = False
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
        }
        code_verifier, code_challenge = pkce.generate_pkce_pair()
        state = secrets.token_urlsafe(32)

        # Prepare scope string
        scope_string = " ".join(self.scopes)
        if "openid" not in scope_string:
            scope_string = f"openid {scope_string}"

        params = {
            "client_id": self.client_id,
            "scope": scope_string,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
        }

        auth_url = f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/authorize?{urlencode(params)}"

        logger.info("🔐 Starting authentication process using Playwright")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless, args=["--no-sandbox"])
            context = browser.new_context()

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
            logger.info(f"🔗 Opening auth URL: {auth_url}")

            page.goto(auth_url)
            page.wait_for_load_state("load")

            logger.info("🔍 Waiting for authentication to complete")
            logger.info(f"Searching for this pattern in URL: {self.redirect_uri}"
            redirect_uri_pattern = re.compile(rf"^{re.escape(self.redirect_uri)}")
            try:
                page.wait_for_url(
                    redirect_uri_pattern,
                    timeout=2 * 60 * 1000,
                    wait_until="load",
                )
            except TimeoutError:
                logger.error("⏱️ Timeout waiting for auth redirect.")
                return None
            except Exception as exc:
                logger.error(f"❌ Error during auth redirect: {exc}")
                return None
            else:
                final_url = page.url
                logger.success("🔄 Redirection received.")
            finally:
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
                    "scope": scope_string,
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

        return response_dict

