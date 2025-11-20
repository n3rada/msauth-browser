# Built-in imports
from datetime import datetime, timezone
import json
import threading
from pathlib import Path
import time

# External library imports
import httpx
from loguru import logger


class Token:
    def __init__(
        self,
        access_token: str,
        refresh_token: str = "",
        expires_in: int = 0,
        scope: str = "",
        path: str = "",
    ) -> None:
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._expires_on = datetime.now(timezone.utc).timestamp() + expires_in
        self._scope = scope
        self._path = path
        self._exit_event = threading.Event()

        human_date = datetime.fromtimestamp(self._expires_on).strftime(
            "%A %d %b %Y, %H:%M:%S"
        )
        logger.info(f"🔐 Expires at {human_date}.")

    @property
    def scope(self) -> str:
        return self._scope

    @property
    def access_token(self) -> str:
        return self._access_token

    @property
    def refresh_token(self) -> str:
        return self._refresh_token

    @property
    def path(self) -> str:
        return self._path

    @property
    def expires_on(self) -> float:
        return self._expires_on

    def save(self) -> None:
        """Save tokens to a file."""

        Path(self._path).write_text(
            json.dumps(
                {
                    "accessToken": self._access_token,
                    "refreshToken": self._refresh_token,
                    "expiresIn": self.expires_in(),
                },
                indent=4,
            ),
            encoding="utf-8",
        )
        logger.success(f"✅ Tokens saved to {self._path}")

    def expires_in(self) -> int:
        return max(0, int(self._expires_on - datetime.now(timezone.utc).timestamp()))

    def refresh_access_token(self, refresh_token: str):
        if not refresh_token:
            logger.error("⛔ No refresh token available to refresh access token.")
            return None, None

        response = httpx.post(
            url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
            data={
                "client_id": "de8bc8b5-d9f9-48b1-a8ad-b748da725064",
                "scope": "openid https://graph.microsoft.com/.default offline_access",
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
            headers={"Origin": "https://developer.microsoft.com"},
            verify=False,
        )

        if response.status_code != 200:
            logger.error(f"❌ Failed to refresh token: {response.text}.")
            return

        new_tokens = response.json()

        self._access_token = new_tokens.get("access_token")
        self._refresh_token = new_tokens.get("refresh_token")
        self._expires_on = datetime.now(timezone.utc).timestamp() + new_tokens.get(
            "expires_in", 0
        )

        logger.success("🔁 Access token refreshed successfully.")
        self.save()

    def start_auto_refresh(self) -> None:
        def refresher():
            logger.info("🔄 Auto token refresher thread started (CTRL+C to stop).")
            while True:
                sleep_duration = (
                    self.expires_on
                    - datetime.now(timezone.utc).timestamp()
                    - 300  # 5 minutes before expiration
                )

                if sleep_duration > 0:
                    logger.debug(f"⏳ Sleeping {sleep_duration:.1f}s until refresh.")
                    time.sleep(sleep_duration)

                logger.debug("🛠️ Time to refresh token.")
                try:
                    self.refresh_access_token(self._refresh_token)
                except Exception as exc:
                    logger.error(f"❌ Failed to refresh token: {exc}")

        thread = threading.Thread(target=refresher, daemon=True, name="Token Refresher")
        thread.start()
