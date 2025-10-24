# Built-in imports
import argparse
import json
from pathlib import Path
import sys

# Third party library imports
from loguru import logger
import pyperclip

# Local library imports
from msauth_browser.src.auth import PlaywrightAuth
from msauth_browser.src.tokens import TokenManager
from msauth_browser.src.config import get_config, list_configs
from msauth_browser.src.logbook import setup_logging


def get_parser() -> argparse.ArgumentParser:
    available_configs = list_configs()

    parser = argparse.ArgumentParser(
        prog="msauth-browser",
        add_help=True,
        description="Interactive Microsoft Authentication - Extract OAuth tokens using browser automation",
        allow_abbrev=True,
        exit_on_error=True,
    )

    parser.add_argument(
        "config",
        nargs="?",
        choices=available_configs if available_configs else None,
        default="graph",
        help="Predefined configuration to load.",
    )

    parser.add_argument(
        "--prt-cookie",
        type=str,
        default=None,
        help="X-Ms-RefreshTokenCredential PRT cookie for SSO",
    )

    parser.add_argument(
        "--headless",
        action="store_true",
        default=False,
        help="Run the browser in headless mode (default: False)",
    )

    parser.add_argument(
        "--save",
        nargs="?",
        choices=["roadtools"],
        const="roadtools",
        default=None,
        help="Persist tokens using the specified backend (default: roadtools if no value specified).",
    )

    return parser


def main() -> int:
    parser = get_parser()
    args = parser.parse_args()
    
    setup_logging()

    config_name = args.config.lower()

    try:
        config = get_config(config_name)
    except KeyError as exc:
        parser.error(str(exc))
        return 1
    
    logger.info(f"🔧 Using configuration '{config_name}' ({config.name})")
    auth_instance = PlaywrightAuth(config)

    tokens = auth_instance.get_tokens(
        prt_cookie=args.prt_cookie, headless=args.headless
    )

    if not tokens:
        return 1

    logger.success("✅ Tokens acquired successfully")
    tokens_printable = json.dumps(tokens, indent=4)

    # Save them in the clipboard for convenience
    try:
        pyperclip.copy(tokens_printable)
        logger.success("📋 Tokens copied to clipboard")
    except pyperclip.PyperclipException:
        logger.warning("⚠️ Failed to copy tokens to clipboard")

    print()
    print(tokens_printable)
    print()

    token_manager = TokenManager(
        access_token=tokens["access_token"],
        refresh_token=tokens.get("refresh_token") or "",
    )

    scope_value = token_manager.scope or "(no scp claim present)"
    logger.info(f"🔭 Access token scopes: {scope_value}")

    if args.save:
        logger.info("💾 Saving tokens")
        if args.save == "roadtools":

            Path(".roadtools_auth").write_text(
                json.dumps(
                    {
                        "accessToken": tokens["access_token"],
                        "refreshToken": tokens["refresh_token"],
                        "expiresIn": tokens["expires_in"],
                    },
                    indent=4,
                ),
                encoding="utf-8",
            )
            logger.success("✅ Tokens saved to .roadtools_auth")
        else:
            logger.warning(
                f"💾 Save option '{args.save}' is not implemented; skipping persistence."
            )

    return 0






