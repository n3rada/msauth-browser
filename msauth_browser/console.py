# Built-in imports
import argparse
import json
from pathlib import Path
import sys

# Third party library imports
from loguru import logger

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
        choices=["roadtools"],
        default=None,
        help="Persist tokens using the specified backend.",
    )

    parser.add_argument(
        "--show-scopes",
        action="store_true",
        default=False,
        help="Display the configured scopes for the selected app and exit.",
    )

    return parser


def run() -> int:
    """Main CLI entry point used by the package script."""

    parser = get_parser()
    args = parser.parse_args()

    if not args.config:
        parser.print_help()
        return 1

    setup_logging()

    config_name = args.config.lower()

    try:
        config = get_config(config_name)
    except KeyError as exc:
        parser.error(str(exc))

    if args.show_scopes:
        logger.info("🔭 Scopes for the selected configuration:")
        for scope in config.default_scopes:
            print(scope)
        return 0

    logger.info(f"🔧 Using configuration '{config_name}' ({config.name})")
    auth_instance = PlaywrightAuth(config)

    tokens = auth_instance.get_tokens(
        prt_cookie=args.prt_cookie, headless=args.headless
    )

    if not tokens:
        return 1

    print(json.dumps(tokens, indent=4))

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
