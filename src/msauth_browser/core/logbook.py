# msauth_browser/core/logbook.py

# Built-in imports
import sys

# Third party library imports
from loguru import logger


def _format_message(record):
    """Custom formatter with compact symbols and colors."""
    level_name = record["level"].name

    # Modern color palette (hex colors for better terminal support)
    trace_brown = "#8b7355"
    debug_blue = "#6c9bd1"
    info_white = "#ecf0f1"
    success_green = "#52c88a"
    warning_orange = "#f39c12"
    error_red = "#e74c3c"
    critical_magenta = "#c71585"
    time_gray = "#a5a5a5"

    # Map levels to symbols and colors
    symbols = {
        "TRACE": (f"<fg {trace_brown}>[*]</fg {trace_brown}>", trace_brown),
        "DEBUG": (f"<fg {debug_blue}>[•]</fg {debug_blue}>", debug_blue),
        "INFO": (f"<fg {info_white}>[i]</fg {info_white}>", info_white),
        "SUCCESS": (f"<fg {success_green}>[✓]</fg {success_green}>", success_green),
        "WARNING": (f"<fg {warning_orange}>[!]</fg {warning_orange}>", warning_orange),
        "ERROR": (f"<fg {error_red}>[✗]</fg {error_red}>", error_red),
        "CRITICAL": (
            f"<fg {critical_magenta}><bold>[⚠]</bold></fg {critical_magenta}>",
            critical_magenta,
        ),
    }

    symbol, color = symbols.get(level_name, ("[?]", "white"))

    return (
        f"<fg {time_gray}>{{time:YYYY-MM-DD HH:mm:ss.SSS!UTC}} (UTC)</fg {time_gray}> "
        f"{symbol} "
        f"<fg {color}>{{message}}</fg {color}>"
        "\n{exception}"
    )


def setup_logging(level: str = "INFO"):
    """
    Setup logging with compact, visually intuitive output.

    Args:
        level: Log level (TRACE, DEBUG, INFO, SUCCESS, WARNING, ERROR, CRITICAL)
    """
    level = level.upper()

    # Validate log level
    valid_levels = ["TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"]
    if level not in valid_levels:
        level = "INFO"

    # Remove all Loguru handlers to avoid duplicates
    logger.remove()

    # Add custom formatted handler
    # enqueue=False for synchronous output to maintain ordering when using print()
    logger.add(
        sys.stderr,
        enqueue=False,
        backtrace=True,
        diagnose=True,
        level=level,
        format=_format_message,
        colorize=True,
    )

    logger.trace(f"Logger initialized at level {level}")
