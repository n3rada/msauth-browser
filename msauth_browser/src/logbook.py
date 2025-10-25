import sys

# Third party library imports
from loguru import logger

# Define the log format
LOG_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<level>{level: <8}</level> | "
    "<level>{message}</level>"
)


def setup_logging(log_level: str = "INFO"):
    log_level = log_level.upper()

    if not logger.level(log_level, None):
        logger.error(f"Invalid log level: {log_level}")
        logger.warning("Using default log level: INFO")
        log_level = "INFO"

    # Remove all Loguru handlers to avoid duplicates
    logger.remove()

    # enqueue=False for synchronous output to maintain ordering
    logger.add(
        sys.stderr,
        enqueue=False,
        backtrace=True,
        level=log_level,
        format=LOG_FORMAT,
        colorize=True,
    )

