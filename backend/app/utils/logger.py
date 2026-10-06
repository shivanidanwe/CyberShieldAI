import logging
import os
from logging.handlers import RotatingFileHandler

from dotenv import load_dotenv

load_dotenv()

_LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "logs")
_LOG_FILE = os.environ.get("CYBERSHIELD_LOG_FILE") or os.path.join(_LOG_DIR, "cybershield.log")

_FORMAT = logging.Formatter(
    "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def _build_logger(name: str = "cybershield") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG if os.environ.get("CYBERSHIELD_DEBUG") == "1" else logging.INFO)

    console = logging.StreamHandler()
    console.setFormatter(_FORMAT)
    logger.addHandler(console)

    try:
        os.makedirs(_LOG_DIR, exist_ok=True)
        file_handler = RotatingFileHandler(
            _LOG_FILE,
            maxBytes=2 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setFormatter(_FORMAT)
        logger.addHandler(file_handler)
    except Exception:
        # File logging is best-effort; the console handler keeps the app usable.
        logger.warning("Could not set up file logging at %s, using console only.", _LOG_FILE)

    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a module-level child logger of the shared 'cybershield' logger."""
    return _build_logger(name if name else "cybershield")