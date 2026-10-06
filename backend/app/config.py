import os
import warnings

from dotenv import load_dotenv

from app.utils.logger import get_logger

load_dotenv()

logger = get_logger("config")

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DB_PATH = os.path.join(_BACKEND_DIR, "cybershield.db").replace("\\", "/")
_SQLITE_FALLBACK = f"sqlite:///{_DB_PATH}"


def _resolve_database_url() -> str:
    database_url = os.getenv("DATABASE_URL", _SQLITE_FALLBACK).strip()

    if not database_url.startswith("postgres"):
        return database_url

    try:
        import psycopg2  # noqa: F401
    except ModuleNotFoundError:
        logger.warning(
            "DATABASE_URL points to PostgreSQL but psycopg2 is not installed. "
            "Falling back to SQLite at %s",
            _SQLITE_FALLBACK,
        )
        return _SQLITE_FALLBACK

    # Verify the configured PostgreSQL server is actually reachable before
    # committing the process to it. If it is not, fall back to SQLite so the
    # application always boots and the recorded data stays coherent.
    if not os.getenv("CYBERSHIELD_FORCE_POSTGRES") == "1":
        try:
            import sqlalchemy as sa

            engine = sa.create_engine(database_url, connect_args={"connect_timeout": 2}, pool_pre_ping=True)
            with engine.connect():
                pass
            engine.dispose()
            logger.info("PostgreSQL reachable — using %s", database_url)
            return database_url
        except Exception as exc:  # noqa: BLE001 - read-only fallback decision
            warnings.warn(
                "DATABASE_URL points to PostgreSQL but the server is not reachable "
                f"({exc}). Falling back to SQLite at {_SQLITE_FALLBACK}.",
                RuntimeWarning,
                stacklevel=2,
            )
            logger.warning(
                "PostgreSQL unreachable (%s). Falling back to SQLite at %s",
                exc,
                _SQLITE_FALLBACK,
            )
            return _SQLITE_FALLBACK

    return database_url


DATABASE_URL = _resolve_database_url()