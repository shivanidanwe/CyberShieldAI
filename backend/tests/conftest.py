"""Shared pytest fixtures — an isolated in-memory SQLite database and test client."""

import os
import sys
from pathlib import Path

import pytest


# Point SQLAlchemy at a throwaway file DB before importing the app modules.
BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_cybershield.db")
os.environ.setdefault("AUTO_SEED", "0")


@pytest.fixture(autouse=True)
def clean_database():
    """Fresh schema for every test."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.database import Base, SessionLocal, engine
    from app import models  # noqa: F401 - ensure models are registered

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    try:
        engine.dispose()
    except Exception:
        pass


@pytest.fixture
def db_session(clean_database):
    from app.database import SessionLocal

    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client