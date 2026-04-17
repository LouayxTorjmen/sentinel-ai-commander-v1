from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from contextlib import contextmanager
from typing import Generator
from urllib.parse import quote_plus
import structlog

from ai_agents.config import get_settings
from ai_agents.database.models import Base

logger = structlog.get_logger()

def get_engine():
    s = get_settings()
    # URL-encode password to handle special chars like @, #, %, etc.
    encoded_password = quote_plus(s.postgres_password)
    url = (
        f"postgresql+psycopg2://{s.postgres_user}:{encoded_password}"
        f"@{s.postgres_host}:{s.postgres_port}/{s.postgres_db}"
    )
    return create_engine(url, pool_pre_ping=True, pool_recycle=3600, echo=False)

def init_db():
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    logger.info("database.initialized")
    return engine

_engine = None
_SessionLocal = None

def get_session_factory():
    global _engine, _SessionLocal
    if _SessionLocal is None:
        _engine = init_db()
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
    return _SessionLocal

@contextmanager
def get_db() -> Generator[Session, None, None]:
    SessionLocal = get_session_factory()
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
