from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "sqlite:///./authlab.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}  # needed for SQLite + FastAPI
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False
)

Base = declarative_base()
def get_db():
    """
    FastAPI dependency:
    yields a DB session per request, then closes it.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
