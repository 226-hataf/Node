import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from config.db import get_db
from api import app


class Settings:
    POSTGRES_USER: str = os.environ.get("POSTGRES_USER")
    POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD")
    POSTGRES_SERVER: str = os.environ.get("POSTGRES_SERVER")
    POSTGRES_PORT: str = os.environ.get("POSTGRES_PORT", 5432)
    POSTGRES_DB: str = os.environ.get("POSTGRES_TEST_DB")   # For unit testing
    DATABASE_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_SERVER}:{POSTGRES_PORT}/{POSTGRES_DB}"


SQLALCHEMY_DATABASE_URL = Settings().DATABASE_URL
engine = create_engine(SQLALCHEMY_DATABASE_URL, echo=True)

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def override_get_db():
    db = TestingSessionLocal()
    db.execute("SET zekoder.id = '2ac1f740-9750-11ed-8bda-db62bac905e2'")
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db  # override main DB to Test DB
