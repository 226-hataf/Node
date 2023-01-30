import os
from api import app
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from business.models.dependencies import get_current_user
from fastapi import Security

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
    # db.execute("SET zekoder.id = '09c645f2-8353-11ed-80ca-571e9bc0bf17'")
    try:
        yield db
    finally:
        db.close()


async def mock_user_roles():
    return Security(get_current_user)

app.dependency_overrides[get_current_user] = mock_user_roles


