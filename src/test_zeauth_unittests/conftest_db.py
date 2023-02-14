import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from config.db import get_db
from api import app


class Settings:
    DB_USERNAME: str = os.environ.get("DB_USERNAME")
    DB_PASSWORD = os.environ.get("DB_PASSWORD")
    DB_HOST: str = os.environ.get("DB_HOST")
    DB_PORT: str = os.environ.get("DB_PORT", 5432)
    DB_NAME: str = os.environ.get("DB_NAME_TEST")
    DATABASE_URL = f"postgresql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"


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
