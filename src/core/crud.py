from sqlalchemy.orm import Session

from core.db_models import models


def create_user(db: Session, user):
    db_user = models.User(**user)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def get_user_login(db: Session, email: str, password: str):
    return db.query(models.User).filter(models.User.email == email, models.User.password == password).first()


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def create_role(db: Session, role):
    db_role = models.Role(**role)
    db.add(db_role)
    db.commit()
    db.refresh(db_role)
    return db_role


def create_user_role(db: Session, role):
    db_role = models.UserRole(**role)
    db.add(db_role)
    db.commit()
    db.refresh(db_role)
    return db_role
