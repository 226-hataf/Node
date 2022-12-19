import datetime
from sqlalchemy import or_
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


def reset_user_password(db: Session, password, user_id: int):
    update = db.query(models.User).get(user_id)
    if update:
        update.password = password
        db.commit()
    db.refresh(update)
    return update


def get_users(db: Session, search, skip: int = 0, limit: int = 20):
    query = db.query(models.User).filter(or_(
        models.User.email.like(f"%{search}%"),
        models.User.first_name.like(f"%{search}%"),
        models.User.last_name.like(f"%{search}%"),
        models.User.user_name.like(f"%{search}%"),
    )).offset(skip).limit(limit)
    return query.all()


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
