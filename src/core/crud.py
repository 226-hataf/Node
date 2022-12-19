import datetime
import logging
from sqlalchemy import or_
from sqlalchemy.orm import Session
from business.models.schema_roles import RoleBase
from core.db_models import models


def get_role_by_id(db: Session, role_id: str):
    return db.query(models.Role).filter(models.Role.id == role_id).first()


def get_roles(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Role).offset(skip).limit(limit).all()


def get_role_by_name(db: Session, name: str):
    return db.query(models.Role).filter(models.Role.name == name).first()


def update_role(db: Session, id: str, name: str, description: str):
    role = get_role_by_id(db, id)
    role.name = name
    role.description = description
    db.commit()
    db.refresh(role)
    return role


def remove_role(db: Session, name: str):
    role = get_role_by_name(db=db, name=name)
    db.delete(role)
    db.commit()


def create_role(db: Session, role_create: RoleBase):
    print(role_create)
    role = models.Role(name=role_create.name, description=role_create.description)
    db.add(role)
    db.commit()
    db.refresh(role)
    return role


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

