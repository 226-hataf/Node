from business.models.schemas_groups import GroupBase
from sqlalchemy.orm import Session
from core.db_models import models


def get_groups(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Group).offset(skip).limit(limit).all()


def get_group_by_name(db: Session, name: str):
    return db.query(models.Group).filter(models.Group.name == name).first()


def get_group_by_id(db: Session, id: str):
    return db.query(models.Group).filter(models.Group.id == id).first()


def create_group(db: Session, group_create: GroupBase):
    group = models.Group(name=group_create.name, description=group_create.description)
    db.add(group)
    db.commit()
    db.refresh(group)
    return group


def update_group(db: Session, id: str, name: str, description: str):
    group = get_group_by_id(db=db, id=id)
    group.name = name
    group.description = description
    db.commit()
    db.refresh(group)
    return group


def remove_group(db: Session, name: str):
    group = get_group_by_name(db=db, name=name)
    db.delete(group)
    db.commit()


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


def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()


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
