from sqlalchemy import or_
from sqlalchemy.orm import Session
from business.models.schema_roles import RoleBase
from business.models.schemas_groups import GroupBase
from core.db_models import models
from fastapi import HTTPException


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


def update_user_group(db: Session, user_id: str, groups: list):
    # First delete the assigned group of the user,
    db.query(models.GroupsUser) \
        .filter(models.GroupsUser.users_id == user_id) \
        .delete()
    # then assign requested group/s to the user
    for obj in db.query(models.Group) \
            .filter(models.Group.name.in_(groups)):
        group = models.GroupsUser(groups_id=obj.id, users_id=user_id)
        db.add(group)
        db.commit()
        db.refresh(group)
        yield group


def group_name_exists(db: Session, groups: list):
    # check the request group names is exists in the Group table, if not throw 404
    # also with this method, if request repeated group name, then it will not allow to use
    # repeated group name, so the update_user_group func. will not run in routes/assignment.py
    res = db.query(models.Group).filter(models.Group.name.in_(groups)).count()
    print(res)
    if len(groups) == res:
        return True
    else:
        raise HTTPException(status_code=404, detail="Group name not exist or repeated ! Check again..")


def get_groups_of_user_by_id(db: Session, user_id: str):
    # Get all groups assigned to the user
    return db.query(models.GroupsUser.users_id, models.Group.name) \
        .join(models.Group) \
        .filter(models.GroupsUser.users_id == user_id).all()
