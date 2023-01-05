import os
import uuid

import jwt
from sqlalchemy import or_, and_
from sqlalchemy.orm import Session
from business.models.schema_clients import ClientCreateSchema, ClientSchema, ClientJWTSchema
from business.models.schema_groups_role import GroupsUserBase, GroupsRoleBase
from business.models.schema_roles import RoleBaseSchema
from business.models.schemas_groups import GroupBaseSchema
from business.models.schemas_groups_users import GroupUserRoleSchema
from business.providers.base import UserNotVerifiedError
from core import log
from core.db_models import models
from datetime import date, datetime, timedelta
from fastapi import HTTPException
from pydantic.schema import Enum
import random
import string
from redis_service.redis_service import RedisClient
client = RedisClient()

JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')


class SortByEnum(str, Enum):
    DESE = 'desc'
    ASC = 'asc'


class SortColumnEnum(str, Enum):
    CREATED_AT = 'created_at'
    USER_NAME = 'user_name'


def get_groups(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Group).offset(skip).limit(limit).all()


def get_group_by_name(db: Session, name: str):
    return db.query(models.Group).filter(models.Group.name == name).first()


def get_group_by_id(db: Session, id: str):
    return db.query(models.Group).filter(models.Group.id == id).first()


def get_groups_name_of_user_by_id(db: Session, user_id: str):
    # Get all groups assigned to a user
    query = db.query(models.GroupsUser.users, models.Group.name)
    groups = query \
        .join(models.Group) \
        .filter(models.GroupsUser.users == user_id) \
        .all()
    if groups is None:
        return None
    return groups


def get_roles_name_of_group(db: Session, groups: list):
    # Get roles name from group_roles
    query = db.query(models.Role.name)
    roles = query.select_from(models.GroupsRole) \
        .join(models.Group, models.Role) \
        .filter(models.Group.name.in_([gr for gr in groups])) \
        .all()
    if roles is None:
        return None
    return roles


def create_group(db: Session, group_create: GroupBaseSchema):
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


def create_role(db: Session, role_create: RoleBaseSchema):
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


def get_user_login(db: Session, email: str):
    user_login = db.query(models.User).filter(models.User.email == email).first()
    if user_login is None:
        return None
    if user_login.verified is False:
        raise UserNotVerifiedError("user is not verified!")
    db.execute(f"SET zekoder.id = '{user_login.id}'")
    if user_login:
        update = db.query(models.User).get(user_login.id)
        update.last_login_at = datetime.now()
        db.commit()
        db.refresh(update)
    return user_login


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def user_verified(db: Session, verified: bool, user_id: int):
    db.execute(f"SET zekoder.id = '{user_id}'")
    update = db.query(models.User).get(user_id)
    if update:
        update.verified = verified
        db.commit()
    db.refresh(update)
    return update


def reset_user_password(db: Session, password, user_id: int):
    db.execute(f"SET zekoder.id = '{user_id}'")
    update = db.query(models.User).get(user_id)
    if update:
        update.password = password
        db.commit()
    db.refresh(update)
    return update


def get_users(db: Session, search, user_status: bool, date_of_creation: date, date_of_last_login: date, sort_by,
              sort_column, skip: int = 0, limit: int = 20):
    query = db.query(models.User)
    if search:
        query = query.filter(or_(
            models.User.email.ilike(f"%{search}%"),
            models.User.first_name.ilike(f"%{search}%"),
            models.User.last_name.ilike(f"%{search}%"),
            models.User.user_name.ilike(f"%{search}%"),
        ))
    if user_status is not None:
        query = query.filter(models.User.user_status == user_status)
    if date_of_last_login:
        query = query.filter(and_(models.User.last_login_at > date_of_last_login,
                                  models.User.last_login_at < date_of_last_login + timedelta(days=1)))
    if date_of_creation:
        query = query.filter(and_(models.User.created_on > date_of_creation,
                                  models.User.created_on < date_of_creation + timedelta(days=1)))

    if sort_column == SortColumnEnum.USER_NAME:
        if sort_by == SortByEnum.ASC:
            query = query.order_by(models.User.user_name.asc())
        else:
            query = query.order_by(models.User.user_name.desc())
    else:
        if sort_by == SortByEnum.ASC:
            query = query.order_by(models.User.created_on.asc())
        else:
            query = query.order_by(models.User.created_on.desc())
    count = query.count()
    query = query.offset(skip).limit(limit)

    return query.all(), count


def update_user_group(db: Session, user_id: str, groups: list):
    query_groupUser = db.query(models.GroupsUser)
    query_group = db.query(models.Group)
    # First delete the assigned group of the user,
    query_groupUser \
        .filter(models.GroupsUser.users == user_id) \
        .delete()
    # then assign requested group/s to the user
    for obj in \
            query_group \
                    .filter(models.Group.name.in_(groups)):
        group = models.GroupsUser(groups=obj.id, users=user_id)
        db.add(group)
        db.commit()
        db.refresh(group)
        yield group


def group_name_exists(db: Session, groups: list):
    query_group = db.query(models.Group)
    # check the request group names is exists in the Group table, if not throw 404
    # also with this method, if request repeated group name, then it will not allow to use
    # repeated group name, so the update_user_group func. will not run in routes/assignment.py
    result = query_group \
        .filter(models.Group.name.in_(groups)) \
        .count()
    if len(groups) == result:
        return True
    else:
        raise HTTPException(status_code=404, detail="Group name not exist or repeated ! Check again..")


def get_groups_of_user_by_id(db: Session, user_id: str):
    # Get all groups assigned to a user
    query = db.query(models.GroupsUser.users, models.Group.name)

    return query \
        .join(models.Group) \
        .filter(models.GroupsUser.users == user_id) \
        .all()


def assign_user_to_group(db: Session, group_id: str, user_id: uuid.UUID):
    query_user = db.query(models.User)
    query_group_user = db.query(models.GroupsUser)

    user_id_exist_in_users_table = query_user.filter(models.User.id == user_id).first()
    if user_id_exist_in_users_table:
        if query_group_user \
                .filter(and_(models.GroupsUser.users == user_id_exist_in_users_table.id,
                             models.GroupsUser.groups == group_id)).first():
            raise HTTPException(status_code=403, detail="Available users are already in the group")
        else:
            group_user = models.GroupsUser(groups=group_id, users=user_id)
            db.add(group_user)
            db.commit()
            db.refresh(group_user)
            yield group_user
    else:
        raise HTTPException(status_code=404, detail="User not exist")


def deassign_user_from_group(db: Session, group_id: str, user_id: uuid.UUID):
    query_user = db.query(models.User)
    query_group_user = db.query(models.GroupsUser)

    group_exist = get_group_by_id(db, group_id)
    if not group_exist:
        raise HTTPException(status_code=404, detail="Group not found")

    user_id_exist_in_users_table = query_user.filter(models.User.id == user_id).first()
    if user_id_exist_in_users_table:
        user_exist_in_group = query_group_user \
            .filter(and_(models.GroupsUser.users == user_id_exist_in_users_table.id,
                         models.GroupsUser.groups == group_id)).first()
        if user_exist_in_group:
            db.delete(user_exist_in_group)
            db.commit()
            yield user_exist_in_group
        else:
            raise HTTPException(status_code=404, detail="User not exist")
    else:
        raise HTTPException(status_code=404, detail="User not exist")


def assign_multi_users_or_roles_to_group(db: Session, group_id: str, group_user_role: GroupUserRoleSchema):
    try:
        # check if request data has 'users' key, assign users to the group
        if group_user_role.users:
            query_user = db.query(models.User)
            query_groupUser = db.query(models.GroupsUser)
            # Check ! do we have a record in our users table, for requested user uuid's ?
            users_in_usersTable = [obj.id for obj in
                                   query_user
                                   .filter(models.User.id.in_(group_user_role.users))]
            # check users in the group
            users_in_groupUserTable = [obj.users for obj in
                                       query_groupUser
                                       .filter(and_(models.GroupsUser.users.in_(users_in_usersTable)),
                                               (models.GroupsUser.groups == group_id))]
            # If users exist in UserTable and not in the groupTable, so assign them to the group
            assign_users_to_group = [obj for obj in users_in_usersTable if obj not in set(users_in_groupUserTable)]

            if assign_users_to_group:  # These users not in the group, so you can assign them to this group
                db.bulk_insert_mappings(
                    models.GroupsUser,
                    [dict(groups=group_id, users=users, ) for users in assign_users_to_group],
                )
                db.commit()
                yield {"users": assign_users_to_group}
            else:
                raise HTTPException(status_code=403, detail="Available users are already in the group")

        # check if request data has 'roles' key, assign users to the group
        if group_user_role.roles:
            query_role = db.query(models.Role)
            query_groupsRole = db.query(models.GroupsRole)

            # Check ! do we have a record in our roles table, for requested roles uuid's ?
            roles_in_rolesTable = [obj.id for obj in
                                   query_role
                                   .filter(models.Role.id.in_(group_user_role.roles))]
            # check roles in the group
            roles_in_groupRolesTable = [obj.roles for obj in
                                        query_groupsRole
                                        .filter(and_(models.GroupsRole.roles.in_(roles_in_rolesTable)),
                                                (models.GroupsRole.groups == group_id))]
            # If roles exist in RolesTable and not in the groupRolesTable, so assign roles to the group
            assign_roles_to_group = [obj for obj in roles_in_rolesTable if obj not in set(roles_in_groupRolesTable)]

            if assign_roles_to_group:
                db.bulk_insert_mappings(
                    models.GroupsRole,
                    [dict(groups=group_id, roles=roles, ) for roles in assign_roles_to_group],
                )
                db.commit()
                yield {"roles": assign_roles_to_group}
            else:
                raise HTTPException(status_code=403, detail="Available roles are already in the group")
    except ValueError as e:
        log.error(e)
        return {"detail": "invalid uuid"}


def remove_multi_users_or_roles_from_group(db: Session, group_id: str, group_user_role: GroupUserRoleSchema):
    try:
        query_groupUser = db.query(models.GroupsUser)
        query_groupsRole = db.query(models.GroupsRole)

        if group_user_role.users:
            # check if available roles in GroupsRole table to delete
            available_users_to_delete = [obj.id for obj in
                                         query_groupUser
                                         .filter(and_(
                                             models.GroupsUser.users.in_(group_user_role.users),
                                             models.GroupsUser.groups == group_id))
                                         ]
            # available users are ready for to delete...
            if available_users_to_delete:
                query_groupUser \
                    .filter(
                    models.GroupsUser.id.in_(available_users_to_delete)) \
                    .delete()
                db.commit()
                return available_users_to_delete
            else:
                raise HTTPException(status_code=404, detail="Users not exist")

        if group_user_role.roles:
            # check if available roles in GroupsRole table to delete
            available_roles_to_delete = [obj.id for obj in
                                         query_groupsRole
                                         .filter(and_(
                                             models.GroupsRole.roles.in_(group_user_role.roles),
                                             models.GroupsRole.groups == group_id))
                                         ]
            # available roles are ready for to delete..
            if available_roles_to_delete:
                query_groupsRole \
                    .filter(
                    models.GroupsRole.id.in_(available_roles_to_delete)) \
                    .delete()
                db.commit()
                return available_roles_to_delete
            else:
                raise HTTPException(status_code=404, detail="Roles not exist")
    except ValueError as e:
        log.error(e)
        return {"detail": "invalid uuid"}


def create_groups_role(db: Session, groups_role_create: GroupsRoleBase):
    groups_role = models.GroupsRole(roles=groups_role_create.roles, groups=groups_role_create.groups)
    db.add(groups_role)
    db.commit()
    db.refresh(groups_role)
    return groups_role


def is_groups_role_not_exists(db: Session, groups_role_create: GroupsRoleBase):
    return not (
        groups_role := db.query(models.GroupsRole)
        .filter(
            models.GroupsRole.roles == groups_role_create.roles,
            models.GroupsRole.groups == groups_role_create.groups,
        )
        .first()
    )


def create_groups_user(db: Session, groups_user_create: GroupsUserBase):
    groups_user = models.GroupsUser(users=groups_user_create.users, groups=groups_user_create.groups)
    db.add(groups_user)
    db.commit()
    db.refresh(groups_user)
    return groups_user


def is_groups_user_not_exists(db: Session, groups_user_create: GroupsUserBase):
    return not (
        groups_user := db.query(models.GroupsRole)
        .filter(
            models.GroupsRole.roles == groups_user_create.groups,
            models.GroupsRole.groups == groups_user_create.users,
        )
        .first()
    )


def generate_client_secret():
    return ''.join(
        random.choices(
            string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation,
            k=32
        )
    )


def create_new_client(db: Session, client: ClientCreateSchema):
    if client:
        # Do database operations
        pass
    else:
        raise HTTPException(status_code=403, detail="Client already exist!")
    # if create is success return these value
    # these values are new clients, client_id and client_secret info's generated from system
    client_response = ClientCreateSchema
    client_response.client_id = uuid.uuid4()
    client_response.client_secret = generate_client_secret()
    return {"client_id": client_response.client_id, "client_secret": client_response.client_secret} # for only to test NOW !!


def create_client_auth(db: Session, client_auth: ClientSchema):
    """
    TODO: Operational transactions will be completed when the DB is ready
    TODO: JWT, Redis is DONE
    """
    CLIENT_TOKEN_EXPIRY_MINUTES = os.environ.get('CLIENT_TOKEN_EXPIRY_MINUTES')
    if client_auth:
        # do database operations
        pass

    # These data will come from DB !!!
    payload = ClientJWTSchema
    payload.expr = (datetime.utcnow() + timedelta(minutes=int(CLIENT_TOKEN_EXPIRY_MINUTES)))  # This is not for redis only for payload
    payload.expr = payload.expr.timestamp()
    payload.client_id = client_auth.client_id
    payload.name = "name from db"
    payload.roles = ["roles1", "roles2"]
    payload.email = "test@test.com"
    payload.iss = "zeauth.[solution domain]"

    payload = dict(
        client_id=str(payload.client_id),
        expr=int(payload.expr),
        iss=payload.iss,
        name=payload.name,
        email=payload.email,
        roles=payload.roles
    )
    # JWT operations
    client_token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")
    payload['client_token'] = client_token
    # Write payload to Redis with expiry 30 Minutes
    client.set_client_token(payload)
    return payload  # for only to test NOW !!


def remove_client(db: Session, client_id: str):
    """
    TODO: Operational transactions will be completed when the DB is ready
    TODO: Write funct to get clients id
    """
    return client_id    # for only to test NOW !!


