import os
import uuid
from typing import Any
import jwt
import requests
from sqlalchemy import or_, and_
from sqlalchemy.orm import Session
from business.models.schema_clients import ClientCreateSchema, ClientSchema, ClientJWTSchema, UUIDCheckForClientIdSchema
from business.models.schema_groups_role import GroupsUserBase, GroupsRoleBase
from business.models.schema_main import UUIDCheckForUserIDSchema
from business.models.schema_roles import RoleBaseSchema
from business.models.schema_users import UsersWithIDsSchema, UserUpdateSchema
from business.models.schemas_groups import GroupBaseSchema
from business.models.schemas_groups_users import GroupUserRoleSchema, UserToGroupsSchema
from business.providers.base import UserNotVerifiedError, SignupSendNotificationError, TemplateNotificationError, \
    CreateNotificationError, ResetPasswordSendNotificationError, ResendConfirmationEmailError
from core import log
from core.db_models import models
from datetime import date, datetime, timedelta
from fastapi import HTTPException
from pydantic.schema import Enum
import secrets
import string
from redis_service.redis_service import RedisClient

client = RedisClient()

SEND_NOTIFICATION_EMAIL_URL = os.environ.get('SEND_NOTIFICATION_EMAIL_URL')
ZEAUTH_URL = os.environ.get('ZEAUTH_URL')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
AUDIENCE = 'ZeAuth'


class SortByEnum(str, Enum):
    DESE = 'desc'
    ASC = 'asc'


class SortColumnEnum(str, Enum):
    CREATED_AT = 'created_at'
    USER_NAME = 'user_name'


def get_groups_users(db: Session, group_id: str):
    query = db.query(models.GroupsUser.users, models.User.first_name)
    users = query \
        .join(models.User) \
        .filter(models.GroupsUser.groups == group_id) \
        .all()
    print(users)
    if users is None:
        return None
    return users


def get_groups(db: Session, skip: int = 0, limit: int = 100):
    query = db.query(models.Group)
    groups = query.offset(skip).limit(limit).all()
    for gr in groups:
        users_id = [users['users'] for users in get_groups_users(db, gr.id)]
        users_name = [users['first_name'] for users in get_groups_users(db, gr.id)]
        groups_list = dict(
            name=gr.name,
            description=gr.description,
            id=gr.id,
            created_on=gr.created_on,
            updated_on=gr.updated_on,
            users_id_in_group=users_id,
            users_name_in_group=users_name
        )
        yield groups_list


def get_group_by_name(db: Session, name: str):
    query = db.query(models.Group)
    groups = query.filter(models.Group.name == name).first()
    if not groups:
        return None
    users_id = [users['users'] for users in get_groups_users(db, groups.id)]
    users_name = [users['first_name'] for users in get_groups_users(db, groups.id)]
    return dict(
        name=groups.name,
        description=groups.description,
        id=groups.id,
        created_on=groups.created_on,
        updated_on=groups.updated_on,
        users_id_in_group=users_id,
        users_name_in_group=users_name
    )


def get_groups_by_name_list(db: Session, groups: list):
    groups_list_uuids = [obj.id for obj in
                         db.query(models.Group)
                         .filter(models.Group.name.in_([gr for gr in groups]))
                         .all()]
    return groups_list_uuids


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
    roles = db.query(models.Role).filter(models.Role.name == name).first()
    return roles or None


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


def get_template_by_name(template_name: str):
    zenotify_base_url = os.environ.get('ZENOTIFY_BASE_URL')
    response = requests.get(f"{zenotify_base_url}/templates/")
    json_response = response.json()
    template = [x['body'] for x in json_response["data"] if x["template_name"] == template_name]
    return template


def create_template_for_notification(body: str, template_name: str, title: str):
    zenotify_base_url = os.environ.get('ZENOTIFY_BASE_URL')
    channel = "email"
    json_data = {
        "template_name": template_name,
        "title": title,
        "body": body,
        "channel": f"{channel}"
    }
    response = requests.post(f"{zenotify_base_url}/templates/", json=json_data)

    if response.status_code == 201:
        log.debug(f'Template created success <{response.json()["id"]}>')
        return response
    else:
        raise TemplateNotificationError


def create_notification(recipients: str, template: str):
    provider = os.environ.get('NOTIFICATION_PROVIDER')
    zenotify_base_url = os.environ.get('ZENOTIFY_BASE_URL')
    target = "email"
    json_data = {
        "recipients": [recipients],
        "push_subscriptions": {},
        "provider": provider,
        "template": template,
        "params": {},
        "target": [f"{target}"],
        "status": "",
        "last_error": ""
    }
    response = requests.post(f"{zenotify_base_url}/notifications/", json=json_data)
    if response.status_code == 201:
        log.debug(f'Notification created success <{response.json()["id"]}>')
        return response
    else:
        raise CreateNotificationError


def send_notification_email(db: Session, email: str, status: str = None, notificationid: str = None):
    email_exist = get_user_by_email(db, email)
    if email_exist:
        headers = {
            'Content-Type': 'application/json',
        }
        if status == 'signup_with_activation_email':
            json_data = {"notificationId": notificationid}
            response = requests.post(f"{SEND_NOTIFICATION_EMAIL_URL}/send/email", json=json_data, headers=headers)
            if response.status_code == 200:
                log.debug(f'Notification email send to <{email_exist.email}>')
            else:
                raise SignupSendNotificationError

        if status == 'reset_password':
            json_data = {"notificationId": notificationid}
            response = requests.post(f"{SEND_NOTIFICATION_EMAIL_URL}/send/email", json=json_data, headers=headers)
            if response.status_code == 200:
                log.debug(f'Notification email send to <{email_exist.email}>')
            else:
                raise ResetPasswordSendNotificationError

        if status == 'resend_confirmation_email':
            json_data = {"notificationId": notificationid}
            response = requests.post(f"{SEND_NOTIFICATION_EMAIL_URL}/send/email", json=json_data, headers=headers)
            if response.status_code == 200:
                log.debug(f'Notification email send to <{email_exist.email}>')
            else:
                raise ResendConfirmationEmailError
    else:
        return None


def create_new_user(db: Session, user):
    email_exist = get_user_by_email(db, user['email'])
    if email_exist:
        raise HTTPException(status_code=403, detail="Email already in use !")
    created_user = models.User(**user)
    db.add(created_user)
    db.commit()
    db.refresh(created_user)
    return created_user


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


def check_username_exist(db: Session, username: str):
    return db.query(models.User).filter(models.User.user_name == username).first()


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def get_multi_users_by_emails(db: Session, emails: list):
    return [obj.id for obj in db.query(models.User).filter(models.User.email.in_(emails))]


def get_multi_groups_by_group_names(db: Session, names: list):
    return [obj.id for obj in db.query(models.Group).filter(models.Group.name.in_(names))]


def get_user_by_uuid(db: Session, user_id: UUIDCheckForUserIDSchema):
    """For single user only"""
    return db.query(models.User).filter(models.User.id == user_id.user_id).first()


def user_verified(db: Session, verified: bool, user_status: bool, user_id: int):
    db.execute(f"SET zekoder.id = '{user_id}'")
    update = db.query(models.User).get(user_id)
    if update:
        update.verified = verified
        update.user_status = user_status
        db.commit()
    db.refresh(update)
    return update


def delete_current_user(db: Session, user_id: UUIDCheckForUserIDSchema):
    """Deletes current user"""
    delete_user = get_user_by_uuid(db, user_id)
    db.delete(delete_user)
    db.commit()
    return {"detail": f"User <{delete_user.id}> deleted successfully !"}


def update_existing_user(db: Session, user_id: UUIDCheckForUserIDSchema, user: UserUpdateSchema):
    """Updating existing user"""
    db.execute(f"SET zekoder.id = '{user_id.user_id}'")
    update = get_user_by_uuid(db, user_id)
    if update:
        update.first_name = user.first_name
        update.last_name = user.last_name
        update.verified = user.verified
        update.user_status = user.user_status
        update.phone = user.phone
        db.commit()
        db.refresh(update)
    return {"first_name": update.first_name, "last_name": update.last_name, "verified": update.verified,
            "user_status": update.user_status, "phone": update.phone}


def userActiveOnOff(db: Session, user_id: UUIDCheckForUserIDSchema, q):
    """
    q parameter represents ON/OFF status. Endpoint sends q parameter ON or OFF
    we can handle it here and set user_status
    """
    db.execute(f"SET zekoder.id = '{user_id.user_id}'")
    update = get_user_by_uuid(db, user_id)
    if update:
        if q == 'ON':
            update.user_status = True
        else:
            update.user_status = False
        db.commit()
    db.refresh(update)
    return {"user_id": update.id, "user_activation": q}


def get_users_with_ids(db: Session, user_ids: UsersWithIDsSchema):
    """Gets users data with fetching Roles and Groups info with their uuid's"""
    query = db.query(models.User)
    data = [obj for obj in query.filter(models.User.id.in_(user_ids.users_ids)).all()]
    for i in data:
        groups = [group['name'] for group in get_groups_name_of_user_by_id(db, str(i.id))]
        roles = get_roles_name_of_group(db, groups)
        roles = [roles for roles, in roles]
        users = [dict(
            id=i.id,
            email=i.email,
            first_name=i.first_name,
            last_name=i.last_name,
            full_name=f"{i.first_name} {i.last_name}",
            username=i.user_name,
            verified=i.verified,
            user_status=i.user_status,
            phone=i.phone,
            created_on=i.created_on,
            last_login_at=i.last_login_at,
            updated_on=i.updated_on,
            groups=groups,
            roles=roles
        )]
        yield {"user": users}
    # execute method, you can use this one too
    """
    users = [obj for obj in
             db.execute("select u.id as id, u.email as email, u.first_name as first_name, "
                        "u.last_name as last_name, concat(u.first_name,' ',u.last_name) as full_name, "
                        "u.user_name as username, u.verified as verified, "
                        "case when u.user_status = 'true' then 'ON' else 'OFF' end as user_status, "
                        "u.phone as phone, u.created_on as created_on, u.last_login_at as last_login_at, "
                        "u.updated_on as updated_on, u.updated_by as updated_by, "
                        "array(select gr.name from groups gr inner join groups__users gru on gru.groups = gr.id "
                        "where gru.users = u.id group by gr.id) as groups, "
                        "array(select r.name from roles r inner join groups__roles grl on grl.roles = r.id "
                        "inner join groups gr on gr.id = grl.groups "
                        "inner join groups__users gru on gru.groups = gr.id "
                        "where grl.roles = r.id and gru.users = u.id group by r.id) as roles "
                        "from users u where u.id in ('b9ae5870-933d-11ed-bfa0-bf475bd063ff', 'deee9916-933c-11ed-9e21-ff7dc39615ee')")
             ]
    yield {"user": users}
    """


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


def assign_multi_groups_to_user(db: Session, user_id: str, groups: UserToGroupsSchema):
    try:
        if groups.groups:

            query_groups = db.query(models.Group)
            query_user = db.query(models.User)
            query_groupUser = db.query(models.GroupsUser)
            # Check ! do we have a record in our groups table, for requested groups uuid's ?
            groups_in_groupsTable = [obj.id for obj in
                                     query_groups
                                     .filter(models.Group.id.in_(groups.groups))]
            # check user in the group
            users_in_groupUserTable = [obj.groups for obj in
                                       query_groupUser
                                       .filter(and_(models.GroupsUser.groups.in_(groups_in_groupsTable)),
                                               (models.GroupsUser.users == user_id))]
            # If users exist in UserTable and not in the groupTable, so assign them to the group
            assign_user_to_groups = [obj for obj in groups_in_groupsTable if obj not in set(users_in_groupUserTable)]

            if assign_user_to_groups:  # These users not in the group, so you can assign them to this group
                db.bulk_insert_mappings(
                    models.GroupsUser,
                    [dict(users=user_id, groups=groups, ) for groups in assign_user_to_groups],
                )
                db.commit()
                return groups.groups
            else:
                raise HTTPException(status_code=403, detail="Available Groups are already related to this User")

    except ValueError as e:
        log.error(e)
        return {"detail": "invalid uuid"}


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
                return {"message": f"Users {users_in_usersTable} successfully assigned to the group",
                        "status_code": "201"}
            else:
                return {"message": f"Available users {users_in_usersTable} are already assigned to the group",
                        "status_code": "403"}

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
                return {"message": f"Roles {roles_in_rolesTable} successfully assigned to the group",
                        "status_code": "201"}
            else:
                return {"message": f"Available roles {roles_in_rolesTable} are already assigned to the group",
                        "status_code": "403"}

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


def is_role_not_exists(db: Session, role_create: RoleBaseSchema):
    return not (
        db.query(models.Role)
        .filter(
            models.Role.name == role_create.name
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
    return ''.join((secrets.choice(
        string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
    ) for i in range(32))) \
        .replace('"',
                 '')  # when generating client_id remove "" for not get error on request body. for example this generated id throws error "%*jt""3g@*4(!_O`sC,]_S'>BE;R@t4h\"


def check_user_has_role(db: Session, user: str, role_name: str) -> [Any]:
    return db.query(
        models.GroupsUser, models.GroupsRole, models.Role
    ).filter(
        models.GroupsUser.users == user,
    ).filter(
        models.GroupsRole.groups == models.GroupsUser.groups
    ).filter(
        models.GroupsRole.roles == models.Role.id
    ).filter(
        models.Role.name == role_name
    ).all()


def get_client_by_uuid_and_secret(db: Session, client_id: uuid, client_secret: str):
    """Check client exists or not ? with client_id and client_secret"""
    client_info = db.query(models.Client) \
        .filter(models.Client.id == client_id,
                models.Client.client_secret == client_secret) \
        .first()
    return client_info


def get_client_by_uuid(db: Session, client_id: UUIDCheckForClientIdSchema):
    """Gets client's id by uuid"""
    client_info = db.query(models.Client).filter(models.Client.id == client_id.client_id).first()
    return client_info


def get_client_by_name(db: Session, name: str):
    client_info = db.query(models.Client).filter(models.Client.name == name).first()
    return client_info


def check_client_exists_with_email(db: Session, email: str):
    """checks email from users table, if exist than gets this email's owner uuid and
    search for this uuid in client table as an owner id, if it exists than
    that means client already exist
    """
    get_uuid_from_email = db.query(models.User).filter(models.User.email == email).first()
    if get_uuid_from_email:
        client_exist = db.query(models.Client).filter(models.Client.owner == get_uuid_from_email.id).first()
        return client_exist
    return None


def create_new_client(db: Session, client: ClientCreateSchema):
    # first check email
    email_exist = get_user_by_email(db, client.email)
    # if exists add client info to client table and add groups to groups__users table
    if email_exist:
        add_to_client_table = models.Client(
            name=client.name,
            client_secret=generate_client_secret(),
            owner=email_exist.id
        )
        db.add(add_to_client_table)
        db.commit()
        db.refresh(add_to_client_table)
        # add groups to groups_users with owner
        groups_list_check = get_groups_by_name_list(db, client.groups)
        if groups_list_check:
            db.bulk_insert_mappings(
                models.GroupsUser,
                [dict(groups=group_id, users=email_exist.id, ) for group_id in groups_list_check],
            )
            db.commit()
        return {"client_id": add_to_client_table.id, "client_secret": add_to_client_table.client_secret}
    else:
        # if not exists
        # add client info to users table first, then get it's uuid
        add_client_to_users_table = models.User(
            email=client.email,
            user_name=client.email,
            password="",
            first_name=client.name
        )
        db.add(add_client_to_users_table)
        db.commit()
        db.refresh(add_client_to_users_table)
        # now add to client info to client table with owner uuid (from users table)
        add_to_client_table = models.Client(
            name=client.name,
            client_secret=generate_client_secret(),
            owner=add_client_to_users_table.id
        )
        db.add(add_to_client_table)
        db.commit()
        db.refresh(add_to_client_table)
        # now add groups to groups_users with its owner
        groups_list_check = get_groups_by_name_list(db, client.groups)
        if groups_list_check:
            db.bulk_insert_mappings(
                models.GroupsUser,
                [dict(groups=group_id, users=add_client_to_users_table.id, ) for group_id in groups_list_check],
            )
            db.commit()
        return {"client_id": add_to_client_table.id, "client_secret": add_to_client_table.client_secret}


def create_client_auth(db: Session, client_auth: ClientSchema):
    CLIENT_TOKEN_EXPIRY_MINUTES = os.environ.get('CLIENT_TOKEN_EXPIRY_MINUTES')
    client_exists = get_client_by_uuid_and_secret(db, client_auth.client_id, client_auth.client_secret)
    # Generate refresh token;
    generated_refresh_token = uuid.uuid4()
    generated_refresh_token = str(generated_refresh_token).replace('-', '')

    if client_exists:
        payload = ClientJWTSchema
        payload.client_id = str(client_exists.id)
        payload.expr = (datetime.utcnow() + timedelta(
            minutes=int(CLIENT_TOKEN_EXPIRY_MINUTES)))  # This is not for redis only for payload
        payload.expr = payload.expr.timestamp()
        payload.name = client_exists.name
        payload.owner = str(client_exists.owner)
        payload.iss = os.environ.get('ZEAUTH_URL')
        payload.groups = [group['name'] for group in get_groups_name_of_user_by_id(db, str(client_exists.owner))]
        payload = dict(
            client_id=payload.client_id,
            aud=AUDIENCE,  # this will need when to decode jwt
            expr=int(payload.expr),
            name=payload.name,
            owner=payload.owner,
            iss=payload.iss,
            groups=payload.groups
        )
        # JWT operations
        client_token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")
        payload['client_token'] = client_token
        payload['refreshToken'] = generated_refresh_token  # Dont send in payload jwt.encode
        # Write payload to Redis with expiry 30 Minutes
        client.set_client_token(payload)
        return payload  # for only to test NOW !!
    return None


def remove_client(db: Session, client_id: UUIDCheckForClientIdSchema):
    """Delete current client from client table"""
    delete_client = get_client_by_uuid(db, client_id)
    db.delete(delete_client)
    db.commit()
    # delete client record from groups_users table
    db.query(models.GroupsUser) \
        .filter(models.GroupsUser.users == delete_client.owner) \
        .delete()
    db.commit()
    # delete current client record from users table
    # if this record created by client and password is empty then we can delete it
    # otherwise client owner in the user table could be admin, user, super-admin ex.!
    # that means password could not be empty, we should not delete this records
    delete_client_from_users_table = db.query(models.User) \
        .filter(and_(models.User.id == delete_client.owner,
                     models.User.password == '')) \
        .first()

    if delete_client_from_users_table:
        db.delete(delete_client_from_users_table)
        db.commit()
    return delete_client.id


def update_status_verified(db: Session, user_id: str, verified: bool, user_status: bool):

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise ValueError(f"USER with id {user_id} not found")
    user.verified = verified
    user.user_status = user_status
    db.commit()
    return user
