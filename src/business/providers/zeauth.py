from datetime import datetime, timedelta, date
import os
import json
import uuid
import rsa
import base64
from business.providers.base import *
from business.models.schema_users import UsersWithIDsSchema, UserUpdateSchema, UserCreateSchema
from business.models.users import User, LoginResponseModel, EncryptDecryptStrSchema, EncryptedContentSchema
from sqlalchemy.exc import IntegrityError
from core import log, crud
import requests
from core.crud import get_groups_name_of_user_by_id, get_roles_name_of_group
from core.cryptography_fernet import StringEncryptDecrypt
from redis_service.redis_service import RedisClient, set_redis, get_redis
from email_service.mail_service import send_email
from ..models.schema_groups_role import GroupsRoleBase, GroupsUserBase
from ..models.schema_main import  UUIDCheckForUserIDSchema
from ..models.schema_roles import RoleBaseSchema
from ..models.schemas_groups import GroupBaseSchema
from ..models.users import ResetPasswordVerifySchema, ConfirmationEmailVerifySchema
import jwt
from config.db import get_db

RESEND_CONFIRMATION_EMAIL_URL = os.environ.get('RESEND_CONFIRMATION_EMAIL_URL')
RESET_PASSWORD_URL = os.environ.get('RESET_PASSWORD_URL')
FUSIONAUTH_APIKEY = os.environ.get('FUSIONAUTH_APIKEY')
APPLICATION_ID = os.environ.get('applicationId')
ZEAUTH_URL = os.environ.get('ZEAUTH_URL')
STR_ENCRYPT_DECRYPT_KEY = os.environ.get('STR_ENCRYPT_DECRYPT_KEY')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
AUDIENCE = 'ZeAuth'
client = RedisClient()
DEFAULT_ADMIN_EMAIL = os.environ.get('DEFAULT_ADMIN_EMAIL')
DEFAULT_ADMIN_PASSWORD = os.environ.get('DEFAULT_ADMIN_PASSWORD')
DEFAULT_GROUPS = [
    {"name": "admin", "description": "Administrators of system"},
    {"name": "super-user", "description": "Users with additional previlages"},
    {"name": "user", "description": "Regular users"}
]
APP_NAME = 'zekoder-zeauth'
ROLE_ACTIONS = ["create", "list", "get", "update", "del"]
ROLE_RESOURCE = ["users", "roles", "groups", "clients"]


class ProviderFusionAuth(Provider):
    admin_user_created = None
    admin_user_id = None

    def __init__(self) -> None:
        self.fusionauth_client = None
        self.str_enc_dec = StringEncryptDecrypt(STR_ENCRYPT_DECRYPT_KEY)
        super().__init__()



    def list_users(self, page: int, page_size: int, search: str, user_status: bool, date_of_creation: date,
                   date_of_last_login: date, sort_by, sort_column, db):
        next_page = 2
        skip = 0
        if page > 0:
            skip = (page - 1) * page_size
            next_page = page + 1

        users, total_count = crud.get_users(db, skip=skip, limit=page_size, search=search, user_status=user_status,
                                            date_of_creation=date_of_creation, date_of_last_login=date_of_last_login,
                                            sort_by=sort_by, sort_column=sort_column)
        users = [self._cast_user(user) for user in users]

        return users, next_page, page_size, total_count

    def _cast_user(self, user):
        return User(
            id=str(user.id),
            email=user.email,
            username=user.user_name,
            verified=user.verified,
            user_status=user.user_status,
            first_name=user.first_name,
            last_name=user.last_name,
            full_name=user.first_name + ' ' + user.last_name if user.last_name else '',
            phone=user.phone,
            last_login_at=user.last_login_at,
            created_at=user.created_on,
            update_at=user.updated_on
        )

    def _social_login_model(self, response: dict) -> object:
        """
        NOTE: For every social provider, use flag like(Google, twitter, facebook) to know where is response coming from.
                Because responses are not same for all social providers
        TWITTER NOTE: Twitter response doesn't have first_name and last_name options. For that reason we assign screen_name
                fields to first_name and last_name
        :param response:
        :return:
        """
        db = get_db().__next__()
        ACCESS_TOKEN_EXPIRY_MINUTES = os.environ.get('ACCESS_TOKEN_EXPIRY_MINUTES')

        if 'google' in response.keys():  # Flag google
            googleResponse = response['google']
            email = googleResponse['email'] if 'email' in googleResponse.keys() else ""
            avatar_url = googleResponse['picture'] if 'picture' in googleResponse.keys() else ""
            first_name = googleResponse['given_name'] if 'given_name' in googleResponse.keys() else ""
            last_name = googleResponse['family_name'] if 'family_name' in googleResponse.keys() else ""
            full_name = googleResponse[
                'name'] if 'name' in googleResponse.keys() else f"{googleResponse['given_name']} {googleResponse['family_name']}"
        elif 'facebook' in response.keys():
            facebookResponse = response['facebook']
            email = facebookResponse['email'] if 'email' in facebookResponse.keys() else ""
            avatar_url = facebookResponse['picture']['data']['url'] if 'picture' in facebookResponse.keys() else ""
            first_name = facebookResponse['first_name'] if 'first_name' in facebookResponse.keys() else ""
            last_name = facebookResponse['last_name'] if 'last_name' in facebookResponse.keys() else ""
            full_name = facebookResponse[
                'name'] if 'name' in facebookResponse.keys() else f"{facebookResponse['first_name']} {facebookResponse['last_name']}"
        elif 'twitter' in response.keys():
            twitterResponse = response['twitter']
            email = twitterResponse['email'] if 'email' in twitterResponse.keys() else ""
            avatar_url = twitterResponse[
                'profile_image_url_https'] if 'profile_image_url_https' in twitterResponse.keys() else ""
            first_name = twitterResponse['screen_name'] if 'screen_name' in twitterResponse.keys() else ""
            last_name = twitterResponse['screen_name'] if 'screen_name' in twitterResponse.keys() else ""
            full_name = twitterResponse[
                'name'] if 'name' in twitterResponse.keys() else f"{twitterResponse['screen_name']} {twitterResponse['screen_name']}"
        else:
            email = ''
            avatar_url = ''
            first_name = ''
            last_name = ''
            full_name = ''

        generated_user_id = uuid.uuid4()  # Only generate one time then use this for the login user, we should put this DB later !!!!!
        generated_user_id = str(generated_user_id).replace('-', '')
        generated_refresh_token = uuid.uuid4()
        generated_refresh_token = str(generated_refresh_token).replace('-', '')

        expr_in_payload = (datetime.utcnow() + timedelta(
            minutes=int(ACCESS_TOKEN_EXPIRY_MINUTES)))  # Don't add redis expr here, use like this.
        expr_in_payload = expr_in_payload.timestamp()  # Timestamp format '1670440005'

        user_id = generated_user_id
        uid = user_id
        verified = True
        user_status = True,

        last_login_at = datetime.utcnow()  # get this data from db
        last_update_at = datetime.utcnow()  # get this data from db
        created_at = datetime.utcnow()

        roles = []
        groups = []
        get_groups = get_groups_name_of_user_by_id(db, str(user_id))
        if get_groups:
            groups = [group['name'] for group in get_groups]
            get_roles = get_roles_name_of_group(db, groups)
            roles = [roles for roles, in get_roles]

        payload = dict(
            aud=AUDIENCE,
            expr=int(expr_in_payload),
            iss=os.environ.get('ZEAUTH_URL'),
            sub=user_id,
            email=email,
            username=email,
            verified=verified,
            user_status=user_status,
            avatar_url=avatar_url,
            first_name=first_name,
            last_name=last_name,
            full_name=full_name,
            roles=roles,
            groups=groups,
            created_at=int(created_at.timestamp()),
            last_login_at=int(last_login_at.timestamp()),
            last_update_at=int(last_update_at.timestamp()),
        )
        try:
            access_token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")
            payload['refreshToken'] = generated_refresh_token  # Dont send in payload jwt.encode
            client.set_user_token(payload)  # write data to Redis

            return LoginResponseModel(
                user=User(
                    id=user_id,
                    email=payload['email'],
                    first_name=payload['first_name'],
                    last_name=payload['last_name'],
                    full_name=payload['full_name'],
                    username=payload['username'],
                    verified=payload['verified'],
                    user_status=payload['user_status'],
                    avatar_url=payload['avatar_url'],
                    created_at=payload['created_at'],
                    last_login_at=payload['last_login_at'],
                    last_update_at=payload['last_update_at'],
                    roles=payload['roles'],
                    groups=payload['groups']
                ),
                uid=uid,
                accessToken=access_token,
                refreshToken=generated_refresh_token,
                expirationTime=payload['expr']
            )
        except Exception as e:
            log.error(e)
            raise e

    def _cast_login_model(self, user) -> object:
        db = get_db().__next__()
        ACCESS_TOKEN_EXPIRY_MINUTES = os.environ.get('ACCESS_TOKEN_EXPIRY_MINUTES')

        full_name = user.first_name

        if user.last_name:
            full_name = f"{full_name} {user.last_name}"

        last_login_at = user.last_login_at
        update_at = user.updated_on
        created_at = user.created_on

        roles = []
        groups = []
        get_groups = get_groups_name_of_user_by_id(db, str(user.id))
        if get_groups:
            groups = [group['name'] for group in get_groups]
            get_roles = get_roles_name_of_group(db, groups)
            roles = [roles for roles, in get_roles]

        generated_refresh_token = uuid.uuid4()
        generated_refresh_token = str(generated_refresh_token).replace('-', '')

        expr_in_payload = (datetime.utcnow() + timedelta(
            minutes=int(ACCESS_TOKEN_EXPIRY_MINUTES)))  # Don't add redis expr here, use like this.
        expr_in_payload = expr_in_payload.timestamp()  # Timestamp format '1670440005'

        payload = dict(
            aud=AUDIENCE,
            expr=int(expr_in_payload),
            iss=os.environ.get('ZEAUTH_URL'),
            id=str(user.id),
            sub=str(user.id),
            email=user.email,
            username=user.user_name,
            verified=user.verified,
            user_status=user.user_status,
            avatar_url='',
            first_name=user.first_name,
            last_name=user.last_name,
            full_name=full_name,
            permissions=groups,
            roles=roles,
            groups=groups,
            created_at=int(created_at.timestamp()),
            last_login_at=int(last_login_at.timestamp()) if last_login_at else None,
            last_update_at=int(update_at.timestamp()) if update_at else None,
        )
        access_token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")
        payload['refreshToken'] = generated_refresh_token  # Dont send in payload jwt.encode
        client.set_user_token(payload)  # write data to Redis

        return LoginResponseModel(
            user=User(
                id=str(user.id),
                email=user.email,
                username=user.user_name,
                verified=user.verified,
                user_status=user.user_status,
                created_at=user.created_on,
                last_login_at=user.last_login_at,
                update_at=user.updated_on,
                first_name=user.first_name,
                last_name=user.last_name,
                roles=roles,
                permissions=groups,
                groups=groups,
                full_name=full_name
            ),
            uid=str(user.id),
            accessToken=access_token,
            refreshToken=generated_refresh_token,
            expirationTime=payload['expr']
        )

    def login(self, user_info, db):
        try:
            if response := crud.get_user_login(db=db, email=user_info.email):
                decrypted_password = self.str_enc_dec.decrypt_str(enc_message=response.password)
                if decrypted_password != user_info.password:
                    raise InvalidCredentialsError('failed login')
                return self._cast_login_model(response)
            else:
                raise InvalidCredentialsError('failed login')
        except Exception as e:
            log.error(e)
            raise e

    def encrypt_str(self, str_for_enc: str):
        encrypted_str = self.str_enc_dec.encrypt_str(message=str_for_enc)
        return EncryptDecryptStrSchema(encrypt_decrypt_str=encrypted_str)

    def decrypt_str(self, str_for_dec: str):
        decrypted_str = self.str_enc_dec.decrypt_str(enc_message=str_for_dec)
        return EncryptDecryptStrSchema(encrypt_decrypt_str=decrypted_str)


    def userActivationProcess(self, db, user_id: UUIDCheckForUserIDSchema, q):
        """user active on/off process can be done from here"""
        try:
            return crud.userActiveOnOff(db, user_id, q=q)
        except Exception as err:
            log.debug(err)
            raise err

    def usersWithIDs(self, db, user_ids: UsersWithIDsSchema):
        """user active on/off process can be done from here"""
        try:
            return crud.get_users_with_ids(db, user_ids)
        except Exception as err:
            log.debug(err)
            raise err

    def updateUser(self, db, user_id: UUIDCheckForUserIDSchema, user: UserUpdateSchema):
        """update existing user"""
        try:
            return crud.update_existing_user(db, user_id, user)
        except Exception as err:
            log.debug(err)
            raise err

    def deleteUser(self, db, user_id: UUIDCheckForUserIDSchema):
        """update existing user"""
        try:
            return crud.delete_current_user(db, user_id)
        except Exception as err:
            log.debug(err)
            raise err

    def createNewUser(self, db, user: UserCreateSchema):
        """create new user"""
        try:
            encrypted_password = self.str_enc_dec.encrypt_str(message=user.password)
            user_Name = user.user_name
            # check if username is not DEFAULT_ADMIN_EMAIL(We need this control for bootsraping)
            # and if username not none, check username taken from another account, if not assign
            # else username field is empty then fetch username field to email field.
            if user_Name != DEFAULT_ADMIN_EMAIL:
                if user.user_name != "":
                    userName = crud.check_username_exist(db, user_Name)
                    if userName is None:
                        user_Name = user.user_name
                    else:
                        raise UserNameError("username already linked to an account")
                else:
                    user_Name = user.email

            created_user = crud.create_new_user(db, user={
                "email": user.email,
                "user_name": user_Name,
                "password": str(encrypted_password),
                "verified": False,
                "user_status": False,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "phone": user.phone,
            })
            return created_user
        except Exception as err:
            log.debug(err)
            raise err

    @staticmethod
    def get_pub_encrypt_key():
        pub_key = base64.b64decode(os.environ.get('DATA_ENCRYPTION_PUB_KEY'))
        public_key = rsa.PublicKey.load_pkcs1(pub_key)
        return str(public_key)

    def enc_to_decrypt(self, encrypted: EncryptedContentSchema):
        # request str to byte
        encrypted = base64.b64decode(encrypted.encrypted)
        # call DATA_ENCRYPTION_PRIV_KEY and decode
        private_key_dec = base64.b64decode(os.environ.get('DATA_ENCRYPTION_PRIV_KEY'))
        # use decoded private key
        private_key = rsa.PrivateKey.load_pkcs1(private_key_dec)
        return {"decrypted": rsa.decrypt(encrypted, private_key).decode('utf-8')}

    def signup(self, db, user: UserRequest) -> User:
        log.info("zeauth")
        try:
            encrypted_password = self.str_enc_dec.encrypt_str(message=user.password)
            log.info(f"encrypted_password {encrypted_password}")

            userName = user.username
            # check if username is not DEFAULT_ADMIN_EMAIL(We need this control for bootsraping)
            # and if username not none, check username taken from another account, if not assign
            # else username field is empty then fetch username field to email field.
            if userName != DEFAULT_ADMIN_EMAIL:
                if user.username != "":
                    userName = crud.check_username_exist(db, userName)
                    if userName is None:
                        userName = user.username
                    else:
                        raise UserNameError("username already linked to an account")
                else:
                    userName = user.email

            user_resp = crud.create_user(db, user={
                "email": user.email,
                "user_name": userName,
                "password": str(encrypted_password),
                "verified": False,  # On signup make user verified False
                "user_status": False,   # On signup make user_status False
                "first_name": user.first_name,
                "last_name": user.last_name,
                "phone": user.phone,
            })
            log.info(user_resp.id)
            log.info(f"user {user_resp.email} created successfully.")
            return self._cast_user(user_resp)

        except IntegrityError as err:
            log.error(err)
            raise DuplicateEmailError() from err
        except Exception as err:
            log.debug(err)
            raise err

    async def reset_password(self, user_info, db):
        try:
            user_resp = crud.get_user_by_email(db=db, email=user_info.username)
            if not user_resp:
                raise UserNotFoundError(f"User '{user_info.username}' not in system")

            reset_key = hash(uuid.uuid4().hex)
            set_redis(reset_key, user_info.username)

            reset_password_url = f"{RESET_PASSWORD_URL}?token={reset_key}"
            await send_email(
                recipients=[user_info.username],
                subject="Reset Password",
                body=reset_password_url
            )
            return True
        except Exception as err:
            log.error(err)
            raise err

    def reset_password_verify(self, reset_password: ResetPasswordVerifySchema, db):
        try:
            try:
                email = get_redis(reset_password.reset_key)
            except Exception as err:
                log.error(f"redis err: {err}")
                raise IncorrectResetKeyError(f"Reset key {reset_password.reset_key} is incorrect!") from err

            encrypted_password = self.str_enc_dec.encrypt_str(message=reset_password.new_password)
            user = crud.get_user_by_email(db, email=email)

            res = crud.reset_user_password(db, password=str(encrypted_password), user_id=user.id)
            log.info(res.email)
            if response := crud.get_user_login(db=db, email=email):
                return self._cast_login_model(response)
        except Exception as err:
            log.error(f"Exception: {err}")
            raise err


    async def resend_confirmation_email(self, db, user_info):
        try:
            user = crud.get_user_by_email(db, user_info.username)
            if not user:
                raise UserNotFoundError(f"User '{user_info.username}' not in system")

            crud.user_verified(db, verified=False, user_status=False, user_id=user.id)

            confirm_email_key = hash(uuid.uuid4().hex)
            set_redis(confirm_email_key, user_info.username)
            confirm_email_url = f"{RESEND_CONFIRMATION_EMAIL_URL}?token={confirm_email_key}"
            directory = os.path.dirname(__file__)
            with open(os.path.join(directory, "../../index.html"), "r", encoding="utf-8") as index_file:
                email_template = index_file.read() \
                    .replace("{{first_name}}", user.first_name) \
                    .replace("{{verification_link}}", confirm_email_url)

                await send_email(
                    recipients=[user_info.username],
                    subject="Confirm email",
                    body=email_template
                )

            return "Confirmation email sent!"
        except Exception as err:
            log.error(err)
            raise err

    def verify_email(self, db, email_verify: ConfirmationEmailVerifySchema):
        try:
            try:
                email = get_redis(email_verify.token)
            except Exception as err:
                log.error(f"redis err: {err}")
                raise IncorrectResetKeyError(f"Token {email_verify.token} is incorrect!") from err

            if user := crud.get_user_by_email(db, email):
                # ZEK-887 user_status should return false if verified is false. If verified is true ,
                # user_status should also return true.
                crud.user_verified(db, verified=True, user_status=True, user_id=user.id)

            return "Email Verified!"
        except Exception as err:
            log.error(f"Exception: {err}")
            raise err

    def verify(self, token: str):
        try:
            user = jwt.decode(bytes(token, 'utf-8'), JWT_SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE)

            if not user.get('email'):
                error_template = "ZeAuth Token verify:  An exception of type {0} occurred. error: {1}"
                log.error(user)
                raise InvalidTokenError('failed token verification')

            if user.get('client_id'):
                client_payload = dict(
                    client_id=str(user.get('client_id')),
                    aud=user.get('aud'),
                    expr=int(user.get('expr')),
                    iss=user.get('iss'),
                    name=user.get('name'),
                    email=user.get('email'),
                    roles=user.get('roles')
                )
                return client_payload

            else:
                return User(
                    id=str(user.get('id')),
                    roles=user.get('roles'),
                    groups=user.get('groups'),
                    email=user.get('email'),
                    user_name=user.get('username'),
                    verified=user.get('verified'),
                    user_status=user.get('user_status'),
                    first_name=user.get('first_name'),
                    last_name=user.get('last_name'),
                    full_name=user.get('full_name'),
                    phone=user.get('phone'),
                    last_login_at=user.get('last_login_at'),
                    created_at=user.get('created_at'),
                    update_at=user.get('last_update_at'),
                    permissions=user.get('groups')
                )

        except Exception as err:
            error_template = "ZeAuth Token verify:  An exception of type {0} occurred. error: {1}"
            log.error(error_template.format(type(err).__name__, str(err)))
            log.debug(err)
            raise InvalidTokenError('failed token verification') from err

    def refreshtoken(self, token: str):
        REDIS_KEY_PREFIX = os.environ.get('REDIS_KEY_PREFIX')
        REDIS_CLIENT_KEY_PREFIX = os.environ.get('REDIS_CLIENT_KEY_PREFIX')

        generated_refresh_token = uuid.uuid4()
        generated_refresh_token = str(generated_refresh_token).replace('-', '')
        try:
            # for user
            if client.get_refresh_token(f"{REDIS_KEY_PREFIX}-{token}", "map_refresh_token"):  # Search for the key if it is exists
                payload_user = client.hgetall_redis_user_payload(f"{REDIS_KEY_PREFIX}-{token}")  # Get data from Redis with refresh token
                if payload_user:
                    # new access_token generated from valid refresh_token request
                    new_access_token_user = jwt.encode(payload_user, JWT_SECRET_KEY, algorithm="HS256")
                    payload_user['refreshToken'] = generated_refresh_token  # Dont send in payload jwt.encode
                    client.set_user_token(payload_user)  # write data to Redis
                    client.del_refresh_token(f"{REDIS_KEY_PREFIX}-{token}")  # delete previous refresh_token key and the data
                    return {'accessToken': new_access_token_user, 'refreshToken': payload_user['refreshToken']}
                else:
                    return {'No Redis Data exists !'}
            # for client
            elif client.get_refresh_token(f"{REDIS_CLIENT_KEY_PREFIX}-{token}", "map_client_refreshToken"):
                payload_client = client.hgetall_redis_client_payload(f"{REDIS_CLIENT_KEY_PREFIX}-{token}")
                if payload_client:
                    # new access_token generated from valid refresh_token request
                    new_access_token_client = jwt.encode(payload_client, JWT_SECRET_KEY, algorithm="HS256")
                    payload_client['refreshToken'] = generated_refresh_token  # Dont send in payload jwt.encode
                    client.set_client_token(payload_client)  # write data to Redis
                    client.del_refresh_token(f"{REDIS_CLIENT_KEY_PREFIX}-{token}")  # delete previous refresh_token key and the data
                    return {'accessToken': new_access_token_client, 'refreshToken': payload_client['refreshToken']}
                else:
                    return {'No Redis Data exists !'}
            else:
                raise InvalidTokenError('failed refresh token request')
        except Exception as err:
            log.error(err)
            raise err

    def zeauth_bootstrap(self):
        db = get_db().__next__()
        log.info("zeauth_bootstrap...")

        if ProviderFusionAuth.admin_user_created:
            return
        try:
            user = self.signup(db, UserRequest(
                email=DEFAULT_ADMIN_EMAIL,
                username=DEFAULT_ADMIN_EMAIL,
                password=DEFAULT_ADMIN_PASSWORD,
                first_name="Master",
                last_name="Account"
            ))
            user_id = user.id
            log.info(f"Master Account created.. {user_id}")
        except DuplicateEmailError as e:
            log.info("user already created")
            db.rollback()
            ProviderFusionAuth.admin_user_created = True
            return None
        except Exception as ex:
            log.error("unable to bootstrap")
            log.error(ex)
            return None
        try:
            # creating default roles
            for resource in ROLE_RESOURCE:
                for action in ROLE_ACTIONS:
                    role_name = f"{APP_NAME}-{resource}-{action}"
                    try:
                        role_description = f"{APP_NAME} action {action} for {resource} "
                        role_create = RoleBaseSchema(name=role_name, description=role_description)
                        if crud.is_role_not_exists(db, role_create):
                            db_role = crud.create_role(db, role_create)
                        log.info(f"role: {role_name} created..")
                    except IntegrityError as err:
                        log.info(f"role {role_name} already created")
                        db.rollback()
                    except Exception as err:
                        log.error("unable to bootstrap")
                        log.error(err)
                        return None
            role_name = f"{APP_NAME}-users-signup"
            role_description = f"{APP_NAME} action signup for users"
            role_create = RoleBaseSchema(
                name=role_name,
                description=role_description
            )
            if crud.is_role_not_exists(db, role_create):
                db_role = crud.create_role(db, role_create)

            # creating default groups
            groups = {}
            for group in DEFAULT_GROUPS:
                try:
                    db_group = crud.create_group(db, group_create=GroupBaseSchema(name=group['name'],
                                                                                  description=group['description']))
                    groups['group_id'] = db_group.id
                    log.info(f"group: {group['name']} created..")
                except IntegrityError as err:
                    db.rollback()
                    log.info(f"group {group['name']} already created")
                except Exception as err:
                    log.error("unable to bootstrap")
                    log.error(err)
                    return None
            # groups roles
            admin_group = crud.get_group_by_name(db, name='admin')
            db_roles = crud.get_roles(db)
            super_user_group = crud.get_group_by_name(db, name='super-user')

            roles_for_super_user = ['zekoder-zeauth-users-create', 'zekoder-zeauth-users-list',
                                    'zekoder-zeauth-users-get', 'zekoder-zeauth-roles-get',
                                    'zekoder-zeauth-roles-list', 'zekoder-zeauth-groups-list',
                                    'zekoder-zeauth-groups-get']

            for role in db_roles:
                if role.name in roles_for_super_user:
                    try:
                        if not crud.is_groups_role_not_exists(db,
                                                          GroupsRoleBase(roles=role.id, groups=super_user_group.id)):
                            group_role = crud.create_groups_role(db,
                                                                 GroupsRoleBase(roles=role.id,
                                                                                groups=super_user_group.id))
                            log.info(f"groups role: {group_role.id} created..")
                        else:
                            log.info("groups role already created")
                    except IntegrityError as err:
                        log.info("groups role already created")
                        db.rollback()
                    except Exception as err:
                        log.error("unable to bootstrap")
                        log.error(err)
                        return None
                if admin_group:
                    try:
                        if crud.is_groups_role_not_exists(db, GroupsRoleBase(roles=role.id, groups=admin_group.id)):
                            group_role = crud.create_groups_role(db,
                                                                 GroupsRoleBase(roles=role.id, groups=admin_group.id))
                            log.info(f"groups role: {group_role.id} created..")
                        else:
                            log.info("groups role already created")
                    except IntegrityError as err:
                        log.info("groups role already created")
                        db.rollback()
                    except Exception as err:
                        log.error("unable to bootstrap")
                        log.error(err)
                        return None

            login = UserLoginSchema(email=DEFAULT_ADMIN_EMAIL, password=DEFAULT_ADMIN_PASSWORD)
            admin_user = self.login(login, db)
            log.info(admin_user)
            admin_user_id = admin_user.uid
            try:
                if crud.is_groups_user_not_exists(db, GroupsUserBase(users=admin_user_id, groups=admin_group.id)):
                    group_user = crud.create_groups_user(db, GroupsUserBase(users=admin_user_id, groups=admin_group.id))
                    log.info(f"groups user: {group_user.id} created..")
                else:
                    log.info("groups user already created")

            except IntegrityError as err:
                db.rollback()
                log.info("groups user already created")
            except Exception as err:
                log.error("unable to bootstrap")
                log.error(err)
                return None

        except Exception as err:
            error_template = "zeauth_bootstrap: An exception of type {0} occurred. error: {1}"
            log.error(error_template.format(type(err).__name__, str(err)))

        ProviderFusionAuth.admin_user_created = True
