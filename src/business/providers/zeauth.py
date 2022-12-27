from datetime import datetime, timedelta, date
import os
import json
import uuid
from business.providers.base import *
from fusionauth.fusionauth_client import FusionAuthClient
from business.models.users import User, LoginResponseModel
from sqlalchemy.exc import IntegrityError
from core import log, crud
import requests
from redis_service.redis_service import RedisClient, set_redis, get_redis
from email_service.mail_service import send_email
from ..models.schema_groups_role import GroupsRoleBase, GroupsUserBase
from ..models.schema_roles import RoleBaseSchema
from ..models.schemas_groups import GroupBaseSchema
from ..models.users import ResetPasswordVerifySchema, ConfirmationEmailVerifySchema
from core.AES import AesStringCipher
import jwt
from config.db import get_db

FUSIONAUTH_APIKEY = os.environ.get('FUSIONAUTH_APIKEY')
APPLICATION_ID = os.environ.get('applicationId')
FUSIONAUTH_URL = os.environ.get('FUSIONAUTH_URL')
AES_KEY = os.environ.get('AES_KEY')
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
ROLE_RESOURCE = ["users", "roles", "groups"]


class ProviderFusionAuth(Provider):
    admin_user_created = None
    admin_user_id = None

    def __init__(self) -> None:
        self.fusionauth_client = None
        self.setup_fusionauth()
        self.aes = AesStringCipher(AES_KEY)
        super().__init__()

    def setup_fusionauth(self):
        self.fusionauth_client = FusionAuthClient(FUSIONAUTH_APIKEY, FUSIONAUTH_URL)

    def get_group_name(self, id: str):
        self.setup_fusionauth()
        try:
            response = self.fusionauth_client.retrieve_group(id)
            if response.was_successful():
                group_name = response.success_response['group']['name']
                return group_name
            else:
                return response.error_response
        except Exception as e:
            log.error(e)
            raise e

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

    def _cast_user_model(self, response: dict):
        full_name = response.get('firstName')
        if response.get('lastName'):
            full_name = f"{full_name} {response.get('lastName')}"

        last_login_at = datetime.fromtimestamp(response['lastLoginInstant'] / 1000)
        last_update_at = datetime.fromtimestamp(response['lastUpdateInstant'] / 1000)
        created_at = datetime.fromtimestamp(response['insertInstant'] / 1000)

        roles = []
        groups = []
        if len(response['registrations']) != 0:
            roles = response['registrations'][0]['roles']
        if len(response['user']['memberships']) != 0:
            for x in response['user']['memberships']:
                group_name = self.get_group_name(x['groupId'])
                groups.append(group_name)

        return User(
            id=response['id'],
            email=response['email'],
            username=response['email'],
            verified=response['verified'],
            user_status=response['active'],
            created_at=str(created_at).split(".")[0],
            last_login_at=str(last_login_at).split(".")[0],
            last_update_at=str(last_update_at).split(".")[0],
            first_name=response.get('firstName'),
            last_name=response.get('lastName'),
            roles=roles,
            groups=groups,
            full_name=full_name
        )

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

        last_login_at = datetime.utcnow()  # get this data from db
        last_update_at = datetime.utcnow()  # get this data from db
        created_at = datetime.utcnow()

        roles = []  # This will come from DB
        groups = []  # This will come from DB

        payload = dict(
            aud=AUDIENCE,
            expr=int(expr_in_payload),
            iss=os.environ.get('FUSIONAUTH_URL'),
            sub=user_id,
            email=email,
            username=email,
            verified=verified,
            user_status=True,
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
            client.set_refresh_token(payload)  # write data to Redis

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
        ACCESS_TOKEN_EXPIRY_MINUTES = os.environ.get('ACCESS_TOKEN_EXPIRY_MINUTES')

        full_name = user.first_name

        if user.last_name:
            full_name = f"{full_name} {user.last_name}"

        last_login_at = user.last_login_at
        update_at = user.updated_on
        created_at = user.created_on

        roles = []
        groups = []
        # if len(response['user']['registrations']) != 0:
        #     roles = response['user']['registrations'][0]['roles']
        # if len(response['user']['memberships']) != 0:
        #     for x in response['user']['memberships']:
        #         group_name = self.get_group_name(x['groupId'])
        #         groups.append(group_name)

        generated_refresh_token = uuid.uuid4()
        generated_refresh_token = str(generated_refresh_token).replace('-', '')

        expr_in_payload = (datetime.utcnow() + timedelta(
            minutes=int(ACCESS_TOKEN_EXPIRY_MINUTES)))  # Don't add redis expr here, use like this.
        expr_in_payload = expr_in_payload.timestamp()  # Timestamp format '1670440005'

        payload = dict(
            aud=AUDIENCE,
            expr=int(expr_in_payload),
            iss=os.environ.get('FUSIONAUTH_URL'),
            sub=str(user.id),
            email=user.email,
            username=user.user_name,
            verified=user.verified,
            user_status=True,
            avatar_url='',
            first_name=user.first_name,
            last_name=user.last_name,
            full_name=full_name,
            roles=roles,
            groups=groups,
            created_at=int(created_at.timestamp()),
            last_login_at=int(last_login_at.timestamp()) if last_login_at else None,
            last_update_at=int(update_at.timestamp()) if update_at else None,
        )
        access_token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")
        payload['refreshToken'] = generated_refresh_token  # Dont send in payload jwt.encode
        client.set_refresh_token(payload)  # write data to Redis

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
            encrypted_password = self.aes.encrypt_str(raw=user_info.password)

            if response := crud.get_user_login(db=db, email=user_info.email, password=str(encrypted_password)):
                return self._cast_login_model(response)
            else:
                raise InvalidCredentialsError('failed login')
        except Exception as e:
            log.error(e)
            raise e

    def signup(self, db, user: UserRequest) -> User:
        log.info("zeauth")
        try:
            encrypted_password = self.aes.encrypt_str(raw=user.password)
            log.info(f"encrypted_password {encrypted_password}")

            user_resp = crud.create_user(db, user={
                "email": user.email,
                "user_name": user.username,
                "password": str(encrypted_password),
                "verified": False,
                "user_status": True,
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

            reset_password_url = f"https://zekoder.netlify.app/auth/resetpassword?token={reset_key}"
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

            encrypted_password = self.aes.encrypt_str(raw=reset_password.new_password)
            user = crud.get_user_by_email(db, email=email)

            res = crud.reset_user_password(db, password=str(encrypted_password), user_id=user.id)
            log.info(res.email)
            if response := crud.get_user_login(db=db, email=email, password=str(encrypted_password)):
                return self._cast_login_model(response)
        except Exception as err:
            log.error(f"Exception: {err}")
            raise err

    async def resend_confirmation_email(self, user_info):
        self.setup_fusionauth()
        try:
            resp = self.fusionauth_client.retrieve_user_by_email(user_info.username)
            if resp.status != 200:
                raise UserNotFoundError(f"User '{user_info.username}' not in system")
            user = resp.success_response['user']

            self.fusionauth_client.resend_email_verification(user_info.username)

            confirm_email_key = hash(uuid.uuid4().hex)
            set_redis(confirm_email_key, user_info.username)
            confirm_email_url = f"https://zekoder.netlify.app/auth/confirm-email?token={confirm_email_key}"
            directory = os.path.dirname(__file__)
            with open(os.path.join(directory, "../../index.html"), "r", encoding="utf-8") as index_file:
                email_template = index_file.read() \
                    .replace("{{first_name}}", user["firstName"]) \
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

    def verify_email(self, email_verify: ConfirmationEmailVerifySchema):
        self.setup_fusionauth()
        try:
            try:
                email = get_redis(email_verify.token)
            except Exception as err:
                log.error(f"redis err: {err}")
                raise IncorrectResetKeyError(f"Token {email_verify.token} is incorrect!") from err

            user = self.fusionauth_client.retrieve_user_by_email(email)
            if user.status == 200:
                self.fusionauth_client.verify_email(user.success_response['user']['id'])

            return "Email Verified!"
        except Exception as err:
            log.error(f"Exception: {err}")
            raise err

    def get_user(self, user_ids: List[str]):
        self.setup_fusionauth()
        try:
            user_info = self.fusionauth_client.search_users_by_ids(user_ids)
            if user_info.status == 200:
                users_list = user_info.success_response['users']
                return {
                    "total": user_info.success_response['total'],
                    "users": [self._cast_user_model(user) for user in users_list]
                }
            else:
                raise NotExistingResourceError()
        except Exception as err:
            error_template = "get_user Exception: An exception of type {0} occurred. error: {1}"
            log.error(error_template.format(type(err).__name__, str(err)))
            raise err

    def verify(self, token: str):
        try:
            user = jwt.decode(bytes(token, 'utf-8'), JWT_SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE)

            if not user.get('email'):
                error_template = "ZeAuth Token verify:  An exception of type {0} occurred. error: {1}"
                log.error(user)
                raise InvalidTokenError('failed token verification')

            return User(
                id=str(user.get('sub')),
                roles=user.get('roles'),
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
                update_at=user.get('last_update_at')
            )

        except Exception as err:
            error_template = "ZeAuth Token verify:  An exception of type {0} occurred. error: {1}"
            log.error(error_template.format(type(err).__name__, str(err)))
            log.debug(err)
            raise InvalidTokenError('failed token verification') from err

    def refreshtoken(self, token: str):
        REDIS_KEY_PREFIX = os.environ.get('REDIS_KEY_PREFIX')

        generated_refresh_token = uuid.uuid4()
        generated_refresh_token = str(generated_refresh_token).replace('-', '')

        try:
            if client.get_refresh_token(f"{REDIS_KEY_PREFIX}-{token}",
                                        "map_refresh_token"):  # Search for the key if it is exists
                payload = client.hgetall_redis_refresh_payload(
                    f"{REDIS_KEY_PREFIX}-{token}")  # Get data from Redis with refresh token
                if payload:
                    # new access_token generated from valid refresh_token request
                    new_access_token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")
                    payload['refreshToken'] = generated_refresh_token  # Dont send in payload jwt.encode
                    client.set_refresh_token(payload)  # write data to Redis
                    client.del_refresh_token(
                        f"{REDIS_KEY_PREFIX}-{token}")  # delete previous refresh_token key and the data
                    return {'accessToken': new_access_token, 'refreshToken': payload['refreshToken']}
                else:
                    return {'No Redis Data exists !'}
            else:
                raise InvalidTokenError('failed refresh token request')
        except Exception as err:
            log.error(err)
            raise err

    def zeauth_bootstrap(self):
        log.info("zeauth_bootstrap...")
        if ProviderFusionAuth.admin_user_created:
            return
        try:
            db = get_db().__next__()
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
        except Exception as ex:
            log.error("unable to bootstrap")
            log.error(ex)
            return None
        try:

            # creating default roles
            for resource in ROLE_RESOURCE:
                for action in ROLE_ACTIONS:
                    db = get_db().__next__()
                    role_name = f"{APP_NAME}-{resource}-{action}"
                    try:
                        role_description = f"{APP_NAME} action {action} for {resource} "
                        db_role = crud.create_role(db,
                                                   role_create=RoleBaseSchema(name=role_name, description=role_description))
                        log.info(f"role: {role_name} created..")
                    except IntegrityError as err:
                        log.info(f"role {role_name} already created")
                    except Exception as err:
                        log.error("unable to bootstrap")
                        log.error(err)
                        return None

            # creating default groups
            groups = {}
            for group in DEFAULT_GROUPS:
                db = get_db().__next__()
                try:
                    db_group = crud.create_group(db, group_create=GroupBaseSchema(name=group['name'],
                                                                            description=group['description']))
                    groups['group_id'] = db_group.id
                    log.info(f"group: {group['name']} created..")
                except IntegrityError as err:
                    log.info(f"group {group['name']} already created")
                except Exception as err:
                    log.error("unable to bootstrap")
                    log.error(err)
                    return None

            # groups roles
            db = get_db().__next__()
            admin_group = crud.get_group_by_name(db, name='admin')
            db = get_db().__next__()
            db_roles = crud.get_roles(db)

            for role in db_roles:
                db = get_db().__next__()
                try:
                    group_role = crud.create_groups_role(db, GroupsRoleBase(roles_id=role.id, groups_id=admin_group.id))
                    log.info(f"groups role: {group_role.id} created..")
                except IntegrityError as err:
                    log.info(f"groups role already created")
                except Exception as err:
                    log.error("unable to bootstrap")
                    log.error(err)
                    return None

            login = UserLoginSchema(email=DEFAULT_ADMIN_EMAIL, password=DEFAULT_ADMIN_PASSWORD)
            db = get_db().__next__()
            admin_user = self.login(login, db)
            log.info(admin_user)
            admin_user_id = admin_user.uid
            db = get_db().__next__()
            try:
                group_user = crud.create_groups_user(db, GroupsUserBase(user_id=admin_user_id, groups_id=admin_group.id))
                log.info(f"groups user: {group_user.id} created..")
            except IntegrityError as err:
                log.info(f"groups user already created")
            except Exception as err:
                log.error("unable to bootstrap")
                log.error(err)
                return None

        except Exception as err:
            error_template = "zeauth_bootstrap: An exception of type {0} occurred. error: {1}"
            log.error(error_template.format(type(err).__name__, str(err)))

        ProviderFusionAuth.admin_user_created = True
