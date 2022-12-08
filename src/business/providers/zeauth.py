from datetime import datetime, timedelta
import os
import json
import uuid
from business.providers.base import *
from fusionauth.fusionauth_client import FusionAuthClient
from business.models.users import User, LoginResponseModel
from sqlalchemy.exc import IntegrityError
from core import log, crud
import requests
from redis_service.redis_service import set_redis, get_redis, hset_redis, hget_redis, hgetall_redis, del_key
from email_service.mail_service import send_email
from ..models.users import ResetPasswordVerifySchema, ConfirmationEmailVerifySchema
from core.AES import AesStringCipher
from core.AES import AesStringCipher
import jwt

FUSIONAUTH_APIKEY = os.environ.get('FUSIONAUTH_APIKEY')
APPLICATION_ID = os.environ.get('applicationId')
FUSIONAUTH_URL = os.environ.get('FUSIONAUTH_URL')
AES_KEY = os.environ.get('AES_KEY')



class ProviderFusionAuth(Provider):

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

    def list_users(self, page: str, page_size: int, search: str):
        headers = {'Authorization': FUSIONAUTH_APIKEY}
        response = requests.get(f'{FUSIONAUTH_URL}/api/user/search?queryString=*', headers=headers)

        if response.status_code != 200:
            return [], 0, 0
        res = response.json()
        users_data = [self._cast_user_model(user) for user in res['users']]
        return users_data, int(page) + 1, res['total']

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
            user_name=user.user_name,
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
        jwt_secret_key = os.environ['JWT_SECRET_KEY']
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

        expr = 60 * int(ACCESS_TOKEN_EXPIRY_MINUTES)  # Redis is reading from here, don't touch this and use this in Redis
        expr_in_payload = (datetime.utcnow() + timedelta(minutes=int(ACCESS_TOKEN_EXPIRY_MINUTES))) # Don't add redis expr here, use like this.
        expr_in_payload = expr_in_payload.timestamp()  # Timestamp format '1670440005'

        user_id = generated_user_id
        uid = user_id
        verified = True

        last_login_at = "Not Created"
        last_update_at = "Not Created"
        created_at = datetime.utcnow()

        roles = []  # This will come from DB
        groups = []  # This will come from DB

        payload = dict(
            aud='ZeAuth',
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
            last_login_at=last_login_at,
            last_update_at=last_update_at,
        )
        try:
            access_token = jwt.encode(payload, jwt_secret_key, algorithm="HS256")
            ip_address = "85.65.125.458"  # for just now
            hset_redis(f"{generated_refresh_token}",
                       f"{generated_refresh_token}",
                       f"{payload['aud']}",
                       f"{ip_address}",
                       f"{payload['iss']}",
                       f"{payload['sub']}",
                       f"{payload['email']}",
                       f"{payload['username']}",
                       f"{payload['verified']}",
                       f"{payload['avatar_url']}",
                       f"{payload['first_name']}",
                       f"{payload['last_name']}",
                       f"{payload['full_name']}",
                       f"{payload['roles']}",
                       f"{payload['groups']}",
                       f"{expr}")
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
        jwt_secret_key = os.environ['JWT_SECRET_KEY']

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

        expr = 60 * int(ACCESS_TOKEN_EXPIRY_MINUTES)  # Redis is reading from here, don't touch this and use this in Redis
        expr_in_payload = (datetime.utcnow() + timedelta(minutes=int(ACCESS_TOKEN_EXPIRY_MINUTES)))  # Don't add redis expr here, use like this.
        expr_in_payload = expr_in_payload.timestamp()  # Timestamp format '1670440005'

        payload = dict(
            aud='ZeAuth',
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
        access_token = jwt.encode(payload, jwt_secret_key, algorithm="HS256")
        ip_address = "85.65.125.458"  # for just now
        hset_redis(f"{generated_refresh_token}",
                   f"{generated_refresh_token}",
                   f"{payload['aud']}",
                   f"{ip_address}",
                   f"{payload['iss']}",
                   f"{payload['sub']}",
                   f"{payload['email']}",
                   f"{payload['username']}",
                   f"{payload['verified']}",
                   f"{payload['avatar_url']}",
                   f"{payload['first_name']}",
                   f"{payload['last_name']}",
                   f"{payload['full_name']}",
                   f"{payload['roles']}",
                   f"{payload['groups']}",
                   f"{expr}")

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

            if response := crud.get_user_by_email(db=db, email=user_info.email, password=str(encrypted_password)):
                # return self._cast_user(response)
                return self._cast_login_model(response)
            else:
                raise InvalidCredentialsError('failed login')
        except Exception as e:
            log.error(e)
            raise e

    async def signup(self, user: User, db) -> User:
        log.info("zeauth")
        try:
            encrypted_password = self.aes.encrypt_str(raw=user.password)
            log.info(f"encrypted_password {encrypted_password}")
            log.info(type(encrypted_password))

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

    async def reset_password(self, user_info):
        self.setup_fusionauth()
        try:
            client_response = self.fusionauth_client.retrieve_user_by_email(user_info.username)
            if not client_response.was_successful():
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

    def reset_password_verify(self, reset_password: ResetPasswordVerifySchema):
        self.setup_fusionauth()
        try:
            try:
                email = get_redis(reset_password.reset_key)
            except Exception as err:
                log.error(f"redis err: {err}")
                raise IncorrectResetKeyError(f"Reset key {reset_password.reset_key} is incorrect!") from err

            res = self.fusionauth_client.forgot_password({
                "applicationId": APPLICATION_ID,
                "loginId": email
            })
            change_password_id = res.success_response["changePasswordId"]
            res2 = self.fusionauth_client.change_password(change_password_id,
                                                          {'password': f'{reset_password.new_password}'})
            if res2.was_successful():
                response = self.fusionauth_client.login({
                    "applicationId": APPLICATION_ID,
                    "loginId": f'{email}',
                    "password": f'{reset_password.new_password}'
                })
                if response.was_successful():
                    return self._cast_login_model(response.success_response)
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
            self.setup_fusionauth()

            validate_jwt = self.fusionauth_client.validate_jwt(token)
            if validate_jwt.status != 200:
                error_template = "fusionauth verify:  An exception of type {0} occurred. error: {1}"
                log.error(error_template.format(type(validate_jwt).__name__, str(validate_jwt)))
                raise InvalidTokenError('failed token verification')

            resp = self.fusionauth_client.retrieve_user_by_email(validate_jwt.success_response['jwt']['email'])
            log.info(resp.success_response)
            return self._cast_user_model(resp.success_response['user'])
        except Exception as err:
            error_template = "fusionauth verify:  An exception of type {0} occurred. error: {1}"
            log.error(error_template.format(type(err).__name__, str(err)))
            log.debug(err)
            raise InvalidTokenError('failed token verification') from err

    def refreshtoken(self, token: str):
        jwt_secret_key = os.environ.get('JWT_SECRET_KEY')
        REDIS_KEY_PREFIX = os.environ.get('REDIS_KEY_PREFIX')

        REFRESH_TOKEN_EXPIRY_MINUTES = os.environ.get("REFRESH_TOKEN_EXPIRY_MINUTES")
        redis_expr = 60 * int(REFRESH_TOKEN_EXPIRY_MINUTES) # Redis is reading from here, don't touch this and use this in Redis
        expr_in_payload = (datetime.utcnow() + timedelta(minutes=int(REFRESH_TOKEN_EXPIRY_MINUTES)))  # Don't add redis expr here, use like this.
        expr_in_payload = expr_in_payload.timestamp()  # Timestamp format '1670440005'

        generated_refresh_token = uuid.uuid4()
        generated_refresh_token = str(generated_refresh_token).replace('-', '')
        ip_address = "85.65.125.458" # This will be change !!!!

        try:
            # Search for the key if it is exists
            if hget_redis(f"{REDIS_KEY_PREFIX}-{token}", "map_refresh_token"):
                # Get data from Redis with refresh token
                data = hgetall_redis(f"{REDIS_KEY_PREFIX}-{token}")
                if data:
                    data_dict = {k.decode(): v.decode() for k, v in data.items()}
                    payload = dict(
                        aud="ZeAuth",
                        expr=int(expr_in_payload),
                        iss=os.environ.get("FUSIONAUTH_URL"),
                        sub=data_dict["map_sub"],
                        email=data_dict["map_email"],
                        username=data_dict["map_username"],
                        verified=data_dict["map_verified"],
                        avatar_url=data_dict["map_avatar_url"],
                        first_name=data_dict["map_first_name"],
                        last_name=data_dict["map_last_name"],
                        full_name=data_dict["map_full_name"],
                        roles=data_dict["map_roles"],
                        groups=data_dict["map_groups"]
                    )
                    # new access_token generated from valid refresh_token request
                    new_access_token = jwt.encode(payload, jwt_secret_key, algorithm="HS256")
                    # new access_token data added to Redis
                    hset_redis(f"{generated_refresh_token}",
                               f"{generated_refresh_token}",
                               f"ZeAuth",
                               f"{ip_address}",
                               f"{os.environ.get('FUSIONAUTH_URL')}",
                               f"{data_dict['map_sub']}",
                               f"{data_dict['map_email']}",
                               f"{data_dict['map_username']}",
                               f"{data_dict['map_verified']}",
                               f"{data_dict['map_avatar_url']}",
                               f"{data_dict['map_first_name']}",
                               f"{data_dict['map_last_name']}",
                               f"{data_dict['map_full_name']}",
                               f"{data_dict['map_roles']}",
                               f"{data_dict['map_groups']}",
                               f"{redis_expr}")
                    # delete old refresh_token key and the data
                    del_key(f"{REDIS_KEY_PREFIX}-{token}")
                    return {'accessToken': new_access_token, 'refreshToken': generated_refresh_token}
            else:
                raise InvalidTokenError('failed refresh token request')
        except Exception as err:
            log.error(err)
            raise err
