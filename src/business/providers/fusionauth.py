import datetime
import os
import json
import uuid
from business.providers.base import *
from fusionauth.fusionauth_client import FusionAuthClient
from business.models.users import User, LoginResponseModel
from core import log
import requests
from redis_service.redis_service import set_redis, get_redis
from email_service.mail_service import send_email
from ..models.users import ResetPasswordVerifySchema, ConfirmationEmailVerifySchema

FUSIONAUTH_APIKEY = os.environ.get('FUSIONAUTH_APIKEY')
APPLICATION_ID = os.environ.get('applicationId')
FUSIONAUTH_URL = os.environ.get('FUSIONAUTH_URL')


class ProviderFusionAuth(Provider):

    def __init__(self) -> None:
        self.fusionauth_client = None
        self.setup_fusionauth()
        super().__init__()

    def setup_fusionauth(self):
        self.fusionauth_client = FusionAuthClient(FUSIONAUTH_APIKEY, FUSIONAUTH_URL)

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

        last_login_at = datetime.datetime.fromtimestamp(response['lastLoginInstant'] / 1000)
        last_update_at = datetime.datetime.fromtimestamp(response['lastUpdateInstant'] / 1000)
        created_at = datetime.datetime.fromtimestamp(response['insertInstant'] / 1000)

        roles = []
        if len(response['registrations']) != 0:
            roles = response['registrations'][0]['roles']

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
            full_name=full_name
        )

    def _cast_login_model(self, response: dict) -> object:
        full_name = response['user'].get('firstName')
        if response['user'].get('lastName'):
            full_name = f"{full_name} {response['user'].get('lastName')}"
        last_login_at = datetime.datetime.fromtimestamp(response['user']['lastLoginInstant'] / 1000)
        last_update_at = datetime.datetime.fromtimestamp(response['user']['lastUpdateInstant'] / 1000)
        created_at = datetime.datetime.fromtimestamp(response['user']['insertInstant'] / 1000)
        expiration_time = datetime.datetime.fromtimestamp(response['tokenExpirationInstant'] / 1000)

        roles = []
        if len(response['user']['registrations']) != 0:
            roles = response['user']['registrations'][0]['roles']

        return LoginResponseModel(
            user=User(
                id=response['user']['id'],
                email=response['user']['email'],
                username=response['user']['email'],
                verified=response['user']['verified'],
                user_status=response['user']['active'],
                created_at=str(created_at).split(".")[0],
                last_login_at=str(last_login_at).split(".")[0],
                last_update_at=str(last_update_at).split(".")[0],
                first_name=response['user'].get('firstName'),
                last_name=response['user'].get('lastName'),
                roles=roles,
                full_name=full_name
            ),
            uid=response['user']['id'],
            accessToken=response['token'],
            refreshToken=response.get('refreshToken') if response.get('refreshToken') else '',
            expirationTime=str(expiration_time).split(".")[0]
        )

    def login(self, user_info):
        self.setup_fusionauth()
        try:
            response = self.fusionauth_client.login({
                "applicationId": APPLICATION_ID,
                "loginId": f'{user_info.email}',
                "password": f'{user_info.password}'
            })
            if response.was_successful():
                ip_address = requests.get('https://api64.ipify.org?format=json').json()
                return self._cast_login_model(response.success_response)
                # return {"data": response.success_response, "ip": ip_address["ip"]}
            else:
                # return {"e": response.error_response, "s": response.success_response}
                raise InvalidCredentialsError('failed login')
        except Exception as e:
            log.error(e)
            raise e

    async def signup(self, user: User) -> User:
        self.setup_fusionauth()
        try:
            if len(user.password) >= 8 and 'string' not in user.password:
                user_create = {
                    'skipVerification': False,
                    'user': {
                        "email": user.email,
                        "userName": user.email,
                        "password": user.password,
                        "firstName": user.first_name,
                        "lastName": user.last_name,
                    }
                }
                response = self.fusionauth_client.create_user(user_create)
                if response.success_response:
                    user_registration = self.fusionauth_client.register({
                        "skipRegistrationVerification": False,
                        "registration": {"applicationId": APPLICATION_ID}
                    },
                        user_id=response.success_response['user']['id']
                    )
                    log.info(f'successfully created new user: {response.success_response}')
                    return Provider._enrich_user(self._cast_user_model(response.success_response['user']))
                else:
                    raise DuplicateEmailError()
            else:
                raise PasswordPolicyError()
        except Exception as e:
            log.debug(e)
            raise e

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
