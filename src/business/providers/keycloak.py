import requests
from core import log
import os
import json
from business.models.users import User
from business.providers.base import DuplicateEmailError, Provider
from keycloak import KeycloakAdmin, KeycloakOpenID, KeycloakPostError, KeycloakConnectionError, \
    KeycloakAuthenticationError, KeycloakPutError
from business.models.users import *
from .base import *
from business.providers.base import *
import uuid
from fastapi.responses import JSONResponse
from fastapi import status
from  src.redis_service.redis_service import set_redis, get_redis
from ..models.users import ResetPasswordVerifySchema
from src.email_service.mail_service import send_email


def cast_login_model(response: dict, username):
    return LoginResponseModel(
        user=User(email=username, id=response['session_state']),
        uid=response['session_state'],
        accessToken=response['access_token'],
        refreshToken=response['refresh_token'],
        expirationTime=response['expires_in'],
    )


class ProviderKeycloak(Provider):
    admin_user_created = None

    def __init__(self) -> None:

        self.keycloak_admin = KeycloakAdmin(
            server_url=os.environ.get('KEYCLOAK_URL'),
            client_id=os.environ.get('CLIENT_ID'),
            realm_name=os.environ.get('REALM_NAME'),
            client_secret_key=os.environ.get('SECRET')
        )
        self.token = self.keycloak_admin.token
        self.keycloak_openid = KeycloakOpenID(
            server_url=os.environ.get('KEYCLOAK_URL'),
            client_id=os.environ.get('CLIENT_ID'),
            realm_name=os.environ.get('REALM_NAME'),
            client_secret_key=os.environ.get('SECRET')
        )
        super().__init__()

    def zeauth_bootstrap(self):
        if ProviderKeycloak.admin_user_created:
            return
        else:
            default_admin = {
                "email": os.environ.get('DEFAULT_ADMIN_EMAIL'),
                "username": os.environ.get('DEFAULT_ADMIN_EMAIL'),
                "firstname": "Master",
                "lastname": "Account"
            }

            self.update_password_policy()

            try:
                self._create_user(**default_admin)
            except:
                log.error(f"user <{os.environ.get('DEFAULT_ADMIN_EMAIL')}> already exists")

            ProviderKeycloak.admin_user_created = True

    def update_password_policy(self) -> str:
        try:
            # password policies
            length = f"length({int(os.environ.get('LENGTH'))})"
            specialChars = f"specialChars({int(os.environ.get('SPECIAL_CHARACTERS'))})"
            upperCase = f"upperCase({int(os.environ.get('UPPERCASE'))})"
            digits = f"digits({int(os.environ.get('DIGITS'))})"

            # definiton of password policy
            password_policy = {"passwordPolicy": f"{length} and {specialChars} and {upperCase} and {digits}"}
            headers = {"Authorization": f"Bearer {self.token['access_token']}"}

            response = requests.put(f"{os.environ.get('KEYCLOAK_URL')}/admin/realms/{os.environ.get('REALM_NAME')}",
                                    headers=headers, json=password_policy)
        except Exception as e:
            raise e

    def _create_user(self, email: str, username: str, firstname: str, lastname: str, enabled: bool = True) -> str:
        try:
            return self.keycloak_admin.create_user(
                {"email": email,
                 "username": username,
                 "enabled": enabled,
                 "firstName": firstname,
                 "lastName": lastname,
                 },
                exist_ok=False
            )
        except Exception as e:
            raise DuplicateEmailError('the user is already exists')

    def signup(self, user: User) -> User:
        # check ifuser exists
        # if exists raises DuplicateEmailError error
        # if not, create the new user disabled
        # TODO: send verification email with verfification link

        try:
            created_user = self._create_user(email=user.email, username=user.email, firstname=user.first_name,
                                             lastname=user.last_name)
            # Send Verify Email
            # response = self.keycloak_admin.send_verify_email(user_id='user_id_keycloak')
            log.info(f'sucessfully created new user: {created_user}')
            return Provider._enrich_user(user)
        except Exception as e:
            raise DuplicateEmailError(f"<{user.email}> already exists")

    def login(self, user_info):
        try:
            response = self.keycloak_openid.token(user_info.email, user_info.password, grant_type='password')
            self.keycloak_openid.userinfo(response['access_token'])
            log.info(response)
            if response:
                return cast_login_model(response, user_info.email)
        except KeycloakAuthenticationError as err:
            log.debug(f"Keycloak Authentication Error: {err}")
            raise InvalidCredentialsError('failed login') from err
        except KeycloakConnectionError as err:
            log.error(f"Un-able to connect with Keycloak. Error: {err}")
            raise CustomKeycloakConnectionError(err) from err
        except KeycloakPostError as err:
            log.error(err)
            raise CustomKeycloakPostError(err.error_message) from err
        except Exception as e:
            log.error(e)
            raise e

    async def reset_password(self, user_info):
        try:
            users = self.keycloak_admin.get_users(query={
                "email": user_info.username
            })
            if len(users) == 0:
                raise UserNotFoundError(f"User '{user_info.username}' not in system")

            reset_key = hash(uuid.uuid4().hex)
            set_redis(reset_key, user_info.username)

            reset_password_url = f"dev.zekoder.com/resetpassword/{reset_key}"
            await send_email(
                recipients=[user_info.username],
                subject="Reset Password",
                body=reset_password_url
            )
            return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "email has been sent"})
        except KeycloakConnectionError as err:
            log.error(f"Un-able to connect with Keycloak. Error: {err}")
            raise CustomKeycloakConnectionError(err) from err
        except KeycloakPostError as err:
            log.error(err)
            raise CustomKeycloakPostError(err.error_message) from err
        except Exception as err:
            log.error(err)
            raise err

    def reset_password_verify(self, reset_password: ResetPasswordVerifySchema):
        try:
            email = get_redis(reset_password.reset_key)
            print(email)
            users = self.keycloak_admin.get_users(query={"email": email})
            if users and len(users) == 1:
                self.keycloak_admin.set_user_password(
                    user_id=users[0]["id"],
                    password=reset_password.new_password,
                    temporary=False
                )

            response = self.keycloak_openid.token(email, reset_password.new_password)
            log.info(response)
            if response:
                return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Password has been reset."})
        except KeycloakConnectionError as err:
            log.error(f"Un-able to connect with Keycloak. Error: {err}")
            raise CustomKeycloakConnectionError(err) from err
        except KeycloakPutError as err:
            log.error(err)
            message = json.loads(err.error_message)
            raise CustomKeycloakPutError(message["error_description"]) from err
        except Exception as err:
            log.error(err)
            raise err
