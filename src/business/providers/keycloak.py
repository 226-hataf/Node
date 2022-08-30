import email
import json
import requests
from core import log
import os
from business.models.users import User
from business.providers.base import DuplicateEmailError, Provider
from keycloak import KeycloakAdmin, KeycloakOpenID, KeycloakPostError
from business.models.users import *
from .base import *


class ProviderKeycloak(Provider):
    admin_user_created = None

    def _cast_login_model(self, response: dict, username):
        return LoginResponseModel(
            user=User(email=username, id=response['session_state']),
            uid=response['session_state'],
            accessToken=response['access_token'],
            refreshToken=response['refresh_token'],
            expirationTime=response['expires_in'],
        )
    def __init__(self) -> None:

        self.keycloak_admin = KeycloakAdmin(
            server_url="https://accounts.dev.zekoder.com",
            client_id=os.environ.get('CLIENT_ID'),
            realm_name=os.environ.get('REALM_NAME'),
            client_secret_key=os.environ.get('SECRET')
        )
        self.token = self.keycloak_admin.token
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
                log.error(f"user <{ os.environ.get('DEFAULT_ADMIN_EMAIL')}> already exists")

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

            response = requests.put(f"{os.environ.get('KEYCLOAK_URL')}/admin/realms/{os.environ.get('REALM_NAME')}", headers=headers, json=password_policy)
        except Exception as e:
            raise e

    def _create_user(self, email: str, username: str, firstname: str, lastname: str, enabled: bool=True) -> str:
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

    def signup(self, user: User)-> User:
        # check ifuser exists
        # if exists raises DuplicateEmailError error
        # if not, create the new user disabled
        # TODO: send verification email with verfification link
        
        try:
            created_user = self._create_user(email=user.email, username=user.email, firstname=user.first_name, lastname=user.last_name)
            # Send Verify Email
            # response = self.keycloak_admin.send_verify_email(user_id='user_id_keycloak')
            log.info(f'sucessfully created new user: {created_user}')
            return Provider._enrich_user(user)
        except Exception as e:
            raise DuplicateEmailError(f"<{user.email}> already exists")

    def login(self, user_info):
        try:
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            data = {
                'username': user_info.email,
                'password': user_info.password,
                'client_id': os.environ.get('CLIENT_ID'),
                'grant_type': 'password',
                'client_secret': os.environ.get('SECRET')
            }
            response = requests.post(
                f"{os.environ.get('KEYCLOAK_URL')}/realms/{os.environ.get('REALM_NAME')}/protocol/openid-connect/token",
                headers=headers, data=data)
            if response.status_code == 200:
                return self._cast_login_model(json.loads(response.content.decode()), user_info.email)
            log.debug(response.json()['error_description'])
            raise InvalidCredentialsError('failed login')
        except Exception as e:
            raise e
