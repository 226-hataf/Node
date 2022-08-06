import email

import requests
from core import log
import os
from business.models.users import User
from business.providers.base import DuplicateEmailError, Provider
from keycloak import KeycloakAdmin, KeycloakOpenID, KeycloakPostError


class ProviderKeycloak(Provider):
    admin_user_created = None

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
            
            length = f"length({int(os.environ.get('LENGTH'))})"
            specialChars = f"specialChars({int(os.environ.get('SPECIAL_CHARACTERS'))})"
            upperCase = f"upperCase({int(os.environ.get('UPPERCASE'))})"
            digits = f"digits({int(os.environ.get('DIGITS'))})"

            password_policy = {"passwordPolicy": f"{length} and {specialChars} and {upperCase} and {digits}"}

            self.update_password_policy(password_policy)

            try:
                self._create_user(**default_admin)
            except:
                log.error(f"user <{ os.environ.get('DEFAULT_ADMIN_EMAIL')}> already exists")

            ProviderKeycloak.admin_user_created = True


    def update_password_policy(self, password_policy: dict) -> str:
        try:
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