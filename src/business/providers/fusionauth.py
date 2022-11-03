import os
from business.providers.base import *
from fusionauth.fusionauth_client import FusionAuthClient
from business.models.users import User
from core import log
import requests


class ProviderFusionAuth(Provider):

    def __init__(self) -> None:
        self.fusionauth_client = None
        self.setup_fusionauth()
        super().__init__()

    def setup_fusionauth(self):
        self.fusionauth_client = FusionAuthClient(
            os.environ.get('FUSIONAUTH_APIKEY'),
            os.environ.get('FUSIONAUTH_URL')
        )

    def login(self, user_info: str):
        self.setup_fusionauth()
        try:
            response = self.fusionauth_client.login({
                "applicationId": os.environ.get('applicationId'),
                "loginId": f'{user_info.email}',
                "password": f'{user_info.password}'
            })
            if response.was_successful():
                ip_address = requests.get('https://api64.ipify.org?format=json').json()
                return {"data": response.success_response, "ip": ip_address["ip"]}
            else:
                return "Criteria does not match !"
        except Exception as e:
            log.error(e)
            raise e

    async def signup(self, user: User) -> User:
        self.setup_fusionauth()
        try:
            if len(user.password) >= 8 and 'string' not in user.password:
                user_create = {
                    'user': {
                        "email": user.email,
                        "password": user.password,
                        "firstName": user.first_name,
                        "lastName": user.last_name,
                    }
                }
                response = self.fusionauth_client.create_user(user_create)
                if response.success_response:
                    log.info(f'successfully created new user: {user_create}')
                    return Provider._enrich_user(user)
                else:
                    raise DuplicateEmailError()
            else:
                raise PasswordPolicyError()
        except Exception as e:
            log.debug(e)
            raise e