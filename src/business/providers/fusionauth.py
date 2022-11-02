import os
from business.providers.base import Provider
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

    def login(self, user_info):
        self.setup_fusionauth()

        try:
            request = {
                "applicationId": os.environ.get('applicationId'),
                "loginId": f'{user_info.email}',
                "password": f'{user_info.password}'
            }
            response = self.fusionauth_client.login(request)
            if response.was_successful():
                ip_address = requests.get('https://api64.ipify.org?format=json').json()
                return {"data": response.success_response, "ip": ip_address["ip"]}
            else:
                return "Criteria does not match !"
        except Exception as e:
            log.error(e)
            raise e

    def signup(self, user: User):
        self.setup_fusionauth()
        try:
            request = {
                "applicationId": os.environ.get('applicationId'),
                "user": {
                    "email": f'{user.email}',
                    "password": f'{user.password}'
                }
            }
            response = self.fusionauth_client.create_user(request)
            if response.was_successful():
                return response.success_response
            else:
                #return {"data": response.error_response, "email": f'{user.email}'}
                return response.error_response
        except Exception as e:
            log.error(e)
            raise e
