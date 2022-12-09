import os
from core import log
import redis
from dotenv import load_dotenv

load_dotenv()
class SocialProviderConfig:
    def __init__(self, provider_name):
        self.provider_name = provider_name
        self.config = {}

    def set_config(self, config_value: dict):
        self.config = config_value

    def get_config(self):
        return self.config


class SocialProviderConfigFactory:
    @staticmethod
    def create_config(provider_name):
        return SocialProviderConfig(provider_name)


# Create a config for a social providers
config_google = SocialProviderConfigFactory.create_config('google')
config_facebook = SocialProviderConfigFactory.create_config('facebook')
# Set a configuration value
config_google.set_config({
    "redirect_url": os.environ.get('GOOGLE_REDIRECT_URL'),
    "app_id": os.environ.get('GOOGLE_APP_ID'),
    "client_secret": os.environ.get('GOOGLE_CLIENT_SECRET'),
    "response_type": "code",
    "url_auth": "https://accounts.google.com/o/oauth2/v2/auth?",
    "scope": "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile",
    "grant_type": "authorization_code"
})





