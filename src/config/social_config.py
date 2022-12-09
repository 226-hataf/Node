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
config_twitter = SocialProviderConfigFactory.create_config('twitter')

# Set a configuration value
config_google.set_config({
    "redirect_url": os.environ.get('GOOGLE_REDIRECT_URL'),
    "app_id": os.environ.get('GOOGLE_APP_ID'),
    "client_secret": os.environ.get('GOOGLE_CLIENT_SECRET'),
    "response_type": "code",
    "url_auth": "https://accounts.google.com/o/oauth2/v2/auth?",
    "url_token": "https://oauth2.googleapis.com/token",
    "scope": "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile",
    "grant_type": "authorization_code"
})
config_facebook.set_config({
    "redirect_url": os.environ.get('FACEBOOK_REDIRECT_URL'),
    "app_id": os.environ.get('FACEBOOK_APP_ID'),
    "client_secret": os.environ.get('FACEBOOK_CLIENT_SECRET'),
    "url_auth": "https://www.facebook.com/v15.0/dialog/oauth?",
    "url_access_token": "https://graph.facebook.com/v15.0/oauth/access_token",
    "url_me": "https://graph.facebook.com/me",
    "fields": "id, first_name, last_name, name, picture, email",
    "scope": "public_profile,email"  # IMPORTANT: IEven if you have given the permissions(public_profile, email)
    # from within the app,
    # the e-mail address will not be returned to you.
    # Scope must be used in the link to get this.
})
config_twitter.set_config({
    "client_key": os.environ.get('TWITTER_CONSUMER_KEY'),
    "client_secret": os.environ.get('TWITTER_CONSUMER_SECRET'),
    "callback_uri": os.environ.get('TWITTER_REDIRECT_URL'),
    "url_request_token": "https://api.twitter.com/oauth/request_token",
    "url_access_token": "https://api.twitter.com/oauth/access_token",
    "url_verify_credentials": "https://api.twitter.com/1.1/account/verify_credentials.json",
    "url_oauth_token": "https://api.twitter.com/oauth/authorize?oauth_token",
})
