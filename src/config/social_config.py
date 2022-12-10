import os
import requests
import jwt
from requests_oauthlib import OAuth1Session
from dotenv import load_dotenv
from core import log

load_dotenv()


class SocialLogin:
    def __init__(self, provider, redirect_url, client_id, client_secret):
        self.provider = provider
        self.redirect_url = redirect_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.get_provider_name()

    def get_provider_name(self):
        return self.provider

    def goto_provider_login_page(self):
        if self.get_provider_name() != 'twitter':
            url_client = f"client_id={self.client_id}&redirect_uri={self.redirect_url}"
            if self.get_provider_name() == 'google':
                url = f"{GoogleLogin().url_auth}" \
                      f"{url_client}" \
                      f"&response_type={GoogleLogin().response_type}" \
                      f"&scope={GoogleLogin().scope}"
                return url
            if self.get_provider_name() == 'facebook':
                url = f"{FacebookLogin().url_auth}" \
                      f"{url_client}" \
                      f"&scope={FacebookLogin().scope}"
                return url
        else:
            if len(TwitterLogin().twitter_get_oauth_request_token()) > 1:
                oauth_token, oauth_token_secret = TwitterLogin().twitter_get_oauth_request_token()
            else:
                oauth_token = None
                oauth_token_secret = None
            url = f"{TwitterLogin().url_oauth_token}={oauth_token}" \
                  f"&oauth_token_secret={oauth_token_secret}" \
                  f"&oauth_callback_confirmed=true"
            return url

    def call_back_provider_data(self, code):
        if self.get_provider_name() != 'twitter':
            url_main = f"code={code}" \
                         f"&client_id={self.client_id}" \
                         f"&client_secret={self.client_secret}" \
                         f"&redirect_uri={self.redirect_url}"

            if self.get_provider_name() == 'google':
                headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
                data = f"{url_main}&grant_type={GoogleLogin().grant_type}"
                response = requests.post(f"{GoogleLogin().url_token}", headers=headers, data=data)
                data = response.json()
                access_token = data['id_token']
                data_jwt = jwt.decode(access_token, audience=self.client_id, options={"verify_signature": False})
                return data_jwt

            if self.get_provider_name() == 'facebook':
                headers = {
                    'Content-Type': 'application/json',
                }
                data = url_main
                access_data = requests.post(f"{FacebookLogin().url_access_token}", headers=headers, data=data)
                log.debug(f"facebook_access_data: {access_data}")
                access = access_data.json()
                access_token = access['access_token']
                data_user = f"access_token={access_token}&fields={FacebookLogin().fields}"
                log.debug(f"facebook_data_user: {data_user}")
                user_data = requests.post(f"{FacebookLogin().url_me}", headers=headers, data=data_user)
                return user_data
        else:
            pass


class GoogleLogin(SocialLogin):
    scope = "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile"
    response_type = "code"
    url_auth = "https://accounts.google.com/o/oauth2/v2/auth?"
    url_token = "https://oauth2.googleapis.com/token"
    grant_type = "authorization_code"

    def __init__(self):
        super().__init__('google',
                         redirect_url=os.environ.get('GOOGLE_REDIRECT_URL'),
                         client_id=os.environ.get('GOOGLE_APP_ID'),
                         client_secret=os.environ.get('GOOGLE_CLIENT_SECRET')
                         )


class FacebookLogin(SocialLogin):
    url_auth = "https://www.facebook.com/v15.0/dialog/oauth?"
    url_access_token = "https://graph.facebook.com/v15.0/oauth/access_token"
    url_me = "https://graph.facebook.com/me"
    fields = "id, first_name, last_name, name, picture, email"
    scope = "public_profile,email"

    def __init__(self):
        super().__init__('facebook',
                         redirect_url=os.environ.get('FACEBOOK_REDIRECT_URL'),
                         client_id=os.environ.get('FACEBOOK_APP_ID'),
                         client_secret=os.environ.get('FACEBOOK_CLIENT_SECRET')
                         )


class TwitterLogin(SocialLogin):
    url_request_token = "https://api.twitter.com/oauth/request_token"
    url_access_token = "https://api.twitter.com/oauth/access_token"
    url_verify_credentials = "https://api.twitter.com/1.1/account/verify_credentials.json"
    url_oauth_token = "https://api.twitter.com/oauth/authorize?oauth_token"

    def __init__(self):
        super().__init__('twitter',
                         redirect_url=os.environ.get('TWITTER_REDIRECT_URL'),
                         client_id=os.environ.get('TWITTER_CONSUMER_KEY'),
                         client_secret=os.environ.get('TWITTER_CONSUMER_SECRET'))

    def twitter_get_oauth_request_token(self):
        try:
            request_token = OAuth1Session(client_key=self.client_id,
                                          client_secret=self.client_secret,
                                          callback_uri=self.redirect_url
                                          )
            url = self.url_request_token
            data = request_token.get(url)
            if data.status_code == 200:
                data_token = str.split(data.text, '&')
                ro_key = str.split(data_token[0], '=')
                ro_secret = str.split(data_token[1], '=')
                resource_owner_key = ro_key[1]
                resource_owner_secret = ro_secret[1]
                return resource_owner_key, resource_owner_secret
            else:
                return {'error': data.status_code}
        except Exception as e:
            log.error(e)
            raise e

    def get_access_token(self, oauth_token, oauth_token_secret, verifier):
        try:
            request_token = OAuth1Session(client_key=self.client_id,
                                          client_secret=self.client_secret,
                                          resource_owner_key=oauth_token,
                                          resource_owner_secret=oauth_token_secret,
                                          verifier=verifier
                                          )
            url = self.url_access_token
            access_token_data = request_token.post(url)
            access_token_list = str.split(access_token_data.text, '&')
            access_token_key = str.split(access_token_list[0], '=')[1]
            access_token_secret = str.split(access_token_list[1], '=')[1]
            return access_token_key, access_token_secret
        except Exception as e:
            log.error(e)
            raise e

    def get_twitter_json(self, access_token_key, access_token_secret):
        try:
            oauth_user = OAuth1Session(client_key=self.client_id,
                                       client_secret=self.client_secret,
                                       resource_owner_key=access_token_key,
                                       resource_owner_secret=access_token_secret)
            url_user = self.url_verify_credentials
            params = {"include_email": 'true'}
            user_data = oauth_user.get(url_user, params=params)
            return user_data.json()
        except Exception as e:
            log.error(e)
            raise e

    def call_back_provider_data(self, oauth_token, verifier):
        oauth_token_secret = self.twitter_get_oauth_request_token()[1]
        access_token_key, access_token_secret = self.get_access_token(oauth_token, oauth_token_secret, verifier)
        twitter_data_person = self.get_twitter_json(access_token_key, access_token_secret)
        return twitter_data_person
