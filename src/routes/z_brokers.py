import os
from fastapi import FastAPI, Request, APIRouter
from core import log
from starlette.responses import RedirectResponse
from business.providers.fusionauth import ProviderFusionAuth
import requests
from core.types import ZKModel
from dotenv import load_dotenv
import json
import jwt
from requests_oauthlib import OAuth1Session

load_dotenv()
router = APIRouter()

model = ZKModel(**{
    "name": 'z_broker',
    "plural": 'z_brokers',
    "permissions": {
        'read': ['zk-zeauth-read'],
        'list': ['zk-zeauth-list'],
        'create': ['zk-zeauth-create'],
        'update': ['zk-zeauth-update'],
        'delete': ['zk-zeauth-delete']
    }
})


@router.get('/google', tags=[model.name], status_code=307, response_class=RedirectResponse)
async def google():
    try:
        redirect_url = os.environ.get('GOOGLE_REDIRECT_URL')
        app_id = os.environ.get('GOOGLE_APP_ID')
        response_type = 'code'
        scope = 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile'
        url = f'https://accounts.google.com/o/oauth2/v2/auth?' \
              f'client_id={app_id}&redirect_uri={redirect_url}&response_type={response_type}&scope={scope}'
        return url
    except Exception as e:
        log.error(e)
        raise e


@router.get('/google/callback', tags=[model.name], status_code=307, response_class=RedirectResponse)
async def call_back_google(request: Request):
    try:
        code = request.query_params['code']
        google_client_id = os.environ.get('GOOGLE_APP_ID')
        client_secret = os.environ.get('GOOGLE_CLIENT_SECRET')
        google_redirect_uri = os.environ.get('GOOGLE_REDIRECT_URL')
        frontend_redirect_url = os.environ.get('FRONTEND_REDIRECT_URL')
        aud = os.environ.get('GOOGLE_APP_ID')
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        data = f'code={code}' \
               f'&client_id={google_client_id}' \
               f'&client_secret={client_secret}' \
               f'&redirect_uri={google_redirect_uri}' \
               f'&grant_type=authorization_code'

        response = requests.post('https://oauth2.googleapis.com/token', headers=headers, data=data)
        data = response.json()
        access_token = data['id_token']
        data_jwt = jwt.decode(access_token, audience=aud, options={"verify_signature": False})
        result = ProviderFusionAuth._cast_login_model_new(data_jwt, {'google': data_jwt})
        result = result.json()
        url = f"{frontend_redirect_url}?result={result}"
        return url
    except Exception as e:
        log.error(e)
        raise e


@router.get('/facebook', tags=[model.name], status_code=307, response_class=RedirectResponse)
async def facebook():
    try:
        redirect_url = os.environ.get('FACEBOOK_REDIRECT_URL')
        app_id = os.environ.get('FACEBOOK_APP_ID')
        scope = 'email'  # IMPORTANT: IEven if you have given the permissions(public_profile, email) from within the app,
        # the e-mail address will not be returned to you. Scope must be used in the link to get this.
        url = f'https://www.facebook.com/v15.0/dialog/oauth?' \
              f'client_id={app_id}&redirect_uri={redirect_url}&scope={scope}'
        return url
    except Exception as e:
        log.error(e)
        raise e


@router.get('/facebook/callback', tags=[model.name], status_code=307, response_class=RedirectResponse)
async def call_back(request: Request):
    try:
        code = request.query_params['code']
        facebook_client_id = os.environ.get('FACEBOOK_APP_ID')
        facebook_client_secret = os.environ.get('FACEBOOK_CLIENT_SECRET')
        facebook_redirect_uri = os.environ.get('FACEBOOK_REDIRECT_URL')
        frontend_redirect_url = os.environ.get('FRONTEND_REDIRECT_URL')
        fields = "id, first_name, last_name, name, picture, email"
        headers = {
            'Content-Type': 'application/json',
        }
        data_access = f'code={code}' \
                      f'&client_id={facebook_client_id}' \
                      f'&client_secret={facebook_client_secret}' \
                      f'&redirect_uri={facebook_redirect_uri}'
        access_data = requests.post('https://graph.facebook.com/v15.0/oauth/access_token',
                                    headers=headers,
                                    data=data_access)
        access = access_data.json()
        access_token = access['access_token']
        data_user = f'access_token={access_token}' \
                    f'&fields={fields}'
        user_data = requests.post('https://graph.facebook.com/v15.0/oauth/access_token',
                                  headers=headers,
                                  data=data_user)
        user = user_data.json()
        result = ProviderFusionAuth._cast_login_model_new(user, {'facebook': user})
        result = result.json()
        url = f"{frontend_redirect_url}?result={result}"
        return url
    except Exception as e:
        log.error(e)
        raise e


def twitter_get_oauth_request_token():
    try:
        request_token = OAuth1Session(client_key=os.environ.get('TWITTER_CONSUMER_KEY'),
                                      client_secret=os.environ.get('TWITTER_CONSUMER_SECRET'),
                                      callback_uri=os.environ.get('TWITTER_REDIRECT_URL')
                                      )
        url = 'https://api.twitter.com/oauth/request_token'
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


def get_access_token(oauth_token, oauth_token_secret, verifier):
    try:
        request_token = OAuth1Session(client_key=os.environ.get('TWITTER_CONSUMER_KEY'),
                                      client_secret=os.environ.get('TWITTER_CONSUMER_SECRET'),
                                      resource_owner_key=oauth_token,
                                      resource_owner_secret=oauth_token_secret,
                                      verifier=verifier
                                      )
        url = 'https://api.twitter.com/oauth/access_token'
        access_token_data = request_token.post(url)
        access_token_list = str.split(access_token_data.text, '&')
        access_token_key = str.split(access_token_list[0], '=')[1]
        access_token_secret = str.split(access_token_list[1], '=')[1]
        return access_token_key, access_token_secret
    except Exception as e:
        log.error(e)
        raise e


def get_twitter_json(access_token_key, access_token_secret):
    try:
        oauth_user = OAuth1Session(client_key=os.environ.get('TWITTER_CONSUMER_KEY'),
                                   client_secret=os.environ.get('TWITTER_CONSUMER_SECRET'),
                                   resource_owner_key=access_token_key,
                                   resource_owner_secret=access_token_secret)
        url_user = 'https://api.twitter.com/1.1/account/verify_credentials.json'
        params = {"include_email": 'true'}
        user_data = oauth_user.get(url_user, params=params)
        return user_data.json()
    except Exception as e:
        log.error(e)
        raise e


def user_name_from_twitter(name, screen_name):
    try:
        if name is not '' or screen_name is not '':
            name_data = name.split(' ')
            if len(name_data) > 1:
                first_name, last_name = name_data
            else:
                if name:
                    first_name = name
                    last_name = ""
                else:
                    first_name = screen_name
                    last_name = ""
        else:
            first_name = "Anonymous"
            last_name = ""
        return first_name, last_name
    except Exception as e:
        log.error(e)
        raise e


@router.get('/twitter', tags=[model.name], status_code=307, response_class=RedirectResponse)
async def twitter():
    try:
        if len(twitter_get_oauth_request_token()) > 1:
            oauth_token, oauth_token_secret = twitter_get_oauth_request_token()
        else:
            oauth_token = None
            oauth_token_secret = None
        url = f'https://api.twitter.com/oauth/authorize?oauth_token={oauth_token}' \
              f'&oauth_token_secret={oauth_token_secret}' \
              f'&oauth_callback_confirmed=true'
        return url
    except Exception as e:
        log.error(e)
        raise e


@router.get('/twitter/callback', tags=[model.name], status_code=307, response_class=RedirectResponse)
async def call_back_twitter(request: Request):
    frontend_redirect_url = os.environ.get('FRONTEND_REDIRECT_URL')
    verifier = request.query_params['oauth_verifier']
    oauth_token = request.query_params['oauth_token']
    try:
        oauth_token_secret = twitter_get_oauth_request_token()[1]
        access_token_key, access_token_secret = get_access_token(oauth_token, oauth_token_secret, verifier)
        twitter_data_person = get_twitter_json(access_token_key, access_token_secret)
        result = ProviderFusionAuth._cast_login_model_new(twitter_data_person, {'twitter': twitter_data_person})
        result = result.json()
        url = f"{frontend_redirect_url}?result={result}"
        return url
    except Exception as e:
        log.error(e)
        raise e
