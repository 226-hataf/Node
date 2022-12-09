import os
from fastapi import FastAPI, Request, APIRouter
from config.social_config import config_google, config_facebook, config_twitter
from core import log
from starlette.responses import RedirectResponse
from business.providers.zeauth import ProviderFusionAuth
import requests
from core.types import ZKModel
from dotenv import load_dotenv
import json
import jwt
from requests_oauthlib import OAuth1Session

load_dotenv()
router = APIRouter()

model = ZKModel(**{
    "name": 'broker',
    "plural": 'brokers',
    "permissions": {
        'read': ['zk-zeauth-read'],
        'list': ['zk-zeauth-list'],
        'create': ['zk-zeauth-create'],
        'update': ['zk-zeauth-update'],
        'delete': ['zk-zeauth-delete']
    }
})
frontend_redirect_url = os.environ.get('FRONTEND_REDIRECT_URL')


@router.get('/google', tags=[model.name], status_code=307, response_class=RedirectResponse)
async def google():
    try:
        conf = config_google.get_config()   # get google configs
        url = f"{conf['url_auth']}" \
              f"client_id={conf['app_id']}" \
              f"&redirect_uri={conf['redirect_url']}" \
              f"&response_type={conf['response_type']}" \
              f"&scope={conf['scope']}"
        return url
    except Exception as e:
        log.error(e)
        raise e


@router.get('/google/callback', tags=[model.name], status_code=307, response_class=RedirectResponse)
async def call_back_google(request: Request):
    try:
        code = request.query_params['code']     # Google response code
        conf = config_google.get_config()  # get google configs
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        data = f"code={code}" \
               f"&client_id={conf['app_id']}" \
               f"&client_secret={conf['client_secret']}" \
               f"&redirect_uri={conf['redirect_url']}" \
               f"&grant_type={conf['grant_type']}"
        response = requests.post(f"{conf['url_token']}", headers=headers, data=data)
        data = response.json()
        access_token = data['id_token']
        data_jwt = jwt.decode(access_token, audience=conf['app_id'], options={"verify_signature": False})
        result = ProviderFusionAuth._social_login_model(data_jwt, {'google': data_jwt})
        result = result.json()
        log.debug(f"google: {result}")
        url = f"{frontend_redirect_url}?result={result}"
        return url
    except Exception as e:
        log.error(e)
        raise e


@router.get('/facebook', tags=[model.name], status_code=307, response_class=RedirectResponse)
async def facebook():
    try:
        conf = config_facebook.get_config()     # get facebook configs
        url = f"{conf['url_auth']}" \
              f"client_id={conf['app_id']}" \
              f"&redirect_uri={conf['redirect_url']}" \
              f"&scope={conf['scope']}"
        return url
    except Exception as e:
        log.error(e)
        raise e


@router.get('/facebook/callback', tags=[model.name], status_code=307, response_class=RedirectResponse)
async def call_back(request: Request):
    try:
        code = request.query_params['code']
        conf = config_facebook.get_config()     # get facebook configs
        headers = {
            'Content-Type': 'application/json',
        }
        data_access = f"code={code}" \
                      f"&client_id={conf['app_id']}" \
                      f"&client_secret={conf['client_secret']}" \
                      f"&redirect_uri={conf['redirect_url']}"
        access_data = requests.post(f"{conf['url_access_token']}", headers=headers, data=data_access)
        log.debug(f"facebook_access_data: {access_data}")
        access = access_data.json()
        access_token = access['access_token']
        data_user = f"access_token={access_token}&fields={conf['fields']}"
        log.debug(f"facebook_data_user: {data_user}")
        user_data = requests.post(f"{conf['url_me']}", headers=headers, data=data_user)
        user = user_data.json()
        result = ProviderFusionAuth._social_login_model(user, {'facebook': user})
        result = result.json()
        log.debug(f"facebook_result: {result}")
        url = f"{frontend_redirect_url}?result={result}"
        return url
    except Exception as e:
        log.error(e)
        raise e


def twitter_get_oauth_request_token():
    try:
        conf = config_twitter.get_config()  # get twitter configs
        request_token = OAuth1Session(client_key=conf['client_key'],
                                      client_secret=conf['client_secret'],
                                      callback_uri=conf['callback_uri']
                                      )
        url = conf['url_request_token']
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
        conf = config_twitter.get_config()  # get twitter configs
        request_token = OAuth1Session(client_key=conf['client_key'],
                                      client_secret=conf['client_secret'],
                                      resource_owner_key=oauth_token,
                                      resource_owner_secret=oauth_token_secret,
                                      verifier=verifier
                                      )
        url = conf['url_access_token']
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
        conf = config_twitter.get_config()  # get twitter configs
        oauth_user = OAuth1Session(client_key=conf['client_key'],
                                   client_secret=conf['client_secret'],
                                   resource_owner_key=access_token_key,
                                   resource_owner_secret=access_token_secret)
        url_user = conf['url_verify_credentials']
        params = {"include_email": 'true'}
        user_data = oauth_user.get(url_user, params=params)
        return user_data.json()
    except Exception as e:
        log.error(e)
        raise e


def user_name_from_twitter(name, screen_name):
    try:
        if name != '' or screen_name != '':
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
        conf = config_twitter.get_config()  # get twitter configs
        if len(twitter_get_oauth_request_token()) > 1:
            oauth_token, oauth_token_secret = twitter_get_oauth_request_token()
        else:
            oauth_token = None
            oauth_token_secret = None
        url = f"{conf['url_oauth_token']}={oauth_token}" \
              f"&oauth_token_secret={oauth_token_secret}" \
              f"&oauth_callback_confirmed=true"
        return url
    except Exception as e:
        log.error(e)
        raise e


@router.get('/twitter/callback', tags=[model.name], status_code=307, response_class=RedirectResponse)
async def call_back_twitter(request: Request):
    verifier = request.query_params['oauth_verifier']
    oauth_token = request.query_params['oauth_token']
    try:
        oauth_token_secret = twitter_get_oauth_request_token()[1]
        access_token_key, access_token_secret = get_access_token(oauth_token, oauth_token_secret, verifier)
        twitter_data_person = get_twitter_json(access_token_key, access_token_secret)
        result = ProviderFusionAuth._social_login_model(twitter_data_person, {'twitter': twitter_data_person})
        result = result.json()
        url = f"{frontend_redirect_url}?result={result}"
        return url
    except Exception as e:
        log.error(e)
        raise e
