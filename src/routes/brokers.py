import os
from fastapi import FastAPI, Request, APIRouter
from core import log
from starlette.responses import RedirectResponse
from fusionauth.fusionauth_client import FusionAuthClient
from business.providers.fusionauth import ProviderFusionAuth, get_access_token, get_twitter_json, user_name_from_twitter
import requests
from core.types import ZKModel
from dotenv import load_dotenv
import json
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


@router.get('/google', tags=[model.name], status_code=307, response_class=RedirectResponse)
async def google():
    redirect_url = os.environ.get('GOOGLE_REDIRECT_URL')
    app_id = os.environ.get('GOOGLE_APP_ID')
    response_type = 'code'
    scope = 'email+profile'
    url = f'https://accounts.google.com/o/oauth2/v2/auth?' \
          f'client_id={app_id}&redirect_uri={redirect_url}&response_type={response_type}&scope={scope}'
    return url


@router.get('/google/callback', tags=[model.name], status_code=307, response_class=RedirectResponse)
async def call_back_google(request: Request):
    code = request.query_params['code']
    frontend_redirect_url = os.environ.get('FRONTEND_REDIRECT_URL')
    fusionauth_client = FusionAuthClient(
        os.environ.get('FUSIONAUTH_APIKEY'),
        os.environ.get('FUSIONAUTH_URL')
    )
    try:
        ip_address = requests.get('https://api64.ipify.org?format=json').json()
        response = fusionauth_client.identity_provider_login({
            "applicationId": os.environ.get('applicationId'),
            "data": {
                'code': f'{code}',
                "redirect_uri": os.environ.get('GOOGLE_REDIRECT_URL')
            },
            "identityProviderId": os.environ.get('identityProviderIdGoogle'),
            "ipAddress": f"{ip_address}"
        })
        if response.was_successful():
            resp_provider = ProviderFusionAuth._cast_login_model(response, response.success_response)
            result = resp_provider.json()
            url = f"{frontend_redirect_url}?result={result}"
            return url
        else:
            return {"e": response.error_response, "s": response.success_response}
    except Exception as e:
        log.error(e)
        raise e


@router.get('/facebook', tags=[model.name], status_code=307, response_class=RedirectResponse)
async def facebook():
    redirect_url = os.environ.get('FACEBOOK_REDIRECT_URL')
    app_id = os.environ.get('FACEBOOK_APP_ID')
    scope = 'email' # IMPORTANT: IEven if you have given the permissions(public_profile, email) from within the app,
    # the e-mail address will not be returned to you. Scope must be used in the link to get this.
    url = f'https://www.facebook.com/v15.0/dialog/oauth?' \
          f'client_id={app_id}&redirect_uri={redirect_url}&scope={scope}'
    return url


@router.get('/facebook/callback', tags=[model.name], status_code=307, response_class=RedirectResponse)
async def call_back(request: Request):
    code = request.query_params['code']
    frontend_redirect_url = os.environ.get('FRONTEND_REDIRECT_URL')
    fusionauth_client = FusionAuthClient(
        os.environ.get('FUSIONAUTH_APIKEY'),
        os.environ.get('FUSIONAUTH_URL')
    )
    try:
        ip_address = requests.get('https://api64.ipify.org?format=json').json()
        response = fusionauth_client.identity_provider_login({
            "applicationId": os.environ.get('applicationId'),
            "data": {
                "code": f"{code}",
                "redirect_uri": os.environ.get('FACEBOOK_REDIRECT_URL')
            },
            "identityProviderId": os.environ.get('identityProviderIdFaceBook'),
            "ipAddress": f"{ip_address}"
        })
        if response.was_successful():
            resp_provider = ProviderFusionAuth._cast_login_model(response, response.success_response)
            result = resp_provider.json()
            url = f"{frontend_redirect_url}?result={result}"
            return url
        else:
            return {"e": response.error_response, "s": response.success_response}
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
    verifier = request.query_params['oauth_verifier']
    oauth_token = request.query_params['oauth_token']
    oauth_token_secret = twitter_get_oauth_request_token()[1]
    access_token_key, access_token_secret = get_access_token(oauth_token, oauth_token_secret, verifier)
    twitter_data_person = get_twitter_json(access_token_key, access_token_secret)
    first_name, last_name = user_name_from_twitter(twitter_data_person['name'], twitter_data_person['screen_name'])
    frontend_redirect_url = os.environ.get('FRONTEND_REDIRECT_URL')
    fusionauth_client = FusionAuthClient(
        os.environ.get('FUSIONAUTH_APIKEY'),
        os.environ.get('FUSIONAUTH_URL')
    )
    try:
        ip_address = requests.get('https://api64.ipify.org?format=json').json()
        response = fusionauth_client.identity_provider_login({
            "applicationId": os.environ.get('applicationId'),
            "data": {
                "oauth_token": f"{access_token_key}",
                "oauth_token_secret": f"{access_token_secret}"
            },
            "identityProviderId": os.environ.get('identityProviderIdTwitter'),
            "ipAddress": f"{ip_address}"
        })
        if response.was_successful():
            user_id = response.success_response['user']['id']
            data = {"user": {"firstName": f"{first_name}", "lastName": f"{last_name}"}}
            update_user_name_info = fusionauth_client.patch_user(user_id, request=data)
            if update_user_name_info.was_successful():
                if response.success_response['user']:
                    response.success_response['user']['firstName'] = first_name
                    response.success_response['user']['lastName'] = last_name
                resp_provider = ProviderFusionAuth._cast_login_model(response, response.success_response)
                result = resp_provider.json()
                url = f"{frontend_redirect_url}?result={result}"
                return url
        else:
            return {"e": response.error_response, "s": response.success_response}
    except Exception as e:
        log.error(e)
        raise e
