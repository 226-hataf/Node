import os
from fastapi import Request, APIRouter
from config.social_config import GoogleLogin, FacebookLogin, TwitterLogin
from core import log
from starlette.responses import RedirectResponse
from business.providers.zeauth import ProviderFusionAuth

from core.types import ZKModel
from dotenv import load_dotenv
import json


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
        conf = GoogleLogin()   # get google configs
        url = conf.goto_provider_login_page()
        return url
    except Exception as e:
        log.error(e)
        raise e


@router.get('/google/callback', tags=[model.name], status_code=307, response_class=RedirectResponse)
async def call_back_google(request: Request):
    try:
        code = request.query_params['code']
        conf = GoogleLogin()    # get google configs
        data_jwt = conf.call_back_provider_data(code)
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
        conf = FacebookLogin()     # get facebook configs
        url = conf.goto_provider_login_page()
        return url
    except Exception as e:
        log.error(e)
        raise e


@router.get('/facebook/callback', tags=[model.name], status_code=307, response_class=RedirectResponse)
async def call_back(request: Request):
    try:
        code = request.query_params['code']
        conf = FacebookLogin()     # get facebook configs
        user_data = conf.call_back_provider_data(code)
        user = user_data.json()
        result = ProviderFusionAuth._social_login_model(user, {'facebook': user})
        result = result.json()
        log.debug(f"facebook_result: {result}")
        url = f"{frontend_redirect_url}?result={result}"
        return url
    except Exception as e:
        log.error(e)
        raise e


@router.get('/twitter', tags=[model.name], status_code=307, response_class=RedirectResponse)
async def twitter():
    try:
        conf = TwitterLogin()   # get twitter configs
        url = conf.goto_provider_login_page()
        return url
    except Exception as e:
        log.error(e)
        raise e


@router.get('/twitter/callback', tags=[model.name], status_code=307, response_class=RedirectResponse)
async def call_back_twitter(request: Request):
    verifier = request.query_params['oauth_verifier']
    oauth_token = request.query_params['oauth_token']
    try:
        conf = TwitterLogin()   # get twitter configs
        twitter_data_person = conf.call_back_provider_data(oauth_token, verifier)
        result = ProviderFusionAuth._social_login_model(twitter_data_person, {'twitter': twitter_data_person})
        result = result.json()
        url = f"{frontend_redirect_url}?result={result}"
        return url
    except Exception as e:
        log.error(e)
        raise e
