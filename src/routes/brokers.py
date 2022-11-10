import os
from fastapi import FastAPI, Request, APIRouter
from core import log
from starlette.responses import RedirectResponse
from fusionauth.fusionauth_client import FusionAuthClient
import requests
from core.types import ZKModel
from dotenv import load_dotenv
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
    scope = 'email'
    url = f'https://accounts.google.com/o/oauth2/v2/auth?' \
          f'client_id={app_id}&redirect_uri={redirect_url}&response_type={response_type}&scope={scope}'
    return url


@router.get('/facebook', tags=[model.name], status_code=307, response_class=RedirectResponse)
async def facebook():
    redirect_url = os.environ.get('FACEBOOK_REDIRECT_URL')
    app_id = os.environ.get('FACEBOOK_APP_ID')
    scope = 'email' # IMPORTANT: IEven if you have given the permissions(public_profile, email) from within the app,
    # the e-mail address will not be returned to you. Scope must be used in the link to get this.
    url = f'https://www.facebook.com/v15.0/dialog/oauth?' \
          f'client_id={app_id}&redirect_uri={redirect_url}&scope={scope}'
    return url


@router.get('/google/callback', tags=[model.name])
async def call_back_google(request: Request):
    code = request.query_params['code']
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
            res = response.success_response
            url = f"/brokers/google_callback?token={res['token']}&refresh_token={res['refreshToken']}&user={res['user']}"
            return RedirectResponse(url)
        else:
            return {'data': 'Authorization failed status_code: ' f'{response.status}'}
    except Exception as e:
        log.error(e)
        raise e


@router.get('/facebook/callback', tags=[model.name])
async def call_back(request: Request):
    code = request.query_params['code']
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
            res = response.success_response
            url = f"/brokers/facebook_callback?token={res['token']}&refresh_token={res['refreshToken']}&user={res['user']}"
            return RedirectResponse(url)
        else:
            return {'data': 'Authorization failed status_code: ' f'{response.status}'}
    except Exception as e:
        log.error(e)
        raise e


@router.get('/google_callback', tags=[model.name])
async def call_back2_google(request: Request):
    params = request.query_params
    return params


@router.get('/facebook_callback', tags=[model.name])
async def call_back2(request: Request):
    params = request.query_params
    return params
