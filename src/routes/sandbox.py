import os
from fastapi import FastAPI, Request, APIRouter
from core import log
from starlette.responses import RedirectResponse
from business.providers.zeauth import ProviderFusionAuth
import requests
from core.types import ZKModel
from dotenv import load_dotenv
import json
import jwt
from requests_oauthlib import OAuth1Session

import os
from core import log
import redis

data = {b'map_refresh_token': b'b4def705b53c4d03852b7beb82c7ae84',
        b'map_username': b'user@test.com',
        b'map_avatar_url': b'',
        b'map_first_name': b'User',
        b'map_aud': b'ZeAuth',
        b'map_roles': b"['zekoder-zestudio-app-get', 'zekoder-zestudio-app_version-create', 'zekoder-zestudio-app_version-list', 'zekoder-zestudio-environment-create', 'zekoder-zestudio-provider-create', 'zekoder-zestudio-provider-get', 'zekoder-zestudio-provider-list', 'zekoder-zestudio-solution-create']",
        b'map_sub': b'e517e863-06b0-479f-bf30-1996a2fdea20',
        b'map_verified': b'True',
        b'map_last_name': b'Test',
        b'map_iss': b'https://accounts.dev.zekoder.net',
        b'map_email': b'user@test.com',
        b'map_groups': b"['user']",
        b'map_full_name': b'User Test',
        b'map_ip': b'85.65.125.458'}

"""
class RedisServer:
    def __init__(self, payload: dict) -> None:
        self._payload = payload
        self.redi = None
        self.setup_redis()

    def setup_redis(self):
        self.redi = redis.Redis(
            host=os.environ.get('REDIS_HOST', 'localhost'),
            port=int(os.environ.get('REDIS_PORT', 6379)),
            password=os.environ.get('REDIS_PASSWORD', None)
        )

    @property
    def payload(self):
        return self._payload

    def hgetall(self, key):
        self.setup_redis()
        try:
            data = self.redi.hgetall(key)
            if data:
                return data
            else:
                return {"No data"}
        except Exception as e:
            log.error(e)
            raise e


obj = RedisServer(data)
print(obj.hgetall("zekoder-b17ac1f845ef486d84d192a427282748"))




class UserPayload:
    mapping_keys = ["map_roles", "map_refresh_token", "map_groups", "map_sub", "map_avatar_url",
                    "map_first_name", "map_username", "map_last_name", "map_full_name",
                    "map_ip", "map_aud", "map_verified", "map_email", "map_iss"]

    def __init__(self, payload: dict):
        self.payload = payload

    def get_data_all(self):
        res = {}
        data_dict = [v.decode() for k, v in data.items()]
        res = {UserPayload.mapping_keys[i]: data_dict[i] for i in range(len(UserPayload.mapping_keys))}
        return res

data = hgetall_redis("zekoder-75c382fe23d84ea88016b3b7cad9a379")

user = UserPayload.get_data(data)
print(user)


class Redis:
    def __init__(self) -> None:
        self.redi = None
        self.setup_redis()

    def setup_redis(self):
        self.redi = redis.Redis(
            host=os.environ.get('REDIS_HOST', 'localhost'),
            port=int(os.environ.get('REDIS_PORT', 6379)),
            password=os.environ.get('REDIS_PASSWORD', None)
        )

    def hgetall_redis(self, key):
        self.setup_redis()
        try:
            data = self.redi.hgetall(key)
            if data:
                return data
            else:
                return {"No data"}
        except Exception as e:
            log.error(e)
            raise e


data = Redis().hgetall_redis("zekoder-b4def705b53c4d03852b7beb82c7ae84")

print(data)
"""







