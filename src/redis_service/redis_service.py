import redis
import os
from core import log
from datetime import datetime, timedelta

redi = redis.Redis(
    host=os.environ.get('REDIS_HOST', 'localhost'),
    port=int(os.environ.get('REDIS_PORT', 6379)),
    password=os.environ.get('REDIS_PASSWORD', None)

)

ONE_HOUR_IN_SECONDS = 3600

REDIS_KEY_PREFIX = os.environ.get('REDIS_KEY_PREFIX')
ACCESS_TOKEN_EXPIRY_MINUTES = os.environ.get('ACCESS_TOKEN_EXPIRY_MINUTES')
expr = 60 * int(ACCESS_TOKEN_EXPIRY_MINUTES)

REFRESH_TOKEN_EXPIRY_MINUTES = os.environ.get("REFRESH_TOKEN_EXPIRY_MINUTES")
expr_in_refresh_payload = (datetime.utcnow() + timedelta(minutes=int(REFRESH_TOKEN_EXPIRY_MINUTES)))  # Don't add redis expr here, use like this.
expr_in_refresh_payload = expr_in_refresh_payload.timestamp()


def set_redis(key, value, expiry_hours=24):
    redi.set(key, value, ex=ONE_HOUR_IN_SECONDS * expiry_hours)


def get_redis(key):
    return redi.get(key).decode("utf-8")


class RedisClient:
    def __init__(self):
        self.redi = redis.Redis(
            host=os.environ.get('REDIS_HOST', 'localhost'),
            port=int(os.environ.get('REDIS_PORT', 6379)),
            password=os.environ.get('REDIS_PASSWORD', None)
        )

    def set_refresh_token(self, payload: dict):
        ip_address = "85.65.125.458"    # this should be change later
        data_dict = {k: v for k, v in payload.items()}
        log.debug(data_dict)
        try:
            if data_dict:
                key = f"{REDIS_KEY_PREFIX}-{data_dict['refreshToken']}"
                res = self.redi.hset(key, mapping={
                    "map_refresh_token": f"{data_dict['refreshToken']}",
                    "map_aud": f"{data_dict['aud']}",
                    "map_ip": f"{ip_address}",
                    "map_iss": f"{data_dict['iss']}",
                    "map_sub": f"{data_dict['sub']}",
                    "map_email": f"{data_dict['email']}",
                    "map_username": f"{data_dict['username']}",
                    "map_verified": f"{data_dict['verified']}",
                    "map_avatar_url": f"{data_dict['avatar_url']}",
                    "map_first_name": f"{data_dict['first_name']}",
                    "map_last_name": f"{data_dict['last_name']}",
                    "map_full_name": f"{data_dict['full_name']}",
                    "map_roles": f"{data_dict['roles']}",
                    "map_groups": f"{data_dict['groups']}"
                })
                self.redi.expire(key, expr)
                if type(res) is not int:
                    log.debug(f"cannot create access token <{key}> to redis")
                else:
                    log.debug(f"token successfully created <{key}> to redis")
            else:
                log.debug(f"No data included while Redis run")
        except Exception as e:
            log.error(e)
            raise e

    def get_refresh_token(self, key, field):
        try:
            data = self.redi.hget(key, field)
            if data:
                return data.decode("utf-8")
            else:
                return ''
        except Exception as e:
            log.error(e)
            raise e

    def del_refresh_token(self, key: str):
        try:
            data = self.redi.delete(key)
            if data:
                log.debug(f"deleted key <{key}> successfully")
            else:
                log.debug(f"<{key}> Not DELETED !!")
        except Exception as e:
            log.error(e)
            raise e

    def hgetall_redis_refresh_payload(self, key: str):
        try:
            data = self.redi.hgetall(key)
            data_dict = {k.decode(): v.decode() for k, v in data.items()}
            if data_dict:
                log.debug(f"refresh: {data_dict} ")
                payload = dict(
                    aud="ZeAuth",
                    expr=int(expr_in_refresh_payload),
                    iss=os.environ.get("FUSIONAUTH_URL"),
                    sub=data_dict["map_sub"],
                    email=data_dict["map_email"],
                    username=data_dict["map_username"],
                    verified=data_dict["map_verified"],
                    avatar_url=data_dict["map_avatar_url"],
                    first_name=data_dict["map_first_name"],
                    last_name=data_dict["map_last_name"],
                    full_name=data_dict["map_full_name"],
                    roles=data_dict["map_roles"],
                    groups=data_dict["map_groups"]
                )
                return payload
            else:
                return {"No data"}
        except Exception as e:
            log.error(e)
            raise e



