import redis
import os
from core import log
from datetime import datetime, timezone

redi = redis.Redis(
    host=os.environ.get('REDIS_HOST', 'localhost'),
    port=int(os.environ.get('REDIS_PORT', 6379)),
    password=os.environ.get('REDIS_PASSWORD', None)

)

ONE_HOUR_IN_SECONDS = 3600

REDIS_KEY_PREFIX = os.environ.get('REDIS_KEY_PREFIX')


def set_redis(key, value, expiry_hours=24):
    redi.set(key, value, ex=ONE_HOUR_IN_SECONDS * expiry_hours)


def get_redis(key):
    return redi.get(key).decode("utf-8")


def hset_redis(key,
               refresh_token,
               aud,
               ip,
               iss,
               sub,
               email,
               username,
               verified,
               avatar_url,
               first_name,
               last_name,
               full_name,
               roles,
               groups,
               expiry_time):
    try:
        key = f"{REDIS_KEY_PREFIX}-{key}"
        res = redi.hset(key, mapping={
            "map_refresh_token": refresh_token,
            "map_aud": aud,
            "map_ip": ip,
            "map_iss": iss,
            "map_sub": sub,
            "map_email": email,
            "map_username": username,
            "map_verified": verified,
            "map_avatar_url": avatar_url,
            "map_first_name": first_name,
            "map_last_name": last_name,
            "map_full_name": full_name,
            "map_roles": roles,
            "map_groups": groups
        })
        redi.expire(key, expiry_time)

        if type(res) is not int:
            log.debug(f"cannot create access token <{key}> to redis")
        else:
            log.debug(f"token successfully created <{key}> to redis")
    except Exception as e:
        log.error(e)
        raise e


def hget_redis(key, field):
    try:
        data = redi.hget(key, field)
        if data:
            return data.decode("utf-8")
        else:
            return ''
    except Exception as e:
        log.error(e)
        raise e


def hgetall_redis(key):
    try:
        data = redi.hgetall(key)
        if data:
            return data
        else:
            return {"No data"}
    except Exception as e:
        log.error(e)
        raise e


def del_key(key):
    try:
        data = redi.delete(key)
        if data:
            return {f"deleted key <data> successfully"}
        else:
            return {f"Key could not deleted !!!"}
    except Exception as e:
        log.error(e)
        raise e
