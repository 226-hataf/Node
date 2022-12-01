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
REDIS_PREFIX = "zekoder"


def set_redis(key, value, expiry_hours=24):
    redi.set(key, value, ex=ONE_HOUR_IN_SECONDS * expiry_hours)


def get_redis(key):
    return redi.get(key).decode("utf-8")


def hset_redis(key, access_token, ip, expiry_time):
    try:
        redi.hset(f"{REDIS_PREFIX}-{key}", mapping={"map_access_token": access_token, "map_ip": ip,  "map_exp": expiry_time})
    except Exception as e:
        log.error(e)
        raise e


def hget_redis(key, field):
    try:
        data = redi.hget(key, field)
        if data:
            return data.decode("utf-8")
        return ''
    except Exception as e:
        log.error(e)
        raise e


def check_permission_refresh_token(prefix_access):
    key = f"REDIS_PREFIX-{prefix_access}"
    """
    TODO: IP address will be added
    :param prefix_access:
    :param exp:
    :return:
    """
    try:
        if hget_redis(key, "map_exp"):
            print('aaa')
            current_time = datetime.now()
            expire_time = hget_redis(key, "map_exp")
            expire_time = expire_time.split('.')
            expire_time = datetime.strptime(expire_time[0], "%Y-%m-%d %H:%M:%S")

            if current_time > expire_time:
                print(hget_redis(key, "map_exp"))
                redi.delete(key)
                print('You are not allowed to get refresh token')
            else:
                print('Generate Refresh token')
        else:
            print('No Data !')

    except Exception as e:
        log.error(e)
        raise e
