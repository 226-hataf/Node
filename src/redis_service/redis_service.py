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


def set_redis(key, value, expiry_hours=24):
    redi.set(key, value, ex=ONE_HOUR_IN_SECONDS * expiry_hours)


def get_redis(key):
    return redi.get(key).decode("utf-8")


def hset_redis(key, access_token, aud, ip, expiry_time):
    """
    set for Redis parameters
    :param key:
    :param access_token:
    :param aud:
    :param ip:
    :param expiry_time:
    :return:
    """
    try:
        redi.hset(f"{REDIS_KEY_PREFIX}-{key}",
                  mapping={"map_access_token": access_token, "map_aud": aud, "map_ip": ip, "map_exp": expiry_time})
    except Exception as e:
        log.error(e)
        raise e


def hget_redis(key, field):
    """
    To get redis data by key and field name
    :param key:
    :param field:
    :return: value
    """
    try:
        data = redi.hget(key, field)
        if data:
            return data.decode("utf-8")
        else:
            return ''
    except Exception as e:
        log.error(e)
        raise e


def check_permission_refresh_token(prefix_access):
    """
    After the exp date is taken from the information from the access_token,
    it is compared with the current time.
    If the exp date is less than the current date then it is expired and the refresh_token is not allowed to be created.
    And requested access_token will be deleted from Redis
    This function provides control of this.
    TODO: IP address will be added, REDIS_KEY_PREFIX (-) will be remove from text, ask Mr Ahmed again
    :param prefix_access:
    :param map_exp:
    :return:
    """
    key = f"{REDIS_KEY_PREFIX}-{prefix_access}"  # this key format will be changed
    try:
        if hget_redis(key, "map_exp"):
            current_time = datetime.now()
            expire_duration = hget_redis(key, "map_exp")
            expire_duration = expire_duration.split('.')
            expire_duration = datetime.strptime(expire_duration[0], "%Y-%m-%d %H:%M:%S")
            if current_time > expire_duration:
                redi.delete(key)
                return False
            else:
                return True
        else:
            log.debug('No Data !')
    except Exception as e:
        log.error(e)
        raise e
