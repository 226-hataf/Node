import redis
import os

redi = redis.Redis(
    host=os.environ.get('REDIS_HOST', 'localhost'),
    port=os.environ.get('REDIS_PORT', 6379),
    password=os.environ.get('REDIS_PASSWORD', None)
)

ONE_HOUR_IN_SECONDS = 3600


def set_redis(key, value, expiry_hours=24):
    redi.set(key, value, ex=ONE_HOUR_IN_SECONDS * expiry_hours)


def get_redis(key):
    return redi.get(key).decode("utf-8")
