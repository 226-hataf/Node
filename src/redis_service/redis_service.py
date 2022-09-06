import redis
import os

redi = redis.Redis(
    os.environ.get('REDIS_HOST', 'localhost'),
    os.environ.get('REDIS_PORT', 6379)
)

ONE_HOUR_IN_SECONDS = 3600


def set_redis(key, value):
    redi.set(key, value, ex=ONE_HOUR_IN_SECONDS * 24)


def get_redis(key):
    return redi.get(key).decode("utf-8")
