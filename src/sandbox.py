import redis
from datetime import datetime, timedelta
from redis_service.redis_service import hset_redis, hget_redis

try:
    r = redis.Redis(host='localhost', port=6379, decode_responses=True)
    r.ping()
except Exception as e:
    print(e)


#exp = datetime.now() + timedelta(minutes=1)

#r.hset("12345", mapping={"firstname": "alper", "ip": "123.123.4.5",  "exp": f"{exp}"})


prefix_access = "zekoder-eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJhYzUzMjliOC05Y2Q3LTQ5Y2UtYjY5Yy03NGI2OTcwMDNjNmIiLCJleHAiOjE2Njk4NjcyMzMsImlzcyI6Imh0dHBzOi8vYWNjb3VudHMuZGV2Lnpla29kZXIubmV0Iiwic3ViIjoiZTUxN2U4NjMtMDZiMC00NzlmLWJmMzAtMTk5NmEyZmRlYTIwIiwiZW1haWwiOiJ1c2VyQHRlc3QuY29tIiwidXNlcm5hbWUiOiJ1c2VyQHRlc3QuY29tIiwidmVyaWZpZWQiOnRydWUsInVzZXJfc3RhdHVzIjp0cnVlLCJmaXJzdF9uYW1lIjoiVXNlciIsImxhc3RfbmFtZSI6IlRlc3QiLCJmdWxsX25hbWUiOiJVc2VyIFRlc3QiLCJyb2xlcyI6WyJ6ZWtvZGVyLXplc3R1ZGlvLWFwcC1nZXQiLCJ6ZWtvZGVyLXplc3R1ZGlvLWFwcF92ZXJzaW9uLWNyZWF0ZSIsInpla29kZXItemVzdHVkaW8tYXBwX3ZlcnNpb24tbGlzdCIsInpla29kZXItemVzdHVkaW8tZW52aXJvbm1lbnQtY3JlYXRlIiwiemVrb2Rlci16ZXN0dWRpby1wcm92aWRlci1jcmVhdGUiLCJ6ZWtvZGVyLXplc3R1ZGlvLXByb3ZpZGVyLWdldCIsInpla29kZXItemVzdHVkaW8tcHJvdmlkZXItbGlzdCIsInpla29kZXItemVzdHVkaW8tc29sdXRpb24tY3JlYXRlIl0sImdyb3VwcyI6WyJ1c2VyIl0sImNyZWF0ZWRfYXQiOiIyMDIyLTExLTI1IDE0OjU5OjUyIiwibGFzdF9sb2dpbl9hdCI6IjIwMjItMTItMDEgMDM6NTk6MzIiLCJsYXN0X3VwZGF0ZV9hdCI6IjIwMjItMTEtMjUgMTQ6NTk6NTIifQ.nfbBFeeWYIIAswEzZzu6u3oeE-vcPa50CCRGkEenOO4"
def redis_call(user_id):
    try:
        if hget_redis(prefix_access, "map_exp"):
            current_time = datetime.now()
            expire_time = hget_redis(prefix_access, "map_exp")
            expire_time = expire_time.split('.')
            expire_time = datetime.strptime(expire_time[0], "%Y-%m-%d %H:%M:%S")

            if current_time > expire_time:
                redi.delete(prefix_access)
                print(hget_redis(prefix_access, "map_exp"))

                print('You are not allowed to get refresh token')
            else:
                print('Generate Refresh token')
        else:
            return 'No Data !'

    except Exception as e:
        print(e)


redis_call(12345)