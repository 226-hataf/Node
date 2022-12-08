"""
 try:
     jwt_secret_key = os.environ.get('JWT_SECRET_KEY')
     refresh_token_exp = int(os.environ.get('REFRESH_TOKEN_EXPIRY_MINUTES'))
     data = jwt.decode(token, jwt_secret_key, audience='ZeAuth', options={"verify_signature": False})
     get_user = hget_redis(f"zekoder-{data['sub']}","map_user_id")  # get user from redis,
     # if redis key expired then no data will be equal to
     # jwt.decoded data, if not expired then refresh_token will be generated
     if get_user == data['sub']:
         data['expr'] = refresh_token_exp
         refresh_token = jwt.encode(data, key=jwt_secret_key, algorithm="HS256")
         return refresh_token
     else:
         raise InvalidTokenError('failed refresh token request')
 except Exception as err:
     log.error(err)
     raise err

 try:
     jwt_secret_key = os.environ.get('JWT_SECRET_KEY')
     REFRESH_TOKEN_EXPIRY_MINUTES = os.environ.get('REFRESH_TOKEN_EXPIRY_MINUTES')
     refresh_token_exp = datetime.utcnow() + timedelta(minutes = int(REFRESH_TOKEN_EXPIRY_MINUTES))
     data = jwt.decode(token, key=jwt_secret_key, audience='ZeAuth', options={"verify_signature": False})
     data['exp'] = refresh_token_exp
     refresh_token = jwt.encode(data, key=jwt_secret_key, algorithm="HS256")
     return {"refresh_token": refresh_token}
 except jwt.ExpiredSignatureError as r:
     log.error(r)
     raise InvalidTokenError('failed token verification') from r
 """
from datetime import datetime, timedelta
REFRESH_TOKEN_EXPIRY_MINUTES = 60

refresh_token_exp = datetime.utcnow() + timedelta(minutes = int(REFRESH_TOKEN_EXPIRY_MINUTES))
print(refresh_token_exp.timestamp())