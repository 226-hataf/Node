# import pytest
# import pydantic
from business.models.users import User
from fastapi_jwt_auth import AuthJWT
from firebase_admin import auth

# pm = User(id="test_id", email="test@example.com", first_name="ezgisu", last_name="tuncel")
# assert pm.id == "test_id"
# assert pm.email == "test@example.com"
# assert pm.first_name == "ezgisu"
# assert pm.last_name == "tuncel"
# assert pm.full_name =="ezgisu tuncel"

# def test_user_model_improper():
#     with pytest.raises(pydantic.ValidationError):
#         user = User(email="useless")
import firebase_admin
firebase_admin.initialize_app()

additional_claims = {
    'ZK_auth_user_create': True,
    'ZK_auth_user_del': True,
    'ZK_chat_session_list': True
}


import jwt
key='super-secret'
payload={
  "name": "ezgisu tuncel",
  "iss": "https://securetoken.google.com/jsc-chatbot",
  "aud": "jsc-chatbot",
  "auth_time": 1652431690,
  "user_id": "eN0oMR5nTcW27v9Au61kJhWsKzt2",
  "sub": "eN0oMR5nTcW27v9Au61kJhWsKzt2",
  "iat": 1652431690,
  "exp": 1652435290,
  "email": "test@example.com",
  "email_verified": False,
  "firebase": {
    "identities": {
      "email": [
        "test@example.com"
      ]
    },
    "sign_in_provider": "password"
  }
}

custom_token = auth.create_custom_token('eN0oMR5nTcW27v9Au61kJhWsKzt2', additional_claims)

auth.set_custom_user_claims('eN0oMR5nTcW27v9Au61kJhWsKzt2', additional_claims)
print(custom_token)

# Request body
# user_id = eN0oMR5nTcW27v9Au61kJhWsKzt2
#     {
#   "id": "user_test_id",
#   "email": "test@example.com",
#   "password": "test123",
#   "full_name": "Ezgisu Tuncel",
#   "permissions": [
#     "ZK_auth_user_create",
#     "ZK_chat_session_list"
#   ]
# }
# from google.oauth2 import service_account
# from google.auth.transport.requests import AuthorizedSession
# import google.auth.transport.requests
# scopes = [
#   "https://www.googleapis.com/auth/userinfo.email",
#   "https://www.googleapis.com/auth/firebase.database"
# ]
# credentials = service_account.Credentials.from_service_account_file("C:\Users\ezgis\Desktop\zeauth\zeauth\jsc-chatbot-sa.json")
# request = google.auth.transport.requests.Request()
# credentials.refresh(request)
# access_token = credentials.token
# print(access_token)
# # token = jwt.encode(payload, key)
# # print (token)
# # decoded = jwt.decode(token, options={"verify_signature": False})
# # print (decoded)
# # print (decoded["email"])
