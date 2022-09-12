import pydantic
import pytest
from fastapi.testclient import TestClient
from fastapi import status
from src.api import app
from src.business.models.users import User
from src.test_zeauth.test_login import test_get_access_token

client = TestClient(app)


# USERS
# def test_get_users():
#     access_token = test_get_access_token()
#     headers = {
#         "accept": "application/json",
#         "Authorization": f"Bearer {access_token}"
#     }
#     response = client.get('/users', headers=headers)
#     assert response.status_code == status.HTTP_200_OK


def test_list():
    response = client.get('/users')
    assert response.status_code == status.HTTP_403_FORBIDDEN



# def test_update():
#     response = client.get('/users/86NrHXybNRfxf9zbyQvsHvfvru02')


def test_user_model_proper():
    pm = User(id="user_test", email="test@example.com", first_name="ezgisu", last_name="tuncel",
              full_name="ezgisu tuncel")
    assert pm.id == "user_test"
    assert pm.email == "test@example.com"
    assert pm.first_name == "ezgisu"
    assert pm.last_name == "tuncel"
    assert pm.full_name == "ezgisu tuncel"


def test_user_model_improper():
    with pytest.raises(pydantic.ValidationError):
        user = User(email="useless")

# def test_update_permissions():
#     user = User(id='user_test', email='ezgisu@cyberneticlabs.io', password='testuser', full_name='Ezgisu Tuncel', permissions=['ZK_auth_user_create', 'ZK_auth_user_del', 'ZK_chat_session_list'])

#     assert user.permissions == ['ZK_auth_user_create', 'ZK_auth_user_del', 'ZK_chat_session_list']
