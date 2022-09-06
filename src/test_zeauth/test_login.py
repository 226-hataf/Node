from fastapi import status
from src.api import app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_login_success():
    login_data = {
        "email": "ar.rehmanmirza@gmail.com",
        "password": "webdir123R@!"
    }
    response = client.post('/login', json=login_data)
    assert response.status_code == status.HTTP_200_OK
    json_resp = response.json()
    assert json_resp["user"]["id"] is not None


def test_login_wrong_password():
    login_data = {
        "email": "ar.rehmanmirza@gmail.com",
        "password": "webdddir123R@!"
    }
    response = client.post('/login', json=login_data)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    json_resp = response.json()
    assert json_resp["detail"] == "username or password is not matching our records"


def test_login_wrong_email():
    login_data = {
        "email": "sdf_ar.rehmanmirza@gmail.com",
        "password": "webdir123R@!"
    }
    response = client.post('/login', json=login_data)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    json_resp = response.json()
    assert json_resp["detail"] == "username or password is not matching our records"


def test_login_wrong_email_and_password():
    login_data = {
        "email": "sdf_ar.rehmanmirza@gmail.com",
        "password": "wsdebdir123R@!"
    }
    response = client.post('/login', json=login_data)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    json_resp = response.json()
    assert json_resp["detail"] == "username or password is not matching our records"


def test_get_access_token():
    login_data = {
        "email": "ar.rehmanmirza@gmail.com",
        "password": "webdir123R@!"
    }
    response = client.post('/login', json=login_data)
    assert response.status_code == status.HTTP_200_OK
    json_resp = response.json()
    assert json_resp["user"]["id"] is not None
    return json_resp["accessToken"]
