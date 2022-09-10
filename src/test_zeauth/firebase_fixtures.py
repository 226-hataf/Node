import pytest


@pytest.fixture()
def mocked_firebase_init_app(mocker):
    mocker.patch('src.business.providers.firebase.firebase_admin', return_value=mocker.Mock(**{
        "name": "firebase init app",
        "initialize_app.return_value": {}
    }))


@pytest.fixture()
def mocked_firestore_client(mocker):
    mocker.patch('src.business.providers.firebase.firestore', return_value=mocker.Mock(**{
        "name": "firestore client",
        "client.return_value": {}
    }))


@pytest.fixture()
def mocked_auth_create_user(mocker):
    mocker.patch('src.business.providers.firebase.auth', return_value=mocker.Mock(**{
        "name": "create_user",
        "create_user.return_value": {"uid": "2343543543432"}
    }))


@pytest.fixture()
def mocked_zeauth_bootstrap(mocker):
    mocker.patch('src.business.providers.firebase.ProviderFirebase.zeauth_bootstrap', return_value=mocker.Mock())


@pytest.fixture()
def mocked_login_request_post(mocker):
    byte_str = b'{"localId": "2334423423", "email": "abdul@gmail.com", "displayName": "Abdul Reman", "idToken": ' \
               b'"sdfkjf", "expiresIn": 300, "refreshToken": "sdfdf"}'
    mocker.patch('src.business.providers.firebase.requests.post', return_value=mocker.Mock(**{
        "status_code": 200,
        "content": byte_str
    }))


@pytest.fixture()
def mocked_login_fail_request_post(mocker):
    mocker.patch('src.business.providers.firebase.requests.post', return_value=mocker.MagicMock(status_code=401, **{
        "error": {"message": "failed login"}
    }))
