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
def mocked_firebase_auth_create_user(mocker):
    mocker.patch('src.business.providers.firebase.auth.create_user', return_value=mocker.MagicMock(uid="2343543543432"))


@pytest.fixture()
def mocked_firebase_auth_delete_user(mocker):
    mocker.patch('src.business.providers.firebase.auth.delete_user', return_value=mocker.MagicMock(uid="2343543543432"))


@pytest.fixture()
def mocked_firebase_auth_update_user(mocker):
    mocker.patch('src.business.providers.firebase.auth.update_user', return_value=mocker.MagicMock(uid="2343543543432"))


@pytest.fixture()
def mocked_firebase_auth_get_user(mocker):
    mocker.patch('src.business.providers.firebase.auth.get_user', return_value=mocker.MagicMock(
        uid="2343543543432",
        **{"_data": {
            "localId": "2343543543432",
            "email": "abdul@gmail.com",
            "emailVerified": True,
            "createdAt": "10-10-2022"
        }}))


@pytest.fixture()
def mocked_firebase_auth_verify_id_token(mocker):
    mocker.patch('src.business.providers.firebase.auth.verify_id_token',
                 return_value=mocker.MagicMock(uid="2343543543432"))


@pytest.fixture()
def mocked_firebase_auth_list_users(mocker):
    user = mocker.Mock(**{"_data": {
        "localId": "2343543543432",
        "email": "abdul@gmail.com",
        "emailVerified": True,
        "createdAt": "10-10-2022"
    }})
    list_users = [user]

    mocker.patch('src.business.providers.firebase.auth.list_users', return_value=mocker.MagicMock(
        users=list_users,
        **{
            "next_page_token": "next_page_token",
            "_max_results": "_max_results"
        }
    ))


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
