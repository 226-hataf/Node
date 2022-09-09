import pytest


@pytest.fixture()
def mocked_keycloak_admin(mocker):
    token = {
        'access_token': 'eyJhbGciOiJS3hLusczkmp6Nk4',
        'expires_in': 300,
        'refresh_expires_in': 0,
        'token_type': 'Bearer',
        'not-before-policy': 0,
        'scope': 'email profile'
    }
    user = {"id": "2334423423", "email": "abdul@gmail.com", "firstName": "Abdul"}
    users_list = [user]

    mocker.patch('src.business.providers.keycloak.KeycloakAdmin', return_value=mocker.Mock(**{
        "name": "mock_Keycloak_admin mocked",
        "PAGE_SIZE": 100,
        "client_id": "account",
        "client_secret_key": "test",
        "connection": "ConnectionManager",
        "token": token,
        "get_users.return_value": users_list,
        "set_user_password.return_value": {},
        "update_user.return_value": {},
        "userinfo.return_value": user,
        "create_user.return_value": "2334423423"
    }))


@pytest.fixture()
def mocked_keycloak_open_id(mocker):
    token = {
        "session_state": "23434554645454",
        "access_token": "sdklklfg",
        "refresh_token": "sdfsdfkj",
        "expires_in": "sdd"
    }
    mocker.patch('src.business.providers.keycloak.KeycloakOpenID', return_value=mocker.Mock(**{
        "authorization": "test auth",
        "client_id": "account",
        "client_secret_key": "test",
        "connection": "ConnectionManager",
        "realm_name": "zeauth-dev",
        "token.return_value": token
    }))


@pytest.fixture()
def mocked_set_redis(mocker):
    mocker.patch('src.redis_service.redis_service.set_redis', return_value=mocker.Mock())


@pytest.fixture()
def mocked_send_email(mocker):
    mocker.patch('src.business.providers.keycloak.send_email', return_value=mocker.Mock())


@pytest.fixture()
def mocked_keycloak_admin_empty_user(mocker):
    token = {
        'access_token': 'eyJhbGciOiJS3hLusczkmp6Nk4',
        'expires_in': 300,
        'refresh_expires_in': 0,
        'token_type': 'Bearer',
        'not-before-policy': 0,
        'scope': 'email profile'
    }
    users_list = []
    mocker.patch('src.business.providers.keycloak.KeycloakAdmin', return_value=mocker.Mock(**{
        "name": "mock_Keycloak_admin mocked",
        "PAGE_SIZE": 100,
        "client_id": "account",
        "client_secret_key": "test",
        "connection": "ConnectionManager",
        "token": token,
        "get_users.return_value": users_list
    }))


@pytest.fixture()
def mocked_get_redis(mocker):
    mocker.patch('src.business.providers.keycloak.get_redis', return_value=mocker.Mock("abdul@gmail.com"))
