import pytest


@pytest.fixture()
def mocked_keycloak_admin(mocker):  # mocker is pytest-mock fixture
    token = {
        'access_token': 'eyJhbGciOiJS3hLusczkmp6Nk4',
        'expires_in': 300,
        'refresh_expires_in': 0,
        'token_type': 'Bearer',
        'not-before-policy': 0,
        'scope': 'email profile'
    }
    users_list = [{"id": "2334423423", "email": "abdul@gmail.com"}]

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
def mocked_keycloak_open_id(mocker):  # mocker is pytest-mock fixture
    mocker.patch('src.business.providers.keycloak.KeycloakOpenID', return_value=mocker.Mock(**{
        "authorization": "test auth",
        "client_id": "account",
        "client_secret_key": "test",
        "connection": "ConnectionManager",
        "realm_name": "zeauth-dev",
    }))


@pytest.fixture()
def mocked_set_redis(mocker):  # mocker is pytest-mock fixture
    mocker.patch('src.redis_service.redis_service.set_redis', return_value=mocker.Mock())


@pytest.fixture()
def mocked_send_email(mocker):  # mocker is pytest-mock fixture
    mocker.patch('src.email_service.mail_service.send_email', return_value=mocker.Mock())


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
