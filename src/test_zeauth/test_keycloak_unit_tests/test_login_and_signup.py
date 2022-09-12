from src.business.models.users import UserLoginSchema, User
from src.business.providers.keycloak import ProviderKeycloak
from src.test_zeauth.keycloak_fixtures import mocked_keycloak_open_id, mocked_keycloak_admin, mocked_set_redis,\
    mocked_send_email
import pytest


@pytest.mark.asyncio
async def test_signup_success(mocked_keycloak_open_id, mocked_keycloak_admin, mocked_set_redis, mocked_send_email
                              ):
    keycloak = ProviderKeycloak()

    signup_schema = User(email="abdul@gmail.com", username="abdul@gmail.com", first_name="Abdul", last_name="Rehman")
    assert signup_schema.email == "abdul@gmail.com"
    assert signup_schema.username == "abdul@gmail.com"
    assert signup_schema.first_name == "Abdul"
    assert signup_schema.last_name == "Rehman"

    signup = await keycloak.signup(signup_schema)
    assert signup.email == "abdul@gmail.com"
    assert signup.username == "abdul@gmail.com"
    assert signup.first_name == "Abdul"
    assert signup.last_name == "Rehman"


def test_login_success(mocked_keycloak_open_id, mocked_keycloak_admin):
    keycloak = ProviderKeycloak()

    login_schema = UserLoginSchema(email="abdul@gmail.com", password="test123")
    assert login_schema.email == "abdul@gmail.com"
    assert login_schema.password == "test123"

    logged_in = keycloak.login(login_schema)

    assert logged_in.user.id == '23434554645454'
    assert logged_in.user.email == 'abdul@gmail.com'

