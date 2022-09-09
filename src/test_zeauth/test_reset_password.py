from src.business.models.users import ResetPasswordSchema
from src.business.providers.keycloak import ProviderKeycloak
import pytest
from src.test_zeauth.keycloak_fixtures import mocked_keycloak_admin, mocked_keycloak_open_id, mocked_set_redis, \
    mocked_send_email, mocked_keycloak_admin_empty_user


@pytest.mark.asyncio
async def test_reset_password_success(mocked_keycloak_admin, mocked_keycloak_open_id, mocked_set_redis,
                                      mocked_send_email):
    keycloak = ProviderKeycloak()

    reset_pass_schema = ResetPasswordSchema(username="abdul@gmail.com")
    assert reset_pass_schema.username == "abdul@gmail.com"

    reset_password = await keycloak.reset_password(reset_pass_schema)
    assert reset_password == True


@pytest.mark.asyncio
async def test_reset_password_fail(mocked_keycloak_admin_empty_user, mocked_keycloak_open_id, mocked_set_redis,
                                   mocked_send_email):
    keycloak = ProviderKeycloak()

    reset_pass_schema = ResetPasswordSchema(username="abdul@gmail.com")
    assert reset_pass_schema.username == "abdul@gmail.com"

    with pytest.raises(Exception) as empty_user_err:
        await keycloak.reset_password(reset_pass_schema)
    assert str(empty_user_err.value) == "User 'abdul@gmail.com' not in system"
