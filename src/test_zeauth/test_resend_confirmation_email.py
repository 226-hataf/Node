from src.business.models.users import ResendConfirmationEmailSchema
from src.business.providers.keycloak import ProviderKeycloak
import pytest
from src.test_zeauth.keycloak_fixtures import mocked_keycloak_admin, mocked_keycloak_open_id, mocked_set_redis, \
    mocked_send_email, mocked_keycloak_admin_empty_user


@pytest.mark.asyncio
async def test_resend_confirmation_email_success(mocked_keycloak_admin, mocked_set_redis,
                                                 mocked_send_email):
    keycloak = ProviderKeycloak()

    reset_pass_schema = ResendConfirmationEmailSchema(username="abdul@gmail.com")
    assert reset_pass_schema.username == "abdul@gmail.com"

    reset_password = await keycloak.resend_confirmation_email(reset_pass_schema)
    assert reset_password == "Confirmation email sent!"


@pytest.mark.asyncio
async def test_resend_confirmation_email_fail(mocked_keycloak_admin_empty_user,
                                              mocked_set_redis, mocked_send_email):
    keycloak = ProviderKeycloak()

    reset_pass_schema = ResendConfirmationEmailSchema(username="abdul@gmail.com")
    assert reset_pass_schema.username == "abdul@gmail.com"

    with pytest.raises(Exception) as empty_user_err:
        await keycloak.resend_confirmation_email(reset_pass_schema)
    assert str(empty_user_err.value) == "User 'abdul@gmail.com' not in system"
