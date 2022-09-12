from src.business.models.users import ResendConfirmationEmailSchema
from src.business.providers.keycloak import ProviderKeycloak
import pytest
from src.test_zeauth.keycloak_fixtures import mocked_keycloak_admin, mocked_keycloak_open_id, mocked_set_redis, \
    mocked_send_email, mocked_keycloak_admin_empty_user


@pytest.mark.asyncio
async def test_resend_confirmation_email_success(mocked_keycloak_admin, mocked_keycloak_open_id, mocked_set_redis,
                                                 mocked_send_email):
    keycloak = ProviderKeycloak()

    confirm_email_schema = ResendConfirmationEmailSchema(username="abdul@gmail.com")
    assert confirm_email_schema.username == "abdul@gmail.com"

    resend_confirm_email = await keycloak.resend_confirmation_email(confirm_email_schema)
    assert resend_confirm_email == "Confirmation email sent!"


@pytest.mark.asyncio
async def test_resend_confirmation_empty_user_err(mocked_keycloak_admin_empty_user, mocked_keycloak_open_id,
                                                  mocked_set_redis, mocked_send_email):
    keycloak = ProviderKeycloak()

    confirm_email_schema = ResendConfirmationEmailSchema(username="abdul@gmail.com")
    assert confirm_email_schema.username == "abdul@gmail.com"

    with pytest.raises(Exception) as empty_user_err:
        await keycloak.resend_confirmation_email(confirm_email_schema)
    assert str(empty_user_err.value) == "User 'abdul@gmail.com' not in system"
