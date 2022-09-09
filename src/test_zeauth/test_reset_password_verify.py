from src.business.models.users import ResetPasswordVerifySchema
from src.business.providers.keycloak import ProviderKeycloak
import pytest
from src.test_zeauth.keycloak_fixtures import mocked_get_redis, mocked_keycloak_admin, mocked_keycloak_open_id


def test_reset_password_verify_success(mocked_get_redis, mocked_keycloak_admin, mocked_keycloak_open_id):
    keycloak = ProviderKeycloak()

    reset_pass_schema = ResetPasswordVerifySchema(reset_key="123456", new_password="test123")
    assert reset_pass_schema.reset_key == "123456"
    assert reset_pass_schema.new_password == "test123"

    reset_password = keycloak.reset_password_verify(reset_pass_schema)
    assert reset_password is not None


def test_reset_password_verify_key_not_found(mocked_keycloak_admin, mocked_keycloak_open_id):
    keycloak = ProviderKeycloak()

    reset_pass_schema = ResetPasswordVerifySchema(reset_key="123456", new_password="test123")
    assert reset_pass_schema.reset_key == "123456"
    assert reset_pass_schema.new_password == "test123"

    with pytest.raises(Exception) as key_not_found:
        keycloak.reset_password_verify(reset_pass_schema)
    assert str(key_not_found.value) == "Reset key 123456 is incorrect!"
