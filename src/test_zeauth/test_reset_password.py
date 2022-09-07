from src.business.models.users import ResetPasswordSchema
# from src.business.providers.keycloak import ProviderKeycloak
from unittest import mock
from mock import patch


@patch("keycloak.KeycloakOpenID")
@patch("keycloak.KeycloakAdmin")
def test_reset_password(mock_Keycloak_admin, mock_keycloak_open_id):
    reset_pass_schema = ResetPasswordSchema(username="abdul")
    assert reset_pass_schema.username == "abdul"

    token = {
        'access_token': 'eyJhbGciOiJS3hLusczkmp6Nk4',
        'expires_in': 300,
        'refresh_expires_in': 0,
        'token_type': 'Bearer',
        'not-before-policy': 0,
        'scope': 'email profile'
    }
    mock_Keycloak_admin.return_value = mock.Mock(**{
        "status_code": 200,
        "json.return_value": {"token": token}
    })
    # keycloak = ProviderKeycloak()

