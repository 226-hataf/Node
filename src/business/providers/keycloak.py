import os
from business.providers.base import Provider
from keycloak import KeycloakAdmin


class ProviderKeycloak(Provider):
    admin_user_created = None

    def __init__(self) -> None:
        super().__init__()

        self.keycloak_admin = KeycloakAdmin(
            server_url="https://accounts.dev.zekoder.com",
            client_id=os.environ.get('CLIENT_ID'),
            realm_name=os.environ.get('REALM_NAME'),
            client_secret_key=os.environ.get('SECRET')
        )
        self.zeauth_bootstrap()


    def zeauth_bootstrap(self):
        if ProviderKeycloak.admin_user_created:
            return
        else:
            user_id_keycloak = self.keycloak_admin.get_user_id(os.environ.get('DEFAULT_ADMIN_EMAIL'))
            if user_id_keycloak:
                ProviderKeycloak.admin_user_created = True
            else:
                self.keycloak_admin.create_user({"email": os.environ.get('DEFAULT_ADMIN_EMAIL'),
                            "username": os.environ.get('DEFAULT_ADMIN_EMAIL'),
                            "enabled": True,
                            "firstName": "Example",
                            "lastName": "Example"})

                ProviderKeycloak.admin_user_created = True