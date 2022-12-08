import os
from .keycloak import ProviderKeycloak
from .firebase import ProviderFirebase
from .zekoderauth import ProviderZekoderAuth
from .zeauth import ProviderFusionAuth


def get_provider():
    provider = os.environ.get('AUTH_PROVIDER')

    if provider.upper() == 'FUSIONAUTH':
        return ProviderFusionAuth()
    elif provider.upper() == 'FIREBASE':
        return ProviderFirebase()
    elif provider.upper() == 'KEYCLOAK':
        return ProviderKeycloak()
    elif provider.upper() == 'ZEKODERAUTH':
        return ProviderZekoderAuth()
    else:
        raise Exception(f"Unknwon provider <{provider}>")
