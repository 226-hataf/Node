import os

from business.providers.keycloak import ProviderKeycloak

from .firebase import ProviderFirebase

def get_provider():
    provider = os.environ.get('AUTH_PROVIDER')

    if provider.upper() == 'FIREBASE':
        return ProviderFirebase()
    elif provider.upper() == 'KEYCLOAK':
        return ProviderKeycloak()
    else:
        raise Exception(f"Unknwon provider <{provider}>")