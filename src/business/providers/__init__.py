import os

from .firebase import ProviderFirebase

def get_provider():
    provider = os.environ.get('AUTH_PROVIDER')

    if provider.upper() == 'FIREBASE':
        return ProviderFirebase()
    else:
        raise Exception(f"Unknwon provider <{provider}>")