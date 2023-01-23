import os
from .zeauth import ProviderFusionAuth


def get_provider():
    provider = os.environ.get('AUTH_PROVIDER')

    if provider.upper() == 'FUSIONAUTH':
        return ProviderFusionAuth()
    else:
        raise Exception(f"Unknown provider <{provider}>")
