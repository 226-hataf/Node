from typing import Optional

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer

from business.providers import get_provider
from business.providers.base import Provider

auth_schema = HTTPBearer()
auth_provider: Provider = get_provider()

class CommonDependencies():
    def __init__(self, page: Optional[str] = 1, size: Optional[int] = 20):
        self.page = page
        self.size = size


class ProtectedMethod:
    def __init__(self, token: str = Depends(auth_schema)):
        self.credentials = token.credentials

    def auth(self, model_required_permissions):
        verified = auth_provider.verify(self.credentials)
        for permission in model_required_permissions:
            if permission in verified['zk-zeauth-permissions']:
                return
        raise HTTPException(403, "user not authorized to do this action")