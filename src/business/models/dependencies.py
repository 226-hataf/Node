from typing import Optional

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer

from business.providers import get_provider
from business.providers.base import Provider
from core import log

auth_schema = HTTPBearer()
auth_provider: Provider = get_provider()

class CommonDependencies():
    def __init__(self, page: Optional[str] = 1, size: Optional[int] = 20, search: Optional[str] = '',
                 user_status: Optional[bool] = True):
        self.page = page
        self.size = size
        self.search = search
        self.user_status = user_status


class ProtectedMethod:
    def __init__(self, token: str = Depends(auth_schema)):
        log.debug(f"verifying token: {token.credentials}")
        self.credentials = token.credentials

    def auth(self, model_required_permissions):
        try:
            verified = auth_provider.verify(self.credentials)
        except:
            raise HTTPException(401, "user not authenticated or using invalid token")           
        for permission in model_required_permissions:
            if permission in verified['zk-zeauth-permissions']:
                return
        raise HTTPException(403, "user not authorized to do this action")



