from typing import Optional
from datetime import date as date_type
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer

from business.providers import get_provider
from business.providers.base import Provider
from core import log

auth_schema = HTTPBearer()
auth_provider: Provider = get_provider()


class CommonDependencies:
    def __init__(self,
                 page: Optional[int] = 1,
                 size: Optional[int] = 20,
                 search: Optional[str] = ''
                 ):
        self.page = page
        self.size = size
        self.search = search


class ProtectedMethod:
    def __init__(self, token: str = Depends(auth_schema)):
        log.debug(f"verifying token: {token.credentials}")
        self.credentials = token.credentials

    def auth(self, model_required_permissions):
        try:
            verified = auth_provider.verify(self.credentials)
        except:
            raise HTTPException(401, "user not authenticated or using invalid token")

        return True
        raise HTTPException(403, "user not authorized to do this action")
