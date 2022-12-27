from typing import Optional
from datetime import date as date_type
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from business.providers import get_provider
from business.providers.base import Provider
from config.db import get_db
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
    def __init__(self, token: str = Depends(auth_schema), db: Session = Depends(get_db)):
        log.debug(f"verifying token: {token.credentials}")
        self.credentials = token.credentials
        self.db = db

    def auth(self, model_required_permissions):
        try:
            verified = auth_provider.verify(self.credentials)
            log.info("SET zekoder.id")
            self.db.execute(f"SET zekoder.id = '{verified.id}'")
        except:
            raise HTTPException(401, "user not authenticated or using invalid token")

        return verified
