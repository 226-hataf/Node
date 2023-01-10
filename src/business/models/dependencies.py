from typing import Optional
from datetime import date as date_type
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, SecurityScopes, OAuth2PasswordBearer
from sqlalchemy.orm import Session
from business.providers import get_provider
from business.providers.base import Provider
from config.db import get_db
from jose import jwt
from core import log, crud
from core.db_models import models

from src.business import User

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


# scopes = [(resource_name, permission_name)]
# scopes = [("users", "create")]
# for scope in scopes:
#   role_to_check = f'zekoder-zeauth-{scope[0]}-{scope[1]}'
#   ## check role is there in user roles

class ProtectedMethod:
    def __init__(self, token: str = Depends(auth_schema), db: Session = Depends(get_db)):
        log.debug(f"verifying token: {token.credentials}")
        self.credentials = token.credentials
        self.db = db

    def auth(self) -> User:
        try:
            verified = auth_provider.verify(self.credentials)
            log.info("SET zekoder.id")
            self.db.execute(f"SET zekoder.id = '{verified.id}'")
        except:
            raise HTTPException(401, "user not authenticated or using invalid token")
        return verified



def get_current_user(
        security_scopes: SecurityScopes, db: Session = Depends(get_db), token_auth=Depends(ProtectedMethod)
) -> models.User:
    user = token_auth.auth()
    for scope in security_scopes.scopes:
        role = f'zekoder-zeauth-{scope}'
        has_role = crud.check_user_has_role(db, user.id, role)
        if not has_role:
            raise HTTPException(401, "User don't have roles specified for API")


def get_current_active_user(
        current_user: models.User = Depends(get_current_user),
) -> models.User:
    return current_user
