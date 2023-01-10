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


def get_current_user(
        security_scopes: SecurityScopes, db: Session = None, email: str = None
) -> models.User:
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = f"Bearer"
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if email is None:
        raise credentials_exception

    user = crud.get_user_by_email(db, email=email)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    allowed = False
    # for scope in security_scopes.scopes:
    #     if scope in token_data.scopes:
    #         allowed = True
    if len(security_scopes.scopes) == 0:
        allowed = True
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not enough permissions",
            headers={"WWW-Authenticate": authenticate_value},
        )
    return user


def get_current_active_user(
        current_user: models.User = Depends(get_current_user),
) -> models.User:
    return current_user


class ProtectedMethod:
    def __init__(self, token: str = Depends(auth_schema), db: Session = Depends(get_db)):
        log.debug(f"verifying token: {token.credentials}")
        self.credentials = token.credentials
        self.db = db

    def auth(self, model_required_permissions):
        try:
            verified = auth_provider.verify(self.credentials)
            get_current_user(db=self.db, email=verified)
            log.info("SET zekoder.id")
            self.db.execute(f"SET zekoder.id = '{verified.id}'")
        except:
            raise HTTPException(401, "user not authenticated or using invalid token")
        return verified
