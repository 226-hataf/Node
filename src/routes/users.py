from typing import List
from config.db import get_db
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime
from business.models.users import UserResponseModel, UsersWithIDsResponse
from business.providers.base import *
from business.providers import get_provider
from core import log
from core.types import ZKModel
from business.models.dependencies import CommonDependencies, ProtectedMethod
from fastapi import Query
from pydantic.schema import Enum


class SortByEnum(str, Enum):
    DESE = 'desc'
    ASC = 'asc'


class SortColumnEnum(str, Enum):
    CREATED_AT = 'created_at'
    USER_NAME = 'user_name'


router = APIRouter()

auth_provider: Provider = get_provider()

model = ZKModel(**{
    "name": 'user',
    "plural": 'users',
    "permissions": {
        'read': ['zk-zeauth-read'],
        'list': ['zk-zeauth-list'],
        'create': ['zk-zeauth-create'],
        'update': ['zk-zeauth-update'],
        'delete': ['zk-zeauth-delete']
    }
})


@router.post('/', tags=[model.plural], status_code=201, response_model=User, response_model_exclude={"password"})
async def create(user: User, token: str = Depends(ProtectedMethod)):
    token.auth(model.permissions.create)
    try:
        signed_up_user = auth_provider.signup(user=user)
        return signed_up_user.dict()
    except DuplicateEmailError:
        raise HTTPException(status_code=403, detail=f"'{user.email}' email is already linked to an account")
    except Exception as e:
        raise e


create.__doc__ = f" Create a new {model.name}".expandtabs()


# list users
@router.get('/', tags=[model.plural],
            status_code=200, response_model=UserResponseModel,
            response_model_exclude_none=True,
            )
async def list(
        token: str = Depends(ProtectedMethod),
        date_of_creation: datetime = Query(default=None),
        sort_by: SortByEnum = SortByEnum.DESE,
        sort_column: SortColumnEnum = Query(default=SortColumnEnum.CREATED_AT),
        date_of_last_login: datetime = Query(default=None),
        user_status: bool = Query(default=None),
        commons: CommonDependencies = Depends(CommonDependencies),
        db: Session = Depends(get_db)
):
    token.auth(model.permissions.list)
    try:
        user_list, next_page, page_size, total_count = auth_provider.list_users(
            page=commons.page,
            page_size=commons.size,
            search=commons.search,
            user_status=user_status,
            date_of_creation=date_of_creation,
            date_of_last_login=date_of_last_login,
            sort_by=sort_by,
            sort_column=sort_column,
            db=db
        )

        return {'next_page': next_page, 'page_size': page_size, 'user_list': user_list, 'total_count': total_count}
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error") from e


list.__doc__ = f" List all {model.plural}".expandtabs()


# assign roles to a user
@router.put('/{user_id}/roles', tags=[model.plural], status_code=201, response_model=User)
async def update_roles(user_id: str, new_role: List[str], token: str = Depends(ProtectedMethod)):
    """
    Update the roles of a user by its id and a list of roles
    """
    token.auth(model.permissions.update)
    try:
        user = (auth_provider.update_user_roles(new_role=new_role, user_id=user_id))
        return user  # list of permissins
    except NotExistingResourceError:
        raise HTTPException(status_code=404, detail="attempt to update not existing user")
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error")


@router.get('/with_ids', tags=[model.plural], status_code=200, response_model=UsersWithIDsResponse,
            response_model_exclude={"password"})
async def get(user_ids: List[str] = Query(...), token: str = Depends(ProtectedMethod)):
    token.auth(model.permissions.read)

    try:
        if len(user_ids) >= 51:
            raise LimitExceededError("limit exceeded!")
        return auth_provider.get_user(user_ids=user_ids)

    except NotExistingResourceError as e:
        log.debug(e)
        raise HTTPException(status_code=404, detail="attempt to get not existing user") from e
    except LimitExceededError as err:
        log.error(err)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="limit exceeded!") from err
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error") from e


get.__doc__ = f" Get a specific {model.name} by it s id".expandtabs()


@router.put('/{user_id}', tags=[model.plural],
            status_code=200)  # , response_model=User, response_model_exclude={"password"}
async def update(user_id: str, user: User, token: str = Depends(ProtectedMethod)):
    token.auth(model.permissions.update)
    try:
        updated_user = auth_provider.update_user(user_id=user_id, user=user)
        return {'updated user': updated_user.uid}
    except NotExistingResourceError:
        log.debug(e)
        raise HTTPException(status_code=404, detail="attempt to update not existing user")
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error")


update.__doc__ = f" Update a {model.name} by its id and payload".expandtabs()


@router.delete('/{user_id}', tags=[model.plural], status_code=202)
async def delete(user_id: str, token: str = Depends(ProtectedMethod)):
    token.auth(model.permissions.delete)
    try:
        deleted_user = auth_provider.delete_user(user_id=user_id)
        return {"deleted": deleted_user.email}
    except NotExistingResourceError as e:
        log.debug(e)
        raise HTTPException(status_code=404, detail="attempt to delete not existing user")
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error")


delete.__doc__ = f" Delete a {model.name} by its id".expandtabs()


@router.put('/{user_id}/on', tags=[model.plural], status_code=201)
async def active_on(user_id: str):
    try:
        updated_user = auth_provider.user_active_on(user_id=user_id)
        return {'updated user': updated_user.uid}
    except NotExistingResourceError as e:
        log.debug(e)
        raise HTTPException(status_code=404, detail="attempt to activate not existing user")
    except Exception as err:
        error_template = "active_on Exception: An exception of type {0} occurred. error: {1}"
        log.error(error_template.format(type(err).__name__, str(err)))
        raise HTTPException(status_code=500, detail="unknown error")


active_on.__doc__ = f" Set {model.name}".expandtabs()


@router.put('/{user_id}/off', tags=[model.plural], status_code=201)
async def active_off(user_id: str):
    try:
        updated_user = auth_provider.user_active_off(user_id=user_id)
        return {'updated user': updated_user.uid}
    except NotExistingResourceError as e:
        log.debug(e)
        raise HTTPException(status_code=404, detail="attempt to deactivate not existing user")
    except Exception as err:
        error_template = "active_off Exception: An exception of type {0} occurred. error: {1}"
        log.error(error_template.format(type(err).__name__, str(err)))
        raise HTTPException(status_code=500, detail="unknown error")


active_off.__doc__ = f" Delete a {model.name}".expandtabs()
