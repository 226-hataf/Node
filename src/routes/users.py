from typing import List
from fastapi import APIRouter, Depends, HTTPException

from business import User
from business.models.users import UserResponseModel
from business.providers.base import Provider, DuplicateEmailError
from business.providers import get_provider
from business.models.dependencies import CommonDependencies
from core import log
from core.types import ZKModel

router = APIRouter()


model = ZKModel(**{
        "name": 'user',
        "plural": 'users',
        "fields": [{"name" : 'id', "pk": True}]
    })

@router.post('/', tags=[model.plural], status_code=201, response_model=User, response_model_exclude={"password"})
async def create(user: User):
    auth_provider: Provider = get_provider()
    try:
        signed_up_user = auth_provider.signup(user=user)
        return signed_up_user.dict()
    except DuplicateEmailError:
        raise HTTPException(status_code=400, detail="this email is already linked to an account")
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=422, detail=f"the user email is required {e}")

create.__doc__ = f" Create a new {model.name}".expandtabs()


@router.get('/', tags=[model.plural], status_code=200, response_model=UserResponseModel, response_model_exclude_none=True)
async def list(commons: CommonDependencies=Depends(CommonDependencies)):
    auth_provider: Provider = get_provider()
    try:
        user_list, next_page, page_size = auth_provider.list_users(page=commons.page, page_size=commons.size)
        return {
            'next_page': next_page,
            'page_size': page_size,
            'user_list': user_list
        }

    except Exception as e:
        log.error(e)


list.__doc__ = f" List {model.plural}".expandtabs()

@router.put('/{user_id}/permissions', tags=[model.plural], status_code=204)
async def update_permissions(user_id: str, user: User):
    auth_provider: Provider = get_provider()

    permissions = {}
    for permission in user.permissions:
        permissions.update({f'{permission}': True})

    additional_claims = auth_provider.update_permissions(user_id=user_id, permissions=permissions)

    return {'confirmed_permissions': additional_claims} # list of permissions


@router.get('/{user_id}', tags=[model.plural], response_model=User, response_model_exclude={"password"})
async def get(user_id: str):
    return User # {}

get.__doc__ = f" Get a specific {model.name} by it s id".expandtabs()


@router.put('/{user_id}', tags=[model.plural], status_code=200) #, response_model=User, response_model_exclude={"password"}
async def update(user_id: str, user: User):
    auth_provider: Provider = get_provider()
    try:
        updated_user = auth_provider.update_user(user_id=user_id, user=user)
        return {'updated user': updated_user.uid}
    except Exception as e:
        log.error(e)
        raise e

update.__doc__ = f" Update a {model.name} by its id and payload".expandtabs()


@router.delete('/{user_id}', tags=[model.plural], status_code=202) # , response_model=User, response_model_include={"email"}
async def delete(user_id: str):
    auth_provider: Provider = get_provider()
    try:
        deleted_user = auth_provider.delete_user(user_id=user_id)
        return {"deleted": deleted_user.email}
    except Exception as e:
        log.error(e)
        raise e
    # return {}

delete.__doc__ = f" Delete a {model.name} by its id".expandtabs()

@router.put('/{user_id}/on', tags=[model.plural], status_code=201)
async def active_on(user_id: str):
    return {}

@router.put('/{user_id}/off', tags=[model.plural], status_code=201)
async def active_off(user_id: str):
    return {}



active_on.__doc__ = f" Set {model.name}".expandtabs()
active_off.__doc__ = f" Delete a {model.name}".expandtabs()

