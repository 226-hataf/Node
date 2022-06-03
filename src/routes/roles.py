from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from business.models.dependencies import CommonDependencies
from business.models.permissions import Permission
from business.models.roles import Roles
from business.providers import get_provider
from business.providers.base import Provider
from core import log
from core.types import ZKModel

router = APIRouter()

model = ZKModel(**{
        "name": 'role',
        "plural": 'roles',
        "fields": [{"name" : 'id', "pk": True}]
    })

# CRUD Operations
# Create
@router.post('/', tags=[model.plural], status_code=201)
async def create(name: str, permissions: List[str], description: Optional[str] = ""):
    auth_provider: Provider = get_provider()
    try:
        roles = auth_provider.create_role(name=name, permissions=permissions, description=description)

        return {'roles': roles}
    except Exception as e:
        log.error(e)

# Read
@router.get('/', tags=[model.plural], status_code=200)
async def list_roles(commons: CommonDependencies=Depends(CommonDependencies)): # , response_model=Roles, response_model_exclude_none=True
    auth_provider: Provider = get_provider()
    try:
        role_list, next_page, page_size = auth_provider.list_all_roles(page=commons.page, page_size=commons.size)

        return {
                'roles': role_list,
                'next_page': next_page,
                'page_size': page_size
            }
    except Exception as e:
        log.error(e)


@router.get('/{role_id}', tags=[model.plural], status_code=200) # , response_model=Roles, response_model_exclude_none=True
async def roles(name: str, commons: CommonDependencies=Depends(CommonDependencies)):
    auth_provider: Provider = get_provider()
    try:
        role_list, next_page, page_size = auth_provider.list_specific_roles(name=name, page=commons.page, page_size=commons.size)

        return {
                'role_name': role_list, 
                'next_page': next_page,
                'page_size': page_size
            }
    except Exception as e:
        log.error(e)
    return {}

# Update
@router.put('/{role_id}', tags=[model.plural], status_code=200)
async def update_roles(role_id: str, permissions: List[str], description: Optional[str] = ""):
    auth_provider: Provider = get_provider()
    try:
        auth_provider.update_role(name=role_id, new_permissions=permissions, description=description)

        return {"updated role": role_id, "new permissions": permissions, "description": description}
    except Exception as e:
        log.error(e)
        raise e

# Delete
@router.delete('/{role_id}', tags=[model.plural], status_code=202)
async def delete(role_id: str):
    auth_provider: Provider = get_provider()
    try:
        role_name = auth_provider.delete_role(name=role_id)
        return {"deleted role": role_name}
    except Exception as e:
        log.error(e)
        raise e