from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from business.models.dependencies import CommonDependencies
from business.models.roles import Roles
from business.providers import get_provider
from business.providers.base import Provider
from core import log
from core.types import ZKModel

from business.models.dependencies import ProtectedMethod

router = APIRouter()
auth_provider: Provider = get_provider()

model = ZKModel(**{
        "name": 'role',
        "plural": 'roles',
        "permissions": {
            'read': ['zk-zeauth-read'],
            'create': ['zk-zeauth-create'],
            'update': ['zk-zeauth-update'],
            'delete': ['zk-zeauth-delete']
        }
    })

# CRUD Operations
# Create
@router.post('/', tags=[model.plural], status_code=201)
async def create(name: str, permissions: List[str], description: Optional[str] = "", token: str=Depends(ProtectedMethod)):
    """
    Create a new role
    """
    token.auth(model.permissions.create)
    try:
        roles = auth_provider.create_role(name=name, permissions=permissions, description=description)

        return {'roles': roles}
    except Exception as e:
        log.error(e)

# Read
@router.get('/', tags=[model.plural], status_code=200)
async def list_roles(token: str=Depends(ProtectedMethod), commons: CommonDependencies=Depends(CommonDependencies)):
    """
    List all roles
    """
    token.auth(model.permissions.read)
    try:
        role_list, next_page, page_size = auth_provider.list_all_roles(page=commons.page, page_size=commons.size)

        return {
                'roles': role_list,
                'next_page': next_page,
                'page_size': page_size
            }
    except Exception as e:
        log.error(e)


@router.get('/{role_id}', tags=[model.plural], status_code=200)
async def roles(name: str,token: str=Depends(ProtectedMethod),  commons: CommonDependencies=Depends(CommonDependencies)):
    """
    List specific role by its name
    """
    token.auth(model.permissions.read)
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
async def update_roles(role_id: str, permissions: List[str], description: Optional[str] = "", token: str=Depends(ProtectedMethod)):
    """
    Update specific role by its name
    """
    token.auth(model.permissions.update)
    try:
        auth_provider.update_role(name=role_id, new_permissions=permissions, description=description)

        return {"updated role": role_id, "new permissions": permissions, "description": description}
    except Exception as e:
        log.error(e)
        raise e

# Delete
@router.delete('/{role_id}', tags=[model.plural], status_code=202)
async def delete(role_id: str, token: str=Depends(ProtectedMethod)):
    """
    Delete a role by its name
    """
    token.auth(model.permissions.delete)
    try:
        role_name = auth_provider.delete_role(name=role_id)
        return {"deleted role": role_name}
    except Exception as e:
        log.error(e)
        raise e