from fastapi import APIRouter, Depends, HTTPException, Security
from sqlalchemy.orm import Session
from business.models.dependencies import ProtectedMethod
from business.models import dependencies
from business.models.schema_main import UUIDCheckForIDSchema
from business.models.schema_roles import RoleBaseSchema, RoleSchema
from business.models.schemas_groups import GroupBaseSchema
from business.providers import get_provider
from business.providers.base import *
from config.db import get_db
from core import log, crud
from core.db_models import models
import uuid
from core.types import ZKModel

router = APIRouter()
auth_provider: Provider = get_provider()

model = ZKModel(**{
    "name": 'role',
    "plural": 'roles',
    "permissions": {
        'read': ['zk-zeauth-read'],
        'list': ['zk-zeauth-list'],
        'create': ['zk-zeauth-create'],
        'update': ['zk-zeauth-update'],
        'delete': ['zk-zeauth-delete']
    }
})


# Create Role
@router.post('/', tags=[model.plural], status_code=201, response_model=RoleSchema, description="Create a Role")
async def create(role_create: RoleBaseSchema, db: Session = Depends(get_db)):
    """Create a role"""
    # check if role name exist, do not create group request
    role_exist = crud.get_role_by_name(db, role_create.name)
    if role_exist:
        raise HTTPException(status_code=403, detail="Role already exist !")
    return crud.create_role(db=db, role_create=role_create)


# list all Roles
@router.get('/', tags=[model.plural], status_code=200, response_model=list[RoleSchema], description="List all Roles", )
async def list(skip: int = 0, limit: int = 20, db: Session = Depends(get_db),
               current_user: models.User = Security(dependencies.get_current_active_user, scopes=["coach"])):
    """List all Roles"""
    try:
        roles = crud.get_roles(db, skip=skip, limit=limit)
        return roles
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error")


# get a role
@router.get('/{role_name}', tags=[model.plural], status_code=200, response_model=RoleSchema, description="Get a Role")
async def role(role_name: str, db: Session = Depends(get_db)):
    """Get a Role"""
    role_get = crud.get_role_by_name(db, role_name)
    if role_get is None:
        raise HTTPException(status_code=404, detail="Role not found")
    return role_get


# Update role
@router.put('/{id}', tags=[model.plural], status_code=200, description="Update a Role")
async def update(id: UUIDCheckForIDSchema = Depends(UUIDCheckForIDSchema), roles: GroupBaseSchema = ...,
                 token: str = Depends(ProtectedMethod),
                 db: Session = Depends(get_db)):
    """Update a Role"""
    token.auth(model.permissions.update)
    checked_uuid = id.id
    role_exist = crud.get_role_by_id(db, str(checked_uuid))
    if not role_exist:
        raise HTTPException(status_code=404, detail="Role not found")
    try:
        updated = crud.update_role(db, str(checked_uuid), roles.name, roles.description)
        return updated
    except ValueError as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error, check the logs")


# Delete role
@router.delete('/{role_name}', tags=[model.plural], status_code=202, description="Delete a Role")
async def delete(role_name: str, db: Session = Depends(get_db)):
    """Delete a Role"""
    role_exist = crud.get_role_by_name(db, role_name)
    if not role_exist:
        raise HTTPException(status_code=404, detail="Role not found")
    try:
        crud.remove_role(db, role_name)
        return {"detail": f"Role <{role_name}> deleted successfully !"}
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error, check the logs")
