import uuid
from fastapi import APIRouter, Depends, HTTPException

from business.models.dependencies import ProtectedMethod
from business.models.schema_main import UUIDCheckForGroupIdSchema, UUIDCheckForIDSchema
from business.models.schemas_groups_users import GroupUserRoleSchema
from business.providers import get_provider
from business.providers.base import *
from core import log
from core.crud import assign_multi_users_or_roles_to_group, remove_multi_users_or_roles_from_group
from business.models.schemas_groups import GroupSchema, GroupBaseSchema
from core import crud
from config.db import get_db
from sqlalchemy.orm import Session
from core.types import ZKModel

router = APIRouter()
auth_provider: Provider = get_provider()

model = ZKModel(**{
    "name": 'group',
    "plural": 'groups',
    "permissions": {
        'read': ['zk-zeauth-read'],
        'list': ['zk-zeauth-list'],
        'create': ['zk-zeauth-create'],
        'update': ['zk-zeauth-update'],
        'delete': ['zk-zeauth-delete']
    }
})


# Create Group
@router.post('/', tags=[model.plural], status_code=201, response_model=GroupSchema, description="Create a group")
async def create(group_create: GroupBaseSchema, db: Session = Depends(get_db)):
    """Create a group"""
    # check if group name exist, do not create group request
    group_exist = crud.get_group_by_name(db, group_create.name)
    if group_exist:
        raise HTTPException(status_code=403, detail="Group already exist !")
    return crud.create_group(db=db, group_create=group_create)


# list all Groups
@router.get('/', tags=[model.plural], status_code=200, response_model=list[GroupSchema], description="List all groups")
async def list(skip: int = 0, limit: int = 20, db: Session = Depends(get_db)):
    """List all the groups"""
    try:
        groups = crud.get_groups(db, skip=skip, limit=limit)
        return groups
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error")


# get a group
@router.get('/{group_name}', tags=[model.plural], status_code=200, response_model=GroupSchema,
            description="Get a group by name")
async def group(group_name: str, db: Session = Depends(get_db)):
    """Get a group by name"""
    group_get = crud.get_group_by_name(db, group_name)
    if group_get is None:
        raise HTTPException(status_code=404, detail="Group not found")
    return group_get


# Update
@router.put('/{id}', tags=[model.plural], status_code=200, description="Update a group")
async def update(id: UUIDCheckForIDSchema = Depends(UUIDCheckForIDSchema), groups: GroupBaseSchema = ...,
                 token: str = Depends(ProtectedMethod), db: Session = Depends(get_db)):
    """ Update a group"""
    token.auth(model.permissions.update)
    checked_uuid = id.id
    group_exist = crud.get_group_by_id(db=db, id=str(checked_uuid))
    if not group_exist:
        raise HTTPException(status_code=404, detail="Group not found")
    try:
        updated = crud.update_group(db, str(checked_uuid), groups.name, groups.description)
        return updated
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error, check the logs")


# Delete
@router.delete('/{group_name}', tags=[model.plural], status_code=202, description="Delete a group")
async def delete(group_name: str, db: Session = Depends(get_db)):
    """Delete a group"""
    group_exist = crud.get_group_by_name(db, group_name)
    if not group_exist:
        raise HTTPException(status_code=404, detail="Group not found")
    try:
        crud.remove_group(db, group_name)
        return {"detail": f"Group <{group_name}> deleted successfully !"}
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error, check the logs")


@router.patch('/{group_id}', tags=[model.plural], status_code=200, description="Assign users or roles to a group")
async def users_or_roles_to_group(group_id: UUIDCheckForGroupIdSchema = Depends(UUIDCheckForGroupIdSchema),
                                  group_user_role: GroupUserRoleSchema = ..., db: Session = Depends(get_db)):
    """Assign Users or Roles to a Group"""
    checked_uuid = group_id.group_id
    group_exist = crud.get_group_by_id(db=db, id=str(checked_uuid))
    if not group_exist:
        raise HTTPException(status_code=404, detail="Group not found")
    try:
        assigned_ids = assign_multi_users_or_roles_to_group(db, str(checked_uuid), group_user_role)
        return assigned_ids
    except ValueError as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error, check the logs")


@router.patch('/{group_id}/remove', tags=[model.plural], status_code=200,
              description="Remove users or roles from a group")
async def remove_users_or_roles_from_group(group_id: UUIDCheckForGroupIdSchema = Depends(UUIDCheckForGroupIdSchema),
                                           group_user_role: GroupUserRoleSchema = ..., db: Session = Depends(get_db)):
    """Remove users or roles from a group"""
    checked_uuid = group_id.group_id
    group_exist = crud.get_group_by_id(db, id=str(checked_uuid))
    if not group_exist:
        raise HTTPException(status_code=404, detail="Group not found")
    try:
        removed_ids = remove_multi_users_or_roles_from_group(db, str(checked_uuid), group_user_role)
        return {"detail": f"<{removed_ids}>  removed from this group"}
    except ValueError as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error, check the logs")
