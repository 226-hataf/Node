import uuid
from fastapi import APIRouter, Depends, HTTPException
from business.providers import get_provider
from business.providers.base import *
from core import log
from core.types import ZKModel
from business.models.schemas_groups import Group, GroupBase
from core import crud
from config.db import get_db
from sqlalchemy.orm import Session

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
@router.post('/', tags=[model.plural], status_code=201, response_model=Group)
async def create(group_create: GroupBase, db: Session = Depends(get_db)):
    # check if group name exist, do not create group request
    group_exist = crud.get_group_by_name(db, group_create.name)
    if group_exist:
        raise HTTPException(status_code=400, detail="Group already exist !")
    return crud.create_group(db=db, group_create=group_create)


# list all Groups
@router.get('/', tags=[model.plural], status_code=200, response_model=list[Group])
async def list(skip: int = 0, limit: int = 20, db: Session = Depends(get_db)):
    try:
        groups = crud.get_groups(db, skip=skip, limit=limit)
        return groups
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error")


# get a group
@router.get('/{group_name}', tags=[model.plural], status_code=200, response_model=Group)
async def group(name: str, db: Session = Depends(get_db)):
    group_get = crud.get_group_by_name(db, name)
    if group_get is None:
        raise HTTPException(status_code=404, detail="Group not found")
    return group_get


# Update
@router.put('/{id}', tags=[model.plural], status_code=200)
async def update(id: str, name: str, description: str, db: Session = Depends(get_db)):
    try:
        # check if uuid is valid
        uuid.UUID(str(id))
        group_exist = crud.get_group_by_id(db=db, id=id)
        if not group_exist:
            raise HTTPException(status_code=404, detail="Group not found")
        updated = crud.update_group(db=db, id=id, name=name, description=description)
        return updated
    except ValueError as e:
        log.error(e)
        return {"detail": "invalid uuid"}


# Delete
@router.delete('/{group_name}', tags=[model.plural], status_code=202)
async def delete(name: str, db: Session = Depends(get_db)):
    group_exist = crud.get_group_by_name(db, name)
    if not group_exist:
        raise HTTPException(status_code=404, detail="Group not found")
    crud.remove_group(db, name)
    return {"detail": f"Group <{name}> deleted successfully !"}

