from fastapi import APIRouter, Depends, HTTPException
from business.providers import get_provider
from business.providers.base import *
from core import log
from core.types import ZKModel
from core.db_models.schemas import Group, GroupBase
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
async def create_group(group_create: GroupBase, db: Session = Depends(get_db)):
    """
    TODO: add required field
    :param group_create:
    :param db:
    :return:
    """
    # check if group name exist, do not create group request
    group_exist = crud.get_group_by_name(db, group_create.name)
    if group_exist:
        raise HTTPException(status_code=400, detail="Group already exist !")
    return crud.create_group(db=db, group_create=group_create)


# list all Groups
@router.get('/', tags=[model.plural], status_code=200, response_model=list[Group])
async def list_groups(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    try:
        groups = crud.get_groups(db, skip=skip, limit=limit)
        return groups
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error")


# get a group
@router.get('/{group_name}', tags=[model.plural], status_code=200, response_model=Group)
async def get_group(name: str, db: Session = Depends(get_db)):
    group = crud.get_group_by_name(db, name)
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found")
    return group


# Update
@router.put('/{group_name}', tags=[model.plural], status_code=200, response_model=Group)
async def update_group(request: GroupBase, db: Session = Depends(get_db)):
    group_exist = crud.get_group_by_name(db, request.name)
    if not group_exist:
        raise HTTPException(status_code=404, detail="Group not found")
    crud.update_group(db, name=request.name, description=request.description)
    return group_exist


# Delete
@router.delete('/{group_name}', tags=[model.plural], status_code=202)
async def delete_group(name: str, db: Session = Depends(get_db)):
    group_exist = crud.get_group_by_name(db, name)
    if not group_exist:
        raise HTTPException(status_code=404, detail="Group not found")
    crud.remove_group(db, name)
    return {"detail": f"Group <{name}> deleted successfully !"}

