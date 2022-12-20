import uuid
from fastapi import APIRouter, Depends, HTTPException
from pydantic.validators import Union
from business.providers import get_provider
from business.providers.base import *
from core import log
from core.crud import update_user_group, group_name_exists
from core.types import ZKModel
from business.models.schemas_groups_users import GroupUserA, GroupUserB, GroupAssign
from core import crud
from config.db import get_db
from sqlalchemy.orm import Session

router = APIRouter()
auth_provider: Provider = get_provider()

model = ZKModel(**{
    "name": 'assignment',
    "plural": 'assignments',
    "permissions": {
        'read': ['zk-zeauth-read'],
        'list': ['zk-zeauth-list'],
        'create': ['zk-zeauth-create'],
        'update': ['zk-zeauth-update'],
        'delete': ['zk-zeauth-delete']
    }
})


@router.get('/{user_id}', tags=[model.plural], status_code=200, response_model=Union[list[GroupUserA] | GroupUserB])
async def get_group_of_user(user_id: str, db: Session = Depends(get_db)):
    try:
        # Check every uuid when needed, to not get uuid format error
        # check if uuid is valid
        # data_dict = [v for k, v in user_group] # use this in users api to fetch group field
        # if they want, you can also use it here, you must remove response model.
        uuid.UUID(str(user_id))
        user_group = crud.get_groups_of_user_by_id(db, user_id)
        if not user_group:
            raise HTTPException(status_code=404, detail="User not found")
        return user_group
    except ValueError as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="Invalid uuid format")


@router.put('/{user_id}', tags=[model.plural], status_code=200)
async def assign_group_to_user(user_id: str, groups: list, db: Session = Depends(get_db)):
    try:
        if group_name_exists(db, groups) is True:
            return update_user_group(db, user_id, groups)
    except ValueError as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="Unknown Error")