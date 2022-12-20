from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from business.models.schema_roles import RoleBase, Role
from business.providers import get_provider
from business.providers.base import *
from config.db import get_db
from core import log, crud
from core.types import ZKModel
import uuid

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
@router.post('/', tags=[model.plural], status_code=201, response_model=Role)
async def create(role_create: RoleBase, db: Session = Depends(get_db)):
    print(role_create)
    # check if role name exist, do not create group request
    role_exist = crud.get_role_by_name(db, role_create.name)
    if role_exist:
        raise HTTPException(status_code=400, detail="Role already exist !")
    return crud.create_role(db=db, role_create=role_create)


# list all Roles
@router.get('/', tags=[model.plural], status_code=200, response_model=list[Role])
async def list(skip: int = 0, limit: int = 20, db: Session = Depends(get_db)):
    try:
        roles = crud.get_roles(db, skip=skip, limit=limit)
        return roles
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error")


# get a role
@router.get('/{role_name}', tags=[model.plural], status_code=200, response_model=Role)
async def role(name: str, db: Session = Depends(get_db)):
    role_get = crud.get_role_by_name(db, name)
    if role_get is None:
        raise HTTPException(status_code=404, detail="Role not found")
    return role_get


# Update role
@router.put('/{id}', tags=[model.plural], status_code=200)
async def update(id: str, name: str, description: str, db: Session = Depends(get_db)):
    try:
        # check if uuid is valid
        uuid.UUID(str(id))
        role_exist = crud.get_role_by_id(db, id)
        if not role_exist:
            raise HTTPException(status_code=404, detail="Role not found")
        updated = crud.update_role(db=db, id=id, name=name, description=description)
        return updated
    except ValueError as e:
        log.error(e)
        return {"detail": "invalid uuid"}


# Delete role
@router.delete('/{role_name}', tags=[model.plural], status_code=202)
async def delete(name: str, db: Session = Depends(get_db)):
    role_exist = crud.get_role_by_name(db, name)
    if not role_exist:
        raise HTTPException(status_code=404, detail="Role not found")
    crud.remove_role(db, name)
    return {"detail": f"Role <{name}> deleted successfully !"}
