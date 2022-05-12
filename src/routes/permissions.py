from fastapi import APIRouter, Depends

from business import Permission
from business.models.dependencies import CommonDependencies
from core import ZKModel

router = APIRouter()


model = ZKModel(**{
        "name": 'permission',
        "plural": 'permissions',
        "fields": [{"name" : 'id', "pk": True}]
    })

@router.post('/', tags=[model.plural])
async def create(permission: Permission):
    return {}

create.__doc__ = f" Create a new {model.name}".expandtabs()


@router.get('/', tags=[model.plural])
async def list(commons: CommonDependencies=Depends(CommonDependencies)):
    return commons

list.__doc__ = f" List {model.plural}".expandtabs()

@router.get('/{permission_id}', tags=[model.plural])
async def get(permission_id: str):
    return {}

get.__doc__ = f" Get a specific {model.name} by it s id".expandtabs()


@router.put('/{permission_id}', tags=[model.plural], status_code=201)
async def update(permission_id: str, permission: Permission):
    return {}

update.__doc__ = f" Update a {model.name} by its id and payload".expandtabs()


@router.delete('/{permission_id}', tags=[model.plural], status_code=201)
async def delete(permission_id: str):
    return {}

delete.__doc__ = f" Delete a {model.name} by its id".expandtabs()
