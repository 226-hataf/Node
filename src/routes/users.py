from fastapi import APIRouter

from business import User
from core.types import ZKModel

router = APIRouter()


model = ZKModel(**{
        "name": 'user',
        "plural": 'users',
        "fields": [{"name" : 'id', "pk": True}]
    })

@router.post('/', tags=[model.plural])
async def create(user: User):
    return {}

create.__doc__ = f" Create a new {model.name}".expandtabs()


@router.get('/', tags=[model.plural])
async def list():
    return []

list.__doc__ = f" List {model.plural}".expandtabs()

@router.get('/{user_id}', tags=[model.plural])
async def get(user_id: str):
    return {}

get.__doc__ = f" Get a specific {model.name} by it s id".expandtabs()


@router.put('/{user_id}', tags=[model.plural], status_code=201)
async def update(user_id: str, user: User):
    return {}

update.__doc__ = f" Update a {model.name} by its id and payload".expandtabs()


@router.delete('/{user_id}', tags=[model.plural], status_code=201)
async def delete(user_id: str):
    return {}

delete.__doc__ = f" Delete a {model.name} by its id".expandtabs()

@router.put('/{user_id}/on', tags=[model.plural], status_code=201)
async def active_on(user_id: str):
    return {}

@router.put('/{user_id}/off', tags=[model.plural], status_code=201)
async def active_off(user_id: str):
    return {}



active_on.__doc__ = f" Set {model.name}".expandtabs()
active_off.__doc__ = f" Delete a {model.name}".expandtabs()

