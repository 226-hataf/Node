import uuid
from business.models.schema_main import UUIDCheckForGroupIdSchema, UUIDCheckForUserIDSchema
from config.db import get_db
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import date, datetime
from business.models.users import UserResponseModel
from business.models.schema_users import UserActivationProcessResponseSchema, UsersWithIDsSchema, \
    UsersWithIDsResponseSchema, UserUpdateSchema, UserResponseSchema, UserCreateSchema
from business.providers.base import *
from business.providers import get_provider
from core import log, crud
from core.crud import assign_user_to_group, deassign_user_from_group
from core.types import ZKModel
from business.models.dependencies import CommonDependencies, ProtectedMethod
from fastapi import Query
from pydantic.schema import Enum


class SortByEnum(str, Enum):
    DESE = 'desc'
    ASC = 'asc'


class SortColumnEnum(str, Enum):
    CREATED_AT = 'created_at'
    USER_NAME = 'user_name'


router = APIRouter()

auth_provider: Provider = get_provider()

model = ZKModel(**{
    "name": 'user',
    "plural": 'users',
    "permissions": {
        'read': ['zk-zeauth-read'],
        'list': ['zk-zeauth-list'],
        'create': ['zk-zeauth-create'],
        'update': ['zk-zeauth-update'],
        'delete': ['zk-zeauth-delete']
    }
})


@router.post('/', tags=[model.plural], status_code=201, response_model=UserResponseSchema, description="Create new user")
async def create_new_user(user: UserCreateSchema, db: Session = Depends(get_db), token: str = Depends(ProtectedMethod)):
    """Create new user"""
    token.auth(model.permissions.create)
    try:
        return auth_provider.createNewUser(db, user)
    except ValueError as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error, check the logs")


# list users
@router.get('/', tags=[model.plural],
            status_code=200, response_model=UserResponseModel,
            response_model_exclude_none=True,
            )
async def list(
        token: str = Depends(ProtectedMethod),
        date_of_creation: date = Query(default=None),
        sort_by: SortByEnum = SortByEnum.DESE,
        sort_column: SortColumnEnum = Query(default=SortColumnEnum.CREATED_AT),
        date_of_last_login: date = Query(default=None),
        user_status: bool = Query(default=None),
        commons: CommonDependencies = Depends(CommonDependencies),
        db: Session = Depends(get_db)
):
    token.auth(model.permissions.list)
    try:
        user_list, next_page, page_size, total_count = auth_provider.list_users(
            page=commons.page,
            page_size=commons.size,
            search=commons.search,
            user_status=user_status,
            date_of_creation=date_of_creation,
            date_of_last_login=date_of_last_login,
            sort_by=sort_by,
            sort_column=sort_column,
            db=db
        )

        return {'next_page': next_page, 'page_size': page_size, 'user_list': user_list, 'total_count': total_count}
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error") from e


list.__doc__ = f" List all {model.plural}".expandtabs()


@router.post('/with_ids', tags=[model.plural], status_code=200, response_model=List[UsersWithIDsResponseSchema], description="Get current Users list with uuid's")
async def gets_current_users(users_ids: UsersWithIDsSchema, token: str = Depends(ProtectedMethod),  db: Session = Depends(get_db)):
    """Get Users list with user's uuid"""
    token.auth(model.permissions.read)
    try:
        return auth_provider.usersWithIDs(db, users_ids)
    except ValueError as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error, check the logs")


@router.put('/{user_id}', tags=[model.plural], status_code=200, response_model=UserUpdateSchema, description="Update current user")
async def updates_current_user(user_id: UUIDCheckForUserIDSchema = Depends(UUIDCheckForUserIDSchema),
                               user: UserUpdateSchema = ...,
                               db: Session = Depends(get_db), token: str = Depends(ProtectedMethod)):
    """Update current user"""
    token.auth(model.permissions.update)
    user_exist = crud.get_user_by_uuid(db, user_id)
    if not user_exist:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        return auth_provider.updateUser(db, user_id, user)
    except ValueError as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error, check the logs")


@router.delete('/{user_id}', tags=[model.plural], status_code=202, description="Delete current user")
async def deletes_current_user(user_id: UUIDCheckForUserIDSchema = Depends(UUIDCheckForUserIDSchema),
                               token: str = Depends(ProtectedMethod),
                               db: Session = Depends(get_db)):
    """Deletes current user"""
    token.auth(model.permissions.delete)
    user_exist = crud.get_user_by_uuid(db, user_id)
    if not user_exist:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        return auth_provider.deleteUser(db, user_id)
    except ValueError as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error, check the logs")


@router.put('/{user_id}/on', tags=[model.plural], status_code=201,
            response_model=UserActivationProcessResponseSchema, description="Activates user status ON")
async def user_active_on(user_id: UUIDCheckForUserIDSchema = Depends(UUIDCheckForUserIDSchema), db: Session = Depends(get_db)):
    """Activates user status ON"""
    user_exist = crud.get_user_by_uuid(db, user_id)
    if not user_exist:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        return auth_provider.userActivationProcess(db, user_id, q='ON')
    except ValueError as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error, check the logs")


@router.put('/{user_id}/off', tags=[model.plural], status_code=201,
            response_model=UserActivationProcessResponseSchema, description="Deactivates user status OFF")
async def user_active_off(user_id: UUIDCheckForUserIDSchema = Depends(UUIDCheckForUserIDSchema), db: Session = Depends(get_db)):
    """Deactivates user status OFF"""
    user_exist = crud.get_user_by_uuid(db, user_id)
    if not user_exist:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        return auth_provider.userActivationProcess(db, user_id, q='OFF')
    except ValueError as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error, check the logs")


@router.patch('/{user_id}/group/{group_id}', tags=[model.plural], status_code=200)
async def user_to_group(group_id: UUIDCheckForGroupIdSchema = Depends(UUIDCheckForGroupIdSchema),
                        user_id: uuid.UUID = ..., db: Session = Depends(get_db)):
    """Assign User to a Group"""
    checked_uuid = group_id.group_id
    group_exist = crud.get_group_by_id(db=db, id=str(checked_uuid))
    if not group_exist:
        raise HTTPException(status_code=404, detail="Group not found")
    try:
        data = assign_user_to_group(db, str(checked_uuid), user_id)
        return data
    except ValueError as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error, check the logs")


@router.patch('/{user_id}/group/{group_id}/remove', tags=[model.plural], status_code=200)
async def remove_user_from_group(group_id: UUIDCheckForGroupIdSchema = Depends(UUIDCheckForGroupIdSchema),
                                 user_id: uuid.UUID = ..., db: Session = Depends(get_db)):
    """Remove User from a Group"""
    checked_uuid = group_id.group_id
    group_exist = crud.get_group_by_id(db=db, id=str(checked_uuid))
    if not group_exist:
        raise HTTPException(status_code=404, detail="Group not found")
    try:
        data = deassign_user_from_group(db, str(checked_uuid), user_id)
        return data
    except ValueError as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error, check the logs")
