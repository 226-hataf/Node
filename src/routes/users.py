from fastapi import APIRouter

router = APIRouter()

@router.post('/users', tags=['users'])
async def list_users():
    return []

@router.get('/users/{user_id}', tags=['users'])
async def get_user(user_id: str):
    return {}

