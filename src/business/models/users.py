import email
import re
from typing import Optional, Union, List
from pydantic import BaseModel, validator

from .permissions import Permission

class User(BaseModel):
    id: Optional[Union[str, int]]
    email: str
    username: Optional[str]
    password: Optional[str]
    verified: Optional[bool]
    avatar_url: Optional[str]
    first_name: Optional[str]
    last_name: Optional[str]
    full_name: Optional[str]
    phone: Optional[str]
    createdAt: Optional[str]
    lastLoginAt: Optional[str]
    permissions: Optional[List]

    @validator('email')
    def check_email(cls, v):
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            assert "invalid email"
        assert v is not None, 'the user email is required'
        # return v
    
class Config:
    orm_mode = True

class UserResponseModel(BaseModel):
    next_page: Optional[str]
    user_list: Optional[List[User]]
    page_size: Optional[int]

