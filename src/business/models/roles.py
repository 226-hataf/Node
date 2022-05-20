from typing import List, Optional
from pydantic import BaseModel, validator


class Roles(BaseModel):
    role_name: Optional[str]
    roles: Optional[List[str]]
    description: Optional[str]
    next_page: Optional[str]
    page_size: Optional[int]


    @validator('role_name')
    def name_cannot_contain_space(cls, v):
        if ' ' in v:
            raise ValueError('name cannot contain a space')
        return v.title()