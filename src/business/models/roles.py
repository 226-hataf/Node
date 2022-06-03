from typing import List, Optional
from pydantic import BaseModel, validator

from business.models.permissions import Permission


class Roles(BaseModel):
    role_name: Optional[str]
    permissions: Optional[List[str]]
    description: Optional[str]
    next_page: Optional[str]
    page_size: Optional[int]


    @validator('role_name')
    def name_cannot_contain_space(cls, v):
        if ' ' in v:
            raise ValueError('name cannot contain a space')
        return v.title()