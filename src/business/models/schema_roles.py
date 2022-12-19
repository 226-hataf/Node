from typing import Optional
from pydantic import BaseModel, Field, validator
from pydantic.validators import datetime
from uuid import uuid4, UUID


class RoleBase(BaseModel):
    """
    I will add Roles name pattern here in the next Task: ZEK-657
    """
    name: str
    description: str

    @validator('name')
    def check_role_not_empty(cls, v):
        if v == '':
            assert v != '', 'Role name can not be empty ! '
        elif v == 'string':
            assert v != 'string', 'This role name is not acceptable '
        return v


class Role(RoleBase):
    id: UUID = Field(default_factory=uuid4)
    created_on: Optional[datetime] = None
    updated_on: Optional[datetime] = None

    class Config:
        orm_mode = True