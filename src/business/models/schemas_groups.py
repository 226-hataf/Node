from typing import Optional
from pydantic import BaseModel, Field, validator
from pydantic.validators import datetime
from uuid import uuid4, UUID


class GroupBase(BaseModel):
    name: str
    description: str

    @validator('name')
    def check_group_not_empty(cls, v):
        if v == '':
            assert v != '', 'Group name can not be empty ! '
        elif v == 'string':
            assert v != 'string', 'This group name is not acceptable '
        return v


class Group(GroupBase):
    id: UUID = Field(default_factory=uuid4)
    created_on: Optional[datetime] = None
    updated_on: Optional[datetime] = None

    class Config:
        orm_mode = True
