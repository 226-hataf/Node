from typing import Optional
from pydantic import BaseModel, Field, validator
from pydantic.validators import datetime
from uuid import uuid4, UUID


class RoleBaseSchema(BaseModel):
    """
    TODO: I will add Roles name pattern here in the next Task: ZEK-657
    """
    name: str = Field(description="The name of Role", title="Role name")
    description: str = Field(description="Description of Role", title="Role description")

    @validator('name')
    def check_role_not_empty(cls, v):
        if v == '':
            assert v != '', 'Role name can not be empty ! '
        elif v == 'string':
            assert v != 'string', 'This role name is not acceptable '
        return v


class RoleSchema(RoleBaseSchema):
    id: UUID = Field(default_factory=uuid4, description="uuid's of Role", title="Role id's")
    created_on: Optional[datetime] = Field(default=None, description="Role created date", title="Role created date")
    updated_on: Optional[datetime] = Field(default=None, description="Role update date", title="Role update date")

    class Config:
        orm_mode = True
