from typing import Optional
from pydantic import BaseModel, Field, validator
from pydantic.validators import datetime
from uuid import uuid4, UUID


class GroupBaseSchema(BaseModel):
    name: str = Field(description="The name of Group", title="Group name")
    description: str = Field(description="Description of Group", title="Group description")

    @validator('name')
    def check_group_not_empty(cls, v):
        if v == '':
            assert v != '', 'Group name can not be empty ! '
        elif v == 'string':
            assert v != 'string', 'This group name is not acceptable '
        return v


class GroupSchema(GroupBaseSchema):
    id: UUID = Field(default_factory=uuid4, description="uuid's of Group", title="Group id's")
    created_on: Optional[datetime] = Field(default=None, description="Group created date", title="Group created date")
    updated_on: Optional[datetime] = Field(default=None, description="Group update date", title="Group update date")
    users_in_group: Optional[list[UUID]] = Field(description="User's uuid's in a group", title="User's uuid's")

    class Config:
        orm_mode = True


class GroupSchemaCreate(GroupBaseSchema):
    id: UUID = Field(default_factory=uuid4, description="uuid's of Group", title="Group id's")
    created_on: Optional[datetime] = Field(default=None, description="Group created date", title="Group created date")
    updated_on: Optional[datetime] = Field(default=None, description="Group update date", title="Group update date")

    class Config:
        orm_mode = True
