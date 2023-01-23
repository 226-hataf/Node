from typing import Optional
from pydantic import BaseModel, Field, validator
from pydantic.validators import datetime
from uuid import uuid4, UUID
import re


class RoleBaseSchema(BaseModel):
    """
    Roles name patterns are added -> Task: ZEK-657
    """
    name: str = Field(description="The name of Role", title="Role name",
                      example="[provider short name]-[app short name]-[resource name]-[permission name]")
    description: str = Field(description="Description of Role", title="Role description")

    @validator('name')
    def check_role_not_empty(cls, v):
        pattern = re.compile(r"^[a-z]+(-[a-z]+-[a-z]+-[a-z]+)$")  # Roles name rules pattern
        special_char = re.compile(r"[!#$%&\'()*+,./:_;<=>?@\\ ]")  # special char and spaces
        latin_char = re.compile(r'[^\x00-\x7f]')    # latin characters rules pattern
        upper_case = r'(?=.*[A-Z])'  # uppercase rules pattern
        if v == '':
            assert v != '', 'Role name can not be empty !'
        if special_char.search(v):
            assert not special_char.search(v), 'Role name cannot contain special characters or spaces !'
        if latin_char.search(v):
            assert not latin_char.search(v), 'Role name cannot contain latin characters !'
        if re.search(upper_case, v):
            assert not re.search(upper_case, v), 'Role name cannot contain uppercase !'
        if v == 'string':
            assert v != 'string', 'Role name is not acceptable !'
        if not re.match(pattern, v):
            assert re.match(pattern, v), "Role's name pattern should be " \
                                         "[provider short name]-[app short name]-[resource name]-[permission name]"
        return v


class RoleSchema(RoleBaseSchema):
    id: UUID = Field(default_factory=uuid4, description="uuid's of Role", title="Role id's")
    created_on: Optional[datetime] = Field(default=None, description="Role created date", title="Role created date")
    updated_on: Optional[datetime] = Field(default=None, description="Role update date", title="Role update date")

    class Config:
        orm_mode = True
