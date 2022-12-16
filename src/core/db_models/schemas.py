from typing import Optional
from pydantic import BaseModel, Field
from pydantic.validators import datetime
from uuid import uuid4, UUID


class GroupBase(BaseModel):
    name: Optional[str]
    description: Optional[str]


class Group(GroupBase):
    id: UUID = Field(default_factory=uuid4)
    created_on: Optional[datetime] = None
    updated_on: Optional[datetime] = None

    class Config:
        orm_mode = True




