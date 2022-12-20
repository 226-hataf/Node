from typing import Optional
from pydantic import BaseModel
from uuid import UUID


class GroupUserA(BaseModel):
    users_id: Optional[UUID] | None = None
    name: Optional[str] | None = None

    class Config:
        orm_mode = True


class GroupUserB(GroupUserA):
    pass


class GroupAssign(BaseModel):
    name: list[str]

    class Config:
        orm_mode = True