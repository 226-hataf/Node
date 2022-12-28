from typing import Optional
from pydantic import BaseModel, Field, validator
from uuid import uuid4, UUID


class GroupsRoleBase(BaseModel):
    roles: UUID
    groups: UUID


class GroupsUserBase(BaseModel):
    users: UUID
    groups_id: UUID
