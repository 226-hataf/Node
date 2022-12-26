from typing import Optional
from pydantic import BaseModel, Field, validator
from uuid import uuid4, UUID


class GroupsRoleBase(BaseModel):
    roles_id: UUID
    groups_id: UUID


class GroupsUserBase(BaseModel):
    user_id: UUID
    groups_id: UUID
