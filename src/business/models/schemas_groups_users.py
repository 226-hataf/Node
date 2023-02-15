from typing import Optional
from pydantic import BaseModel, root_validator, validator, Field
from uuid import UUID


class GroupUserRoleSchema(BaseModel):  # Always use Schema at end of Schema classes
    users: Optional[list[UUID]] = Field(description="Users uuid's to be assign/deassign to a group",
                                        title="Users uuid's")
    roles: Optional[list[UUID]] = Field(description="Roles uuid's to be assigned/deassign to a group",
                                        title="Roles uuid's")

    @root_validator(pre=True)
    def check_field(cls, values):
        fields = list(values.keys())
        if len(set(fields).intersection({"users", "roles"})) == 1:
            # Request body cannot be empty and,
            # Only one of these (users or roles) can be sent in the request body.
            return values
        else:
            raise ValueError('Neither users nor roles are set in body')

    class Config:
        orm_mode = True
