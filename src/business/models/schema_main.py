import uuid
from core import log
from pydantic import BaseModel, validator, Field
from uuid import UUID


class UUIDCheckForGroupIdSchema(BaseModel):
    group_id: UUID = Field(description="It checks the uuid format in group_id fields with uuid parameters "
                                       "and returns an error if it does not conform to the uuid format.",
                           title="UUID Format Checker")

    @validator('group_id')
    def check_id_format(cls, v):
        try:
            if uuid.UUID(str(v)):
                return v
        except ValueError as e:
            log.error(e)
            return {"detail": "invalid uuid"}


class UUIDCheckForIDSchema(BaseModel):
    id: UUID = Field(description="It checks the uuid format in ID fields with uuid parameters "
                                 "and returns an error if it does not conform to the uuid format.",
                     title="UUID Format Checker")

    @validator('id')
    def check_id_format(cls, v):
        try:
            if uuid.UUID(str(v)):
                return v
        except ValueError as e:
            log.error(e)
            return {"detail": "invalid uuid"}


class UUIDCheckForUserIDSchema(BaseModel):
    user_id: UUID = Field(description="It checks the uuid format in user_id fields with uuid parameters "
                                      "and returns an error if it does not conform to the uuid format.",
                          title="UUID Format Checker")

    @validator('user_id')
    def check_id_format(cls, v):
        try:
            if uuid.UUID(str(v)):
                return v
        except ValueError as e:
            log.error(e)
            return {"detail": "invalid uuid"}
