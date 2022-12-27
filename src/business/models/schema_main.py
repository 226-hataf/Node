import uuid
from core import log
from pydantic import BaseModel, validator, Field
from uuid import UUID


class UUIDCheckerSchema(BaseModel):
    id : UUID  = Field(description="It checks the uuid format in fields with uuid parameters "
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
