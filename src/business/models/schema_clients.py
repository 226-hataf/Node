import re
import uuid
from typing import Optional, List
from pydantic import BaseModel, Field, validator, root_validator
from uuid import uuid4, UUID
import random
import string
from core import log


def generate_client_secret():
    """Generates client_secret with described rule ZEK-553"""
    return ''.join(
        random.choices(
            string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation, k=32
        )
    ).replace('"', '')  # when generating client_id remove "" for not get error on request body.
    # for example this generated id throws error "%*jt""3g@*4(!_O`sC,]_S'>BE;R@t4h\"


class ClientSchema(BaseModel):
    client_id: UUID = Field(default_factory=uuid4, description="ID of the generated client", title="Client ID")
    client_secret: str = Field(default=generate_client_secret(),
                               description="32 Long alphanumerical string with matching: "
                                           "[a-z][A-Z][0-9][-_%]", title="Client secret")

    # Check all fields are not empty and set in the body
    @root_validator(pre=True)
    def check_field(cls, values):
        fields = list(values.keys())
        if len(set(fields).intersection({"client_id", "client_secret"})) > 1:
            # Request body cannot be empty and,
            # And must be sent all together in the request body.
            return values
        else:
            raise ValueError('All fields must be set in body')

    @validator("client_id", "client_secret")
    def options_non_empty(cls, v):
        if v == '':
            assert v != '', 'Empty value not excepted ! '
        return v

    class Config:
        orm_mode = True


class ClientCreateSchema(BaseModel):
    name: str = Field(description="Name of Service", title="Service Name")
    email: str = Field(description="Email of Service", title="Service Email")
    groups: Optional[List[str]] = Field(description="Users Groups Permissions", title="Users Group",
                                        example=["admin", "user"])
    # Email format check
    @validator('email')
    def check_email(cls, email):
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise ValueError("invalid email format")
        return email

    # Check all fields are not empty and set in the body
    @root_validator(pre=True)
    def check_field(cls, values):
        fields = list(values.keys())
        if len(set(fields).intersection({"name", "email", "groups"})) > 2:
            # Request body cannot be empty and,
            # And must be sent all together in the request body.
            return values
        else:
            raise ValueError('All fields must be set in body')

    # Check if fields are empty or value=string or empty list !
    @validator("name", "email", "groups")
    def options_non_empty(cls, v):
        if v == '':
            assert v != '', 'Empty value not excepted ! '
        if v == [] or v == ['']:
            assert v != [], 'Empty list not excepted ! '
            assert v != [''], 'Empty list not excepted ! '
        if v == 'string':
            assert v != 'string', 'Value string not excepted ! '
        if v == ['string']:
            assert v != ['string'], 'Value string not excepted ! '
        return v

    class Config:
        orm_mode = True


class ClientJWTSchema(BaseModel):
    client_id: UUID = Field(default_factory=uuid4, description="ID of the generated client", title="Client ID")
    expr: int = Field(description="Generated JWT has fixed 30M lifetime and stored in Redis",
                      title="Expiry time in Minutes")
    name: str = Field(description="Name of Service", title="Service Name")
    owner: UUID = Field(default_factory=uuid4, description="ID of the client owner", title="Client Owner ID")
    iss: str = Field(description="JWT generated with issuer", title="The issuer")
    groups: List[str] = Field(description="Client Groups", title="Client Group")
    client_token: str = Field(description="JWT token includes client info", title="JWT Token")

    # Check if fields are empty
    @validator("client_id", "expr", "name", "owner", "iss", "client_token")
    def options_non_empty(cls, v):
        if v == '':
            assert v != '', 'Empty value not excepted ! '
        return v

    class Config:
        orm_mode = True


class UUIDCheckForClientIdSchema(BaseModel):
    client_id: UUID = Field(description="It checks the uuid format in client_id fields with uuid parameters "
                                       "and returns an error if it does not conform to the uuid format.",
                           title="UUID Format Checker")

    @validator('client_id')
    def check_id_format(cls, v):
        try:
            if uuid.UUID(str(v)):
                return v
        except ValueError as e:
            log.error(e)
            return {"detail": "invalid uuid"}

    class Config:
        orm_mode = True

