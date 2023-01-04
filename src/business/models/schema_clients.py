import re
from pydantic import BaseModel, Field, validator, root_validator
from uuid import uuid4, UUID
import random
import string


def generate_client_secret():
    """Generates client_secret with described rule ZEK-553"""
    return ''.join(
        random.choices(
            string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation, k=32
        )
    )


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
    roles: list[str] = Field(description="List of valid roles to be granted for the service",
                             title="Granted Service Roles")

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
        if len(set(fields).intersection({"name", "email", "roles"})) > 2:
            # Request body cannot be empty and,
            # And must be sent all together in the request body.
            return values
        else:
            raise ValueError('All fields must be set in body')

    # Check if fields are empty or value=string or empty list !
    @validator("name", "email", "roles")
    def options_non_empty(cls, v):
        if v == '':
            assert v != '', 'Empty value not excepted ! '
        if v == [] or v == ['']:
            assert v != [], 'Empty list not excepted ! '
            assert v != [''], 'Empty list not excepted ! '
        if v == 'string':
            assert v != 'string', 'Value string not excepted ! '
        return v

    class Config:
        orm_mode = True


class ClientJWTSchema(ClientCreateSchema):
    client_id: UUID = Field(default_factory=uuid4, description="ID of the generated client", title="Client ID")
    expr: int = Field(description="Generated JWT has fixed 30M lifetime and stored in Redis", title="Expiry time in Minutes")
    iss: str = Field(description="JWT generated with issuer", title="The issuer")
    client_token: str = Field(description="JWT token includes client info", title="JWT Token")

    # Check if fields are empty
    @validator("expr", "iss", "client_token", "client_id")
    def options_non_empty(cls, v):
        if v == '':
            assert v != '', 'Empty value not excepted ! '
        return v

    class Config:
        orm_mode = True
