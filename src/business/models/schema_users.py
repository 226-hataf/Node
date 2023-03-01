import re
from typing import Optional, List
from pydantic import BaseModel, validator, Field, root_validator
from uuid import uuid4, UUID
from pydantic.validators import datetime
from core import log


class ZeBaseModel(BaseModel):
    class Config:
        orm_mode = True
        extra = "forbid"  # to disallow extra fields


class UserActivationProcessResponseSchema(ZeBaseModel):
    user_id: UUID = Field(default_factory=uuid4, description="uuid's of User", title="User id's")
    user_activation: str = Field(description="User activation status", title="User Activation", example="ON/OFF")


class UsersWithIDsSchema(ZeBaseModel):
    users_ids: Optional[list[UUID]] = Field(description="User's uuid's in a list", title="User's uuid's")

    @validator("users_ids")
    def options_non_empty(cls, v):
        if v == [] or v == ['']:
            assert v != [], 'Empty list not excepted ! '
        return v


class UserUpdateSchema(ZeBaseModel):
    """Only these fields are related to update a current user"""
    first_name: Optional[str] = Field(description="User's first name", title="User's first name", example="test")
    last_name: Optional[str] = Field(description="User's last name", title="User's last name", example="ze")
    verified: Optional[bool] = Field(description="User's verified status true/false", title="User's verified status")
    user_status: Optional[bool] = Field(description="User's active status true/false", title="User's active status")
    phone: Optional[str] = Field(description="User's phone", title="User's phone", example="555-55-55")

    @validator("first_name", "last_name")
    def options_non_empty(cls, v):
        if v == '':
            assert v != '', 'Empty value not excepted ! '
        return v

    @root_validator(pre=True)
    def check_field(cls, values):
        print(values)
        if len(values) > 0:
            return values
        else:
            raise ValueError('Request body can not be empty !')


class UserResponseSchema(ZeBaseModel):
    """created user's response"""
    id: Optional[UUID] = Field(description="User's uuid", title="User's uuid")
    email: Optional[str] = Field(description="User's email", title="User's email", example="test-ze@test.com")
    password: Optional[str] = Field(description="User's password", title="User's password", example="gAAAAABjw0VGdYxDbneai8bdfPdTov-A9WKT6M10C8dR7bun0_cJ1Hfz2D")
    user_name: Optional[str] = Field(description="User's username", title="User's username", example="test-ze@test.com")
    first_name: Optional[str] = Field(description="User's first name", title="User's first name", example="test")
    last_name: Optional[str] = Field(description="User's last name", title="User's last name", example="ze")
    verified: Optional[bool] = Field(description="User's verified status true/false", title="User's verified status")
    user_status: Optional[bool] = Field(description="User's active status true/false", title="User's active status")
    phone: Optional[str] = Field(description="User's phone", title="User's phone", example="555-55-55")
    created_on: Optional[datetime] = Field(description="User's created time on system", title="User's created time")
    updated_on: Optional[datetime] = Field(description="User's last updated time on system", title="User's last updated time")
    last_login_at: Optional[datetime] = Field(description="User's last login time on system", title="User's last login time")


class UserCreateSchema(ZeBaseModel):
    """user create schema"""
    email: str = Field(description="User's email", title="User's email", example="test-ze@test.com")
    user_name: Optional[str] = Field(description="User's username", title="User's username")
    password: Optional[str] = Field(description="User's password", title="User's password", example="Te&te&123")
    first_name: Optional[str] = Field(description="User's first name", title="User's first name", example="test")
    last_name: Optional[str] = Field(description="User's last name", title="User's last name", example="ze")
    verified: Optional[bool] = Field(description="Users verified status true/false", title="Users verified status")
    user_status: Optional[bool] = Field(description="Users active status true/false", title="Users active status")
    phone: Optional[str] = Field(description="User's phone", title="User's phone", example="555-55-55")

    @validator('email')
    def check_email(cls, email):
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise ValueError("invalid email format")
        return email

    @validator('password')
    def check_password(cls, password):
        """
        Password generation fails if the pattern rules are not met.!
        not Less than 8 character
        Not containing at least one number
        Not containing at least one capital letter
        Not containing at least one small letter
        Not containing at least one special character
        :param password:
        :return:
        """
        patterns = {'([A-Z])': 'one capital letter,',
                    '([a-z])': 'one small letter,',
                    '([0-9])': 'one number,',
                    '([#?!@$%^&*-])': 'one special character'}

        if len(password) >= 8:
            log.debug(password)
            result = ' '.join([v for k, v in patterns.items() if not re.search(k, password)])
            if result:
                log.debug(result)
                raise ValueError(f"Password needs at least {result}")
            else:
                return password
        else:
            raise ValueError("invalid password format")


class UserWithIDList(ZeBaseModel):
    id: Optional[UUID] = Field(description="Users uuid", title="Users uuid")
    email: Optional[str] = Field(description="Users email", title="Users email", example="test-ze@test.com")
    first_name: Optional[str] = Field(description="Users first name", title="Users first name", example="test")
    last_name: Optional[str] = Field(description="Users last name", title="Users last name", example="ze")
    full_name: Optional[str] = Field(description="Users full name", title="Users full name", example="test ze")
    username: Optional[str] = Field(description="Users username", title="Users username", example="test-ze@test.com")
    verified: Optional[bool] = Field(description="Users verified status True/False", title="Users verified status")
    user_status: Optional[bool] = Field(description="Users active status ON/OFF", title="Users active status")
    phone: Optional[str] = Field(description="Users phone", title="Users phone", example="555-55-55")
    created_on: Optional[datetime] = Field(description="Users created time on system", title="Users created time")
    last_login_at: Optional[datetime] = Field(description="Users last login time on system", title="Users last login time")
    updated_on: Optional[datetime] = Field(description="Users last updated time on system", title="Users last updated time")
    groups: Optional[List[str]] = Field(description="Users Groups Permissions", title="Users Group",
                                        example=["admin", "user"])
    roles: Optional[List[str]] = Field(description="Users Roles Permissions", title="Users Roles",
                                       example=["zekoder-zeauth-users-create", "zekoder-zeauth-users-list"])


class UsersWithIDsResponseSchema(BaseModel):
    user: list[UserWithIDList]

