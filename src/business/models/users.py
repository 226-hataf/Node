import os
import re
from typing import Optional, Union, List
from pydantic import BaseModel, validator, ValidationError
from enum import Enum

from pydantic.validators import datetime


# from business.models.roles import Roles

# from .permissions import Permission

class RolesEnum(str, Enum):
    VIEW_APPLICATIONS = 'view-applications'
    UMA_PROTECTION = 'uma_protection'
    MANAGE_ACCOUNT = 'manage-account'
    MANAGE_ACCOUNT_LINKS = 'manage-account-links'
    MANAGE_CONSENT = 'manage-consent'
    VIEW_PROFILE = 'view-profile'
    DELETE_ACCOUNT = 'delete-account'
    VIEW_CONSENT = 'view-consent'
    LIST = "zk-zeauth-list"
    CREATE = "zk-zeauth-create"
    READ = "zk-zeauth-read"
    DELETE = "zk-zeauth-delete"
    UPDATE = "zk-zeauth-update"


class User(BaseModel):
    id: Optional[Union[str, int]]
    email: str
    roles: Optional[List[str]]
    groups: Optional[List[str]]
    username: Optional[str]
    password: Optional[str]
    verified: Optional[bool]
    user_status: Optional[bool]
    avatar_url: Optional[str]
    first_name: Optional[str]
    last_name: Optional[str]
    full_name: Optional[str]
    phone: Optional[str]
    created_at: Optional[datetime]
    last_login_at: Optional[datetime]
    update_at: Optional[datetime]
    permissions: Optional[List[str]]


class UserRequest(BaseModel):
    email: str
    roles: Optional[List[str]]
    username: Optional[str]
    password: Optional[str]
    first_name: Optional[str]
    last_name: Optional[str]
    full_name: Optional[str]
    phone: Optional[str]
    permissions: Optional[List[str]]

    @validator('email')
    def check_email(cls, email):
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise ValueError("invalid email format")
        return email

    @validator('password')
    def check_password(cls, password):
        if not re.match(r"(?!^[0-9]*$)(?!^[a-z]*$)(?!^[A-Z]*$)^(.{8,15})$", password):
            raise ValueError("invalid password format")
        return password


class Config:
    orm_mode = True


class UserResponseModel(BaseModel):
    next_page: Optional[str]
    user_list: Optional[List[User]]
    page_size: Optional[int]


class UserLoginSchema(BaseModel):
    email: str
    password: str


class ResendConfirmationEmailSchema(BaseModel):
    username: str


class LoginResponseModel(BaseModel):
    user: User
    uid: str
    accessToken: str
    refreshToken: str
    expirationTime: str


class ResetPasswordSchema(BaseModel):
    username: str


class ResetPasswordVerifySchema(BaseModel):
    reset_key: str
    new_password: str


class ConfirmationEmailVerifySchema(BaseModel):
    token: str


class UserActiveOnOff(BaseModel):
    uid: str


class UsersWithIDsResponse(BaseModel):
    total: int
    users: List[User]
