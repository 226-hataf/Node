from typing import List
from business.models.users import UserRequest, User, UserLoginSchema
from datetime import date
from core import log
import os


class Provider:
    def __init__(self) -> None:
        # ZeAuth Bootstraping
        self.zeauth_bootstrap()


class SignupSendNotificationError(Exception):
    """Raised when notification email not send"""
    pass


class TemplateNotificationError(Exception):
    """Raised when notification template create error"""
    pass

class CreateNotificationError(Exception):
    """Raised when creating notification error"""
    pass

class ResetPasswordSendNotificationError(Exception):
    """Raised when reset password link could not send"""
    pass

class DuplicateEmailError(Exception):
    pass


class PasswordPolicyError(Exception):
    pass


class InvalidTokenError(Exception):
    pass


class InvalidCredentialsError(Exception):
    pass


class UserNotVerifiedError(Exception):
    pass


class NotExistingResourceError(Exception):
    pass


class UserNotFoundError(Exception):
    pass


class UserNameError(Exception):
    pass


class IncorrectResetKeyError(Exception):
    pass
