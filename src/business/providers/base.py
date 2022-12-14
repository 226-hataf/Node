from typing import List
from business.models.users import UserRequest, User, UserLoginSchema
from core import log
import os


class Provider:
    def __init__(self) -> None:
        # ZeAuth Bootstraping
        self.zeauth_bootstrap()

    def zeauth_bootstrap(self):
        log.error(f"method zeauth_bootstrap not implement for firebase provider")

    @staticmethod
    def _enrich_user(user: User) -> User:
        if user.full_name is None and (user.first_name or user.last_name):
            first_name = user.first_name if user.first_name is not None else ''
            last_name = user.last_name if user.last_name is not None else ''
            user.full_name = str(first_name) + ' ' + str(last_name)
        if user.full_name and (user.last_name is None or user.first_name is None):
            user.first_name, user.last_name = user.full_name.split(' ')
        return user

    def signup(self, user: UserRequest, db):
        log.error(f"method signup not implement for {os.environ.get('AUTH_PROVIDER')} provider")

    def login(self, user_info: UserLoginSchema, db):
        log.error(f"method signin not implement for {os.environ.get('AUTH_PROVIDER')} provider")

    def delete_user(self, user_id: str):
        log.error(f"method delete_user not implement for {os.environ.get('AUTH_PROVIDER')} provider")

    def list_users(self, page: str, page_size: int, search: str, db):
        log.error(f"method list_users not implement for {os.environ.get('AUTH_PROVIDER')} provider")

    def get_user(self, user_ids: List[str]):
        log.error(f"method get_user not implement for {os.environ.get('AUTH_PROVIDER')} provider")

    def update_user_roles(self, new_role: List[str], user_id: str):
        log.error(f"method update_user_roles not implement for {os.environ.get('AUTH_PROVIDER')} provider")

    def update_user(self, user_id: str, user: User):
        log.error(f"method update_user not implement for {os.environ.get('AUTH_PROVIDER')} provider")

    def suspend_user(self, user_id: str):
        log.error(f"method suspend_user not implement for {os.environ.get('AUTH_PROVIDER')} provider")

    def activate_user(self, user_id: str):
        log.error(f"method activate_user not implement for {os.environ.get('AUTH_PROVIDER')} provider")

    # ROLES
    def create_role(self, name: str, permissions: List[str], description: str):
        log.error(f'method create_role not implemented for {os.environ.get("AUTH_PROVIDER")} provider')

    def get_role(self, name: str, page: str, page_size: int):
        log.error(f'method list_specific_roles not implemented for {os.environ.get("AUTH_PROVIDER")} provider')

    def list_roles(self, page: str, page_size: int):
        log.error(f'method list_all_roles not implemented for {os.environ.get("AUTH_PROVIDER")} provider')

    def update_role(self, name: str, new_permissions: List[str], description: str):
        log.error(f'method update_role not implemented for {os.environ.get("AUTH_PROVIDER")} provider')

    def delete_role(self, name: str):
        log.error(f'method delete_role not implemented for {os.environ.get("AUTH_PROVIDER")} provider')

    def verify(self, token: str):
        log.error(f'method verify not implemented for {os.environ.get("AUTH_PROVIDER")} provider')

    def user_active_on(self, user_id: str):
        log.error(f'method user_active_on not implemented for {os.environ.get("AUTH_PROVIDER")} provider')

    def user_active_off(self, user_id: str):
        log.error(f'method user_active_off not implemented for {os.environ.get("AUTH_PROVIDER")} provider')

    def reset_password_verify(self, reset_pass, db):
        pass

    def reset_password(self, user_info, db):
        pass


class DuplicateEmailError(Exception):
    pass


class PasswordPolicyError(Exception):
    pass


class UnauthorizedError(Exception):
    pass


class InvalidTokenError(Exception):
    pass


class InvalidCredentialsError(Exception):
    pass


class NotExistingResourceError(Exception):
    pass


class LimitExceededError(Exception):
    pass


class CustomKeycloakConnectionError(Exception):
    pass


class CustomKeycloakPostError(Exception):
    pass


class UserNotFoundError(Exception):
    pass


class CustomKeycloakPutError(Exception):
    pass


class CustomKeycloakInvalidGrantError(Exception):
    pass


class IncorrectResetKeyError(Exception):
    pass
