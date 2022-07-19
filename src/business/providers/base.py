from typing import List
from business.models.users import User
from core import log

class Provider:
    def __init__(self) -> None:
        # ZeAuth Bootstraping
        self.zeauth_bootstrap()

    def zeauth_bootstrap(self):
        log.error(f"method zeauth_bootstrap not implement for firebase provider")

    def signup(self, user: User):
        log.error(f"method signup not implement for firebase provider")

    def login(self, email: str, password: str):
        log.error(f"method signin not implement for firebase provider")

    def delete_user(self, user_id: str):
        log.error(f"method delete_user not implement for firebase provider")

    def list_users(self, page:str, page_size:int):
        log.error(f"method list_users not implement for firebase provider")

    def get_user(self, user_id: str):
        log.error(f"method get_user not implement for firebase provider")

    def update_user_roles(self, new_role: list[str], user_id: str):
        log.error(f"method update_user_roles not implement for firebase provider")

    def update_user(self, user_id: str, user: User):
        log.error(f"method update_user not implement for firebase provider")

    def suspend_user(self, user_id: str):
        log.error(f"method suspend_user not implement for firebase provider")
    
    def activate_user(self, user_id: str):
        log.error(f"method activate_user not implement for firebase provider")

    # ROLES
    def create_role(self, name: str, permissions: List[str], description: str):
        log.error(f'method create_role not implemented for firebase provider')
    
    def get_role(self, name: str, page: str, page_size: int):
        log.error(f'method list_specific_roles not implemented for firebase provider')

    def list_roles(self, page: str, page_size: int):
        log.error(f'method list_all_roles not implemented for firebase provider')

    def update_role(self, name: str, new_permissions: List[str], description: str):
        log.error(f'method update_role not implemented for firebase provider')

    def delete_role(self, name: str):
        log.error(f'method delete_role not implemented for firebase provider')

    def verify(self, token: str):
        log.error(f'method verify not implemented for firebase provider')

    def user_active_on(self, user_id: str):
        log.error(f'method user_active_on not implemented for firebase provider')

    def user_active_off(self, user_id: str):
        log.error(f'method user_active_off not implemented for firebase provider')


class DuplicateEmailError(Exception):
    pass

class UnauthorizedError(Exception):
    pass

class InvalidTokenError(Exception):
    pass

class InvalidCredentialsError(Exception):
    pass

class NotExisitngResourceError(Exception):
    pass