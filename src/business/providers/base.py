from typing import List
from business.models.users import User
from core import log
class Provider:

    def signup(self, user: User):
        log.error(f"method signup not implement for provider")

    def signin(self, username: str, password: str):
        log.error(f"method signin not implement for provider")

    def delete_user(self, user_id: str):
        log.error(f"method delete_user not implement for provider")

    def list_users(self, page:str, page_size:int):
        log.error(f"method list_users not implement for provider")

    def get_user(self, user_id: str):
        log.error(f"method get_user not implement for provider")

    def update_user_roles(self, new_role: list[str], user_id: str):
        log.error(f"method update_user_roles not implement for provider")

    def update_user(self, user_id: str, user: User):
        log.error(f"method update_user not implement for provider")

    def suspend_user(self, user_id: str):
        log.error(f"method suspend_user not implement for provider")
    
    def activate_user(self, user_id: str):
        log.error(f"method activate_user not implement for provider")

    # ROLES
    def create_role(self, name: str, permissions: List[str], description: str):
        log.error(f'method create_role not implemented for provider')
    
    def list_specific_roles(self, name: str, page: str, page_size: int):
        log.error(f'method list_specific_roles not implemented for provider')

    def list_all_roles(self, page: str, page_size: int):
        log.error(f'method list_all_roles not implemented for provider')

    def update_role(self, name: str, new_permissions: List[str], description: str):
        log.error(f'method update_role not implemented for provider')

    def delete_role(self, name: str):
        log.error(f'method delete_role not implemented for provider')

    def verify(self, token: str):
        log.error(f'method verify not implemented for provider')

    def user_active_on(self, user_id: str):
        log.error(f'method user_active_on not implemented for provider')

    def user_active_off(self, user_id: str):
        log.error(f'method user_active_off not implemented for provider')


class DuplicateEmailError(Exception):
    pass
