from typing import List
from business.models.users import User
from core import log
class Provider:

    def signup(self, user: User):
        log.error(f"method signup not implement for provider")

    def signin(self, username: str, password: str):
        log.error(f"method asignin not implement for provider")

    def delete_user(self, user_id: str):
        log.error(f"method delete_user not implement for provider")

    def list_users(self, page:str, page_size:int):
        log.error(f"method list_user not implement for provider")

    def get_user(self, user_id: str):
        log.error(f"method get_user not implement for provider")

    def update_user_permissions(self, user_id:str):
        log.error(f"method update_user_permissions not implement for provider")
    def update_user_roles(self, new_role: list[str], user_id: str):
        log.error(f"method update_user_permissions not implement for provider")
    def update_user(self, old_user: User, new_user: User):
        log.error(f"method update_user not implement for provider")

    def suspend_user(self, user_id: str):
        log.error(f"method suspend_user not implement for provider")
    
    def activate_user(self, user_id: str):
        log.error(f"method activate_user not implement for provider")

    # ROLES
    def create_role(self, name: str, permissions: List[str]):
        log.error(f'method create_roles not implemented for provider')
    
    def list_specific_roles(self, name: str, page: str, page_size: int):
        log.error(f'method list_specific_roles not implemented for provider')

    def list_all_roles(self, page: str, page_size: int):
        log.error(f'method list_all_roles not implemented for provider')

    def update_role(self, name: str, new_permissions: List[str]):
        log.error(f'method update_roles not implemented for provider')

    def delete_role(self, role_name: str):
        log.error(f'method delete_role not implemented for provider')


class DuplicateEmailError(Exception):
    pass

class RequiredField(Exception):
    pass