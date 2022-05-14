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

    def update_permissions(self, user_id:str):
        log.error(f"method verify_user not implement for provider")

    def update_user(self, old_user: User, new_user: User):
        log.error(f"method update_user not implement for provider")

    def suspend_user(self, user_id: str):
        log.error(f"method suspend_user not implement for provider")
    
    def activate_user(self, user_id: str):
        log.error(f"method activate_user not implement for provider")

class DuplicateEmailError(Exception):
    pass