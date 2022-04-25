class Provider:

    def signup(self, user: User):
        log.error(f"method signup not implement for provider")

    def signin(self, usernmae: str, password: str):
        log.error(f"method asignin not implement for provider")

    def delete_user(self, user_id: str):
        log.error(f"method delete_user not implement for provider")

    def update_user(self, old_user: User, new_user: User):
        log.error(f"method update_user not implement for provider")

    def suspend_user(self, user_id: str):
        log.error(f"method suspend_user not implement for provider")
    
    def activate_user(self, user_id: str):
        log.error(f"method activate_user not implement for provider")
