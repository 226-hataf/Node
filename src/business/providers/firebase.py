from typing import List
from business.models.users import User
from .base import Provider, DuplicateEmailError
from firebase_admin import auth
from core import log
import firebase_admin
import jwt

firebase_admin.initialize_app()
class ProviderFirebase(Provider):

    @staticmethod
    def _enrich_user(user: User):
        if user.full_name is None and (user.first_name or user.last_name):
            return str(user.first_name) + ' ' + str(user.last_name)
        
        if user.full_name and (user.last_name is None or user.first_name is None):
            user.first_name, user.last_name = user.full_name.split(' ')

        return user

    def signup(self, user: User):
        try:
            new_user = auth.create_user(
                email=user.email,
                password=user.password,
                phone_number=user.phone,
                display_name=user.full_name,
                photo_url=user.avatar_url,
            )
            log.info(f'sucessfully created new user: {new_user.uid}')
            user.id = new_user.uid
            return ProviderFirebase._enrich_user(user)
        except auth.EmailAlreadyExistsError:
            raise DuplicateEmailError
        except Exception as e:
            raise e

    # def signin(self, username: str, password: str):
    #     auth.get_users([
    #         auth.UidIdentifier('uid1'),
    #     ])

    def delete_user(self, user_id: str):
        try:
            deleted_user = auth.get_user(user_id) # find the user to delete by its id
            auth.delete_user(deleted_user.uid) # delete the user by its unique id
            log.info(f'successfully deleted user {deleted_user.uid}')
            return deleted_user
        except Exception as e:
            raise e

    def _cast_user(self, data: dict):
        return User(
            id=data['localId'],
            email=data['email'],
            verified=data['emailVerified'],
            createdAt=data['createdAt'],
            lastLoginAt=data['lastLoginAt'],
        )
        
    def list_users(self, page: str, page_size: int):
        try:
            page = auth.list_users(max_results=page_size,page_token=page)

            next_page = page.next_page_token

            users = [self._cast_user(user._data) for user in page.users]

            return users, next_page, page._max_results
        except Exception as e:
            raise e

    def update_permissions(self, user_id: str, permissions: dict):
        uid = user_id
        
        additional_claims = {
            'ZK_auth_user_create': True,
            'ZK_auth_user_del': False,
            'ZK_chat_session_list': True
        }

        # compare permissions and additional_claims
        set_per = set(permissions.items())
        set_claims = set(additional_claims.items())

        keys_to_remove = dict(set_claims - set_per)

        for key in list(keys_to_remove):
            if key:
                additional_claims.pop(key)

        custom_token = auth.create_custom_token(uid, additional_claims) # {"ZK_zeauth_permissions": list(additional_claims.keys())}

        auth.set_custom_user_claims(uid, {"ZK_zeauth_permissions": list(additional_claims.keys())})
        
        return additional_claims # custom_token