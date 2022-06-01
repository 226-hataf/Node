from typing import List

from fastapi import HTTPException
from business.models.users import User
from business.models.roles import Roles
from .base import Provider, DuplicateEmailError
from firebase_admin import auth, firestore
from core import log
import firebase_admin




class ProviderFirebase(Provider):
    db = None

    def __init__(self) -> None:
        super().__init__()
        if ProviderFirebase.db is None:
            firebase_admin.initialize_app()
            ProviderFirebase.db = firestore.client()
    @staticmethod
    def _enrich_user(user: User):
        if user.full_name is None and (user.first_name or user.last_name):
            return str(user.first_name) + ' ' + str(user.last_name)
        
        if user.full_name and (user.last_name is None or user.first_name is None):
            user.first_name, user.last_name = user.full_name.split(' ')

        return user

    def signup(self, user: User):
        try:
            if user.email is None:
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
            else:
                raise e
        except auth.EmailAlreadyExistsError:
            raise DuplicateEmailError
        except Exception as e:
            raise e


    def delete_user(self, user_id: str):
        try:
            deleted_user = auth.get_user(user_id) # find the user to delete by its id
            if deleted_user:
                auth.delete_user(deleted_user.uid) # delete the user by its unique id
                log.info(f'successfully deleted user {deleted_user.uid}')
                return deleted_user
        except Exception as e:
            raise e

    def update_user(self, user_id: str, user: User):
        try:
            updated_user = auth.get_user(user_id)
            if updated_user:
                user = auth.update_user(
                    uid=user_id,
                    email=user.email,
                    phone_number=user.phone,
                    password=user.password,
                    display_name=user.full_name,
                    photo_url=user.avatar_url,
                )
                log.info(f'sucessfully updated user {user.uid}')
                return user
            else:
                raise HTTPException(status_code=404, detail="there is no registered user to update")
        except Exception as e:
            log.error(e)
            # raise e

    def _cast_user(self, data: dict):
        return User(
            id=data['localId'],
            email=data['email'],
            verified=data['emailVerified'],
            createdAt=data['createdAt'],
            # lastLoginAt=data['lastLoginAt'],
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
        try:    
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
        except Exception as e:
            log.error(e)

    # CRUD ROLES
    def create_role(self, name: str, permissions: List[str], description: str):
        try:
            col_ref = ProviderFirebase.db.collection(name).document('role')

            col_ref.set({'role_name': name, 'permissions': permissions, 'description': description})

            return permissions
        except Exception as e:
            log.error(e)

    def list_roles(self, name: str, page: str, page_size: int):
        try:
            page = auth.list_users(max_results=page_size,page_token=page)
            next_page = page.next_page_token

            docs = ProviderFirebase.db.collection(name).get()
            roles_list = {}
            for doc in docs:
                roles_list.update(doc.to_dict())

            return name, roles_list, next_page, page._max_results#docs.to_dict()
        except Exception as e:
            log.error(e)
            log.error("no such document")

    def update_role(self, name: str, new_permissions: List[str], description: str):
        try:
            doc = ProviderFirebase.db.collection(name).document('role')
            if doc.get()._exists:
                doc.update({'role_name': name, 'permissions': new_permissions, 'description': description})
            else:
                raise HTTPException(status_code=404, detail=f"there is no role named '{name}'")
        except Exception as e:
            log.error(e)


    def delete_role(self, name: str):
        try:
            doc = ProviderFirebase.db.collection(name).document('role')
            if doc.get()._exists:
                doc.delete()
                return name
            else:
                raise HTTPException(status_code=404, detail=f"there is no role named '{name}'")
        except Exception as e:
            log.error(e)
