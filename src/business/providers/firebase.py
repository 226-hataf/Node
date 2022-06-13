import ast
from typing import List


from fastapi import HTTPException
import firebase_admin
from firebase_admin import auth, firestore

from business.models.users import User
from .base import Provider, DuplicateEmailError
from core import log

from business.models.users import *

class ProviderFirebase(Provider):
    db = None

    def __init__(self) -> None:
        super().__init__()
        if ProviderFirebase.db is None:
            firebase_admin.initialize_app()
            ProviderFirebase.db = firestore.client()

    @staticmethod
    def _enrich_user(user: User) -> User:
        if user.full_name is None and (user.first_name or user.last_name):
            first_name = user.first_name if user.first_name is not None else ''
            last_name = user.last_name if user.last_name is not None else ''
            user.full_name = str(first_name) + ' ' + str(last_name)
        if user.full_name and (user.last_name is None or user.first_name is None):
            user.first_name, user.last_name = user.full_name.split(' ')
        return user

    def signup(self, user: User):
        try:
            user = ProviderFirebase._enrich_user(user)
            if user.email is not None:
                new_user = auth.create_user(
                    email=user.email,
                    password=user.password,
                    phone_number=user.phone,
                    display_name= user.full_name,
                    photo_url=user.avatar_url,
                )
                log.info(f'sucessfully created new user: {new_user.uid}')
                user.id = new_user.uid
                return ProviderFirebase._enrich_user(user)
        except auth.EmailAlreadyExistsError:
            raise DuplicateEmailError
        except Exception as e:
            raise e

    def login(self, email: str, password: str):
        try:
            check_user = auth.get_user_by_email(email)
            raise HTTPException(status_code=403, detail="username or password are invalid")
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
            permissions = ast.literal_eval(data["customAttributes"])['zk-zeauth-permissions'] if "customAttributes" in data else [], 
            roles = ast.literal_eval(data["customAttributes"])["zk-zeauth-roles"] if "customAttributes" in data else [],full_name=data['displayName'] if "displayName" in data else None
        )
        
    def list_users(self, page: str, page_size: int):
        try:
            result = auth.list_users(max_results=page_size,page_token=page)
            users = [self._cast_user(user._data) for user in result.users]

            return users, result.next_page_token, result._max_results

        except Exception as e:
            raise e

    def get_user(self, user_id: str):
        try:
            user_info = auth.get_user(user_id)
            if user_info:
                return self._cast_user(user_info._data)
        except Exception as e:
            raise HTTPException(status_code=404, detail="the user is not found")


    def update_user_roles(self, new_role: List[str], user_id: str):
        try:
            uid = user_id
            update_user_role = auth.get_user(uid)
            if update_user_role:
                new_permissions = []
                for role in new_role:
                    role_ref =  ProviderFirebase.db.collection("zk-zauth-roles").document(role).get()
                    for pre in role_ref._data["permissions"]:
                        new_permissions.append(pre)
                auth.set_custom_user_claims(uid, {"zk-zeauth-permissions" : new_permissions, "zk-zeauth-roles" : new_role})
                user= auth.get_user(user_id)
                return self._cast_user(user._data)
        except Exception as e:
            raise e

    # CRUD ROLES
    def create_role(self, name: str, permissions: List[str], description: str):
        try:
            col_ref = ProviderFirebase.db.collection('zk-zauth-roles').document(name)

            col_ref.set({'role_name': name, 'permissions': permissions, 'description': description})

            return permissions
        except Exception as e:
            log.error(e)

    def list_specific_roles(self, name: str, page: str, page_size: int):
        try:
            page = auth.list_users(max_results=page_size, page_token=page)
            next_page = page.next_page_token

            docs = ProviderFirebase.db.collection('zk-zauth-roles').document(name).get()

            return docs.to_dict(), next_page, page._max_results#docs.to_dict()
        except Exception as e:
            log.error(e)
            log.error("no such document")

    def list_all_roles(self, page: str, page_size: int):
        try:
            page = auth.list_users(max_results=page_size, page_token=page)
            next_page = page.next_page_token
            docs = ProviderFirebase.db.collection('zk-zauth-roles').get()
            roles_list = []
            for doc in docs:
                roles_list.append(doc.to_dict())
            return roles_list, next_page, page._max_results
        except Exception as e:
            log.error(e)
            log.error("no such document")


    def update_role(self, name: str, new_permissions: List[str], description: str):
        try:
            doc = ProviderFirebase.db.collection("zk-zauth-roles").document(name)
            if doc.get()._exists:
                doc.update({'role_name': name, 'permissions': new_permissions, 'description': description})
            else:
                raise HTTPException(status_code=404, detail=f"there is no role named '{name}'")
        except Exception as e:
            log.error(e)


    def delete_role(self, name: str):
        try:
            doc = ProviderFirebase.db.collection("zk-zauth-roles").document(name)
            if doc.get()._exists:
                doc.delete()
                return name
            else:
                raise HTTPException(status_code=404, detail=f"there is no role named '{name}'")
        except Exception as e:
            log.error(e)

    def verify(self, token: str):
        try:
            decoded_token = auth.verify_id_token(token)
            return decoded_token
        except Exception as e:
            log.debug(e)
            raise HTTPException(403, "failed token verification")


    def user_active_on(self, user_id: str):
        try:
            updated_user = auth.get_user(user_id)
            if updated_user:
                user = auth.update_user(
                    uid= user_id,
                    disabled=False
                )
                log.info(f'sucessfully updated user {user.uid}')
                return user
            else:
                raise HTTPException(status_code=404, detail="there is no registered user to update")
        except Exception as e:
            raise e


    def user_active_off(self, user_id: str):
        try:
            updated_user = auth.get_user(user_id)
            if updated_user:
                user = auth.update_user(
                    uid= user_id,
                    disabled=True
                )
                log.info(f'sucessfully updated user {user.uid}')
                return user
            else:
                raise HTTPException(status_code=404, detail="there is no registered user to update")
        except Exception as e:
            raise e