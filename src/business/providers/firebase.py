from pickletools import int4
from typing import List
from unittest.util import strclass

from fastapi import HTTPException
from business.models.permissions import Permission
from business.models.users import User
from business.models.roles import Roles
from .base import Provider, DuplicateEmailError, RequiredField
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
            if user.email is not None:
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
            # raise HTTPException(status_code=422, detail=f"the user email is required ")
            # raise e


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
            result = auth.list_users(max_results=page_size, page_token=page)

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

    # def update_user_permissions(self, user_id: str, new_list_permissions: list):
    #     try:    
    #         uid = user_id
    #         user_info = auth.get_user(uid)
    #         # compare permissions and additional_claim

    #         #custom_token = auth.create_custom_token(uid, new_list_permissions) # {"ZK_zeauth_permissions": list(additional_claims.keys())}

    #         auth.set_custom_user_claims(uid, new_list_permissions)
            
    #         return new_list_permissions # custom_token
    #     except Exception as e:
    #         log.error(e)

    def update_user_roles(self, new_role: list[str], user_id: str):
        try:
            uid = user_id
            update_user_role = auth.get_user(uid)
            if update_user_role:
                new_roles = {}
                new_permissions = {}
                for role in new_role:
                    new_roles.update({f'{role}': True})
                    role_ref = ProviderFirebase.db.collection("ZK_roles_test").document(role).get()
                    # the permissions of the new roles
                    role_permissions = role_ref._data["permissions"]

                    for pre in role_permissions:
                       new_permissions.update({f'{pre}': True})
                
                    auth.set_custom_user_claims(uid, new_permissions)
            
                #auth.set_custom_user_claims(uid, new_roles)

                
                return list(new_permissions.keys())
        except Exception as e:
            raise e

    # CRUD ROLES
    def create_role(self, name: str, permissions: List[str], description: str):
        try:
            col_ref = ProviderFirebase.db.collection('ZK_roles_test').document(name)

            col_ref.set({'role_name': name, 'permissions': permissions, 'description': description})

            return permissions
        except Exception as e:
            log.error(e)

    def list_specific_roles(self, name: str, page: str, page_size: int):
        try:
            page = auth.list_users(max_results=page_size,page_token=page)
            next_page = page.next_page_token

            docs = ProviderFirebase.db.collection('ZK_roles_test').document(name).get()
            # for doc in docs:
            #     roles_list.update(doc.to_dict())

            return docs.to_dict(), next_page, page._max_results#docs.to_dict()
        except Exception as e:
            log.error(e)
            log.error("no such document")

    def list_all_roles(self, page: str, page_size: int):
        try:
            page = auth.list_users(max_results=page_size,page_token=page)
            next_page = page.next_page_token
            docs = ProviderFirebase.db.collection('ZK_roles_test').get()
            roles_list = []
            for doc in docs:
                roles_list.append(doc.to_dict())
            return roles_list, next_page, page._max_results
        except Exception as e:
            log.error(e)
            log.error("no such document")


    def update_role(self, name: str, new_permissions: List[str], description: str):
        try:
            doc = ProviderFirebase.db.collection('ZK_roles_test').document(name)
            if doc.get()._exists:
                doc.update({'role_name': name, 'permissions': new_permissions, 'description': description})
            else:
                raise HTTPException(status_code=404, detail=f"there is no role named '{name}'")
        except Exception as e:
            log.error(e)


    def delete_role(self, name: str):
        try:
            doc = ProviderFirebase.db.collection('ZK_roles_test').document(name)
            if doc.get()._exists:
                doc.delete()
                return name
            else:
                raise HTTPException(status_code=404, detail=f"there is no role named '{name}'")
        except Exception as e:
            log.error(e)
