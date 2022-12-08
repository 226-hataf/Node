import ast
import os
from typing import List
import firebase_admin
from firebase_admin import auth, firestore
import requests
import json
from business.models.users import *
from .base import *
from core import log

from business.models.users import *


class ProviderFirebase(Provider):
    db = None

    def __init__(self) -> None:
        if ProviderFirebase.db is None:
            firebase_admin.initialize_app()
            ProviderFirebase.db = firestore.client()

            super().__init__()

    def zeauth_bootstrap(self):
        # if there is no default admin user, create one, create roles and assign the roles to the admin user
        user_info = {
            'default_admin_email': os.environ.get('DEFAULT_ADMIN_EMAIL', 'tuncelezgisu111@gmail.com'),
            'default_admin_password': os.environ.get('DEFAULT_ADMIN_PASSWORD', '12345ezgi123')
        }
        try:
            user_model = User(email=user_info['default_admin_email'], password=user_info['default_admin_password'])

            user = self.signup(user=user_model)
            permissions = os.environ.get('DEFAULT_ADMIN_PERMISSIONS').split(',')
            self.create_role(name=os.environ.get('DEFAULT_ADMIN_ROLES'), permissions=permissions,
                             description="default admin role")
            self.update_user_roles(user_id=user.id, new_role=[os.environ.get('DEFAULT_ADMIN_ROLES')])
        except DuplicateEmailError as e:
            log.debug('email used for bootstraping already exists')
        except Exception as e:
            log.error(e)
            raise ("ZeAuth bootstraping failed cannot start properly, unexpected behavior may occur")

    def _cast_login_model(self, response: dict):
        return LoginResponseModel(
            user=User(email=response['email'], id=response['localId'], full_name=response['displayName']),
            uid=response['localId'],
            accessToken=response['idToken'],
            refreshToken=response['refreshToken'],
            expirationTime=response['expiresIn'],
        )

    def login(self, user_info, db):
        try:
            headers = {
                'Content-Type': 'application/json'
            }
            json_data = {
                'email': user_info.email,
                'password': user_info.password,
                'returnSecureToken': 'true',
            }
            response = requests.post(
                f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={os.environ.get('API_KEY')}",
                headers=headers, json=json_data)
            if response.status_code == 200:
                return self._cast_login_model(json.loads(response.content.decode()))
            else:
                log.debug(response.json()['error']['message'])
                raise InvalidCredentialsError('failed login')
        except Exception as e:
            log.error(e)
            raise e

    def signup(self, user: User, db):
        try:
            user = Provider._enrich_user(user)
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
                return Provider._enrich_user(user)
        except auth.EmailAlreadyExistsError:
            raise DuplicateEmailError('duplicate email registration attempt')
        except Exception as e:
            raise e

    def verify(self, token: str):
        try:
            decoded_token = auth.verify_id_token(token)
            return decoded_token
        except Exception as e:
            log.debug(e)
            raise InvalidTokenError('failed token verification')

    def delete_user(self, user_id: str):
        try:
            deleted_user = auth.get_user(user_id)  # find the user to delete by its id
            if deleted_user:
                auth.delete_user(deleted_user.uid)  # delete the user by its unique id
                log.debug(f'successfully deleted user {deleted_user.uid}')
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
                log.debug(f'sucessfully updated user {user.uid}')
                return user
            else:
                raise NotExistingResourceError('attempt to update not existing user')
        except Exception as e:
            log.error(e)
            raise e

    def _cast_user(self, data: dict):
        return User(
            id=data['localId'],
            email=data['email'],
            verified=data['emailVerified'],
            created_at=data['createdAt'],
            permissions=ast.literal_eval(data["customAttributes"])[
                'zk-zeauth-permissions'] if "customAttributes" in data else [],
            roles=ast.literal_eval(data["customAttributes"])["zk-zeauth-roles"] if "customAttributes" in data else [],
            full_name=data['displayName'] if "displayName" in data else None
        )

    def list_users(self, page: str, page_size: int, search: str):
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
            else:
                raise NotExistingResourceError()

        except Exception as e:
            raise e

    def update_user_roles(self, new_role: List[str], user_id: str):
        try:
            uid = user_id
            update_user_role = auth.get_user(uid)
            if update_user_role:
                new_permissions = []
                for role in new_role:
                    role_ref = ProviderFirebase.db.collection("zk-zauth-roles").document(role).get()
                    for pre in role_ref._data["permissions"]:
                        new_permissions.append(pre)
                auth.set_custom_user_claims(uid,
                                            {"zk-zeauth-permissions": new_permissions, "zk-zeauth-roles": new_role})
                user = auth.get_user(user_id)
                return self._cast_user(user._data)
        except Exception as e:
            raise e

    def user_active_on(self, user_id: str):
        try:
            updated_user = auth.get_user(user_id)
            if updated_user:
                user = auth.update_user(
                    uid=user_id,
                    disabled=False
                )
                log.info(f'sucessfully updated user {user.uid}')
                return user
            else:
                raise NotExistingResourceError('attempt to activate not existing user')
        except Exception as e:
            raise e

    def user_active_off(self, user_id: str):
        try:
            updated_user = auth.get_user(user_id)
            if updated_user:
                user = auth.update_user(
                    uid=user_id,
                    disabled=True
                )
                log.debug(f'sucessfully updated user {user.uid}')
                return user
            else:
                raise NotExistingResourceError('attempt to deactivate not existing user')
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

    def get_role(self, name: str):
        try:

            doc = ProviderFirebase.db.collection('zk-zauth-roles').document(name).get()
            if doc:
                return doc.to_dict()
            else:
                raise NotExistingResourceError(f"'{name}' role not found")
        except Exception as e:
            log.error(e)
            log.error("no such document")

    def list_roles(self, page: str, page_size: int):
        try:
            offset = page_size * (int(page) - 1)
            docs = ProviderFirebase.db.collection('zk-zauth-roles').limit(page_size).offset(offset).get()
            roles_list = [doc.to_dict() for doc in docs]
            return roles_list, int(page) + 1, page_size
        except Exception as e:
            raise e

    def update_role(self, name: str, new_permissions: List[str], description: str):
        try:
            doc = ProviderFirebase.db.collection("zk-zauth-roles").document(name)
            if doc.get()._exists:
                doc.update({'role_name': name, 'permissions': new_permissions, 'description': description})
            else:
                raise NotExistingResourceError('attemtp to update not exisitng role')
        except Exception as e:
            raise e

    def delete_role(self, name: str):
        try:
            doc = ProviderFirebase.db.collection("zk-zauth-roles").document(name)
            if doc.get()._exists:
                doc.delete()
                return name
            else:
                raise NotExistingResourceError('attempt to delete not existing role')
        except Exception as e:
            raise e

    def resend_confirmation_email(self):
        raise NotExistingResourceError('Not implemented yet.')

    def reset_password(self, user_info):
        raise NotExistingResourceError('Not implemented yet.')

    def reset_password_verify(self, reset_password):
        raise NotExistingResourceError('Not implemented yet.')
