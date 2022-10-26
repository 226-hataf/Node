import ast
import datetime
import keycloak
import requests
from core import log
import os
import json
from business.models.users import User
from business.providers.base import DuplicateEmailError, Provider
from keycloak import KeycloakAdmin, KeycloakOpenID, KeycloakPostError, KeycloakConnectionError, \
    KeycloakAuthenticationError, KeycloakPutError, KeycloakGetError
from business.models.users import *
from .base import *
from business.providers.base import *
import uuid
from redis_service.redis_service import set_redis, get_redis
from ..models.users import ResetPasswordVerifySchema, ConfirmationEmailVerifySchema
from email_service.mail_service import send_email


def cast_login_model(response: dict, user_info):
    full_name = user_info['firstName']
    if user_info['lastName']:
        full_name = f"{full_name} {user_info['lastName']}"
    created_at = datetime.datetime.fromtimestamp(user_info['createdTimestamp'] / 1000)

    return LoginResponseModel(
        user=User(
            id=user_info['id'],
            email=user_info['email'],
            username=user_info['username'],
            verified=user_info['emailVerified'],
            user_status=user_info['enabled'],
            created_at=str(created_at).split(".")[0],
            first_name=user_info['firstName'],
            last_name=user_info['lastName'],
            full_name=full_name
        ),
        uid=user_info['id'],
        accessToken=response['access_token'],
        refreshToken=response['refresh_token'],
        expirationTime=response['expires_in'],
    )


ROLES = 'zk-zeauth-create,zk-zeauth-read,zk-zeauth-delete,zk-zeauth-update,zk-zeauth-list'
DEFAULT_ADMIN_EMAIL = os.environ.get('DEFAULT_ADMIN_EMAIL', 'tuncelezgisu111@gmail.com')
DEFAULT_ADMIN_PASSWORD = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'Webdir243R!@')
DEFAULT_ADMIN_ROLES = os.environ.get('DEFAULT_ADMIN_ROLES', ROLES).split(',')
DEFAULT_ADMIN_PERMISSIONS = os.environ.get('DEFAULT_ADMIN_PERMISSIONS', ROLES).split(',')
MAX_LIST_USERS = os.environ.get('MAX_LIST_USERS', 500)
DEFAULT_ROLES = [{"name": "admin", "description": "admin role for users"},
                 {"name": "user", "description": "user role for users"}]
USERS_TABLE_ROLE_POLICIES = ['zekoder-zeauth-users-user-policy', 'zekoder-zeauth-users-admin-policy']
DEFAULT_SCOPE = ["list", "get", "update", "del"]
USER_PERMISSIONS = ["zekoder-zeauth-user-list", "zekoder-zeauth-user-get", "zekoder-zeauth-user-del",
                    "zekoder-zeauth-user-update"]


class ProviderKeycloak(Provider):
    admin_user_created = None

    def __init__(self) -> None:
        self.setup_keycloak()
        super().__init__()

    def setup_keycloak(self):
        self.keycloak_admin = KeycloakAdmin(
            server_url=os.environ.get('KEYCLOAK_URL'),
            client_id=os.environ.get('CLIENT_ID'),
            realm_name=os.environ.get('REALM_NAME'),
            client_secret_key=os.environ.get('SECRET')
        )
        self.token = self.keycloak_admin.token
        self.keycloak_openid = KeycloakOpenID(
            server_url=os.environ.get('KEYCLOAK_URL'),
            client_id=os.environ.get('CLIENT_ID'),
            realm_name=os.environ.get('REALM_NAME'),
            client_secret_key=os.environ.get('SECRET')
        )

    def _get_server_url(self):
        return f"{self.keycloak_admin.server_url}/admin/realms/{os.environ.get('REALM_NAME')}/clients/{self._get_client_id()}"

    def create_scope_user(self, payload, token):
        if scope_exist := self.keycloak_admin.get_client_scope_by_name(client_scope_name=payload["name"]):
            return None
        data = json.dumps(payload)
        url = f"{self._get_server_url()}/authz/resource-server/scope"
        resp = requests.post(url, data=data, headers={"authorization": f"Bearer {token['access_token']}",
                                                      "content-type": "application/json"})

        return resp.json()

    def permission_user(self, payload, token):
        if permissions := self.keycloak_admin.get_client_authz_permissions(client_id=self._get_client_id()):
            for permission in permissions:
                if permission["name"] == payload["name"]:
                    return permission
        data = json.dumps(payload)
        url = f"{self._get_server_url()}/authz/resource-server/permission/scope"
        resp = requests.post(url, data=data, headers={"authorization": f"Bearer {token['access_token']}",
                                                      "content-type": "application/json"})

        return resp.json()

    def get_and_create_client_authz_resource(self, payload):
        if resources := self.keycloak_admin.get_client_authz_resources(client_id=self._get_client_id()):
            for resource in resources:
                if resource["name"] == payload["name"]:
                    return resource
        return self.keycloak_admin.create_client_authz_resource(client_id=self._get_client_id(), payload=payload,
                                                                skip_exists=True)

    def get_and_create_client_authz_role_based_policy(self, payload):
        if policies := self.keycloak_admin.get_client_authz_policies(client_id=self._get_client_id()):
            for policy in policies:
                if policy["name"] == payload["name"]:
                    return policy
        if payload["name"] == USERS_TABLE_ROLE_POLICIES[0]:
            if user_policy := self.keycloak_admin.create_client_authz_role_based_policy(client_id=self._get_client_id(),
                                                                                        payload=payload):
                return user_policy
        if payload["name"] == USERS_TABLE_ROLE_POLICIES[1]:
            if admin_policy := self.keycloak_admin.create_client_authz_role_based_policy(
                    client_id=self._get_client_id(), payload=payload):
                return admin_policy

    def zeauth_bootstrap(self):
        if ProviderKeycloak.admin_user_created:
            return
        default_admin = {
            "email": DEFAULT_ADMIN_EMAIL,
            "username": DEFAULT_ADMIN_EMAIL,
            "secret": DEFAULT_ADMIN_PASSWORD,
            "firstname": "Master",
            "lastname": "Account"
        }
        try:
            self.update_password_policy()
        except Exception as err:
            error_template = "update_password_policy: An exception of type {0} occurred. error: {1}"
            log.error(error_template.format(type(err).__name__, str(err)))

        try:
            user = self._create_user_signup(**default_admin)

        except Exception as ex:
            log.info("user already created")
            log.error(ex)
        try:

            # creating default roles
            roles = {}
            for role in DEFAULT_ROLES:
                role = self.keycloak_admin.create_realm_role(payload=role, skip_exists=True)
                roles[role] = self.keycloak_admin.get_realm_role(role)

            token = self.keycloak_openid.token(DEFAULT_ADMIN_EMAIL, DEFAULT_ADMIN_PASSWORD, grant_type="password")

            # Creating Scope

            scope_list = []
            scope_id = []
            for scope in DEFAULT_SCOPE:
                try:
                    payload = {
                        "name": scope,
                        "displayName": scope
                    }
                    scope_data = self.create_scope_user(payload=payload, token=token)
                    if scope_data:
                        scope_list.append(scope_data)
                        scope_id.append(scope_data["id"])

                    else:
                        pass
                except Exception as ex:
                    log.error(f"Boot strap fail due to :{ex}")

            # Creating Resource
            try:
                payload = {"scopes": scope_list, "attributes": {}, "uris": ["email"], "name": "users",
                           "ownerManagedAccess": "", "displayName": "email", "type": "table"}

                users_resource = self.get_and_create_client_authz_resource(payload=payload)
                if users_resource:
                    log.info("resource created")

            except Exception as ex:
                log.error(ex)
                log.info("this resourse already created")

            # Creating Role Policy
            payload = {
                "name": USERS_TABLE_ROLE_POLICIES[0],
                "type": "role",
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
                "roles": [{
                    "id": roles['user']['id'],
                    "required": True
                }]
            }
            user_policy = self.get_and_create_client_authz_role_based_policy(payload=payload)

            payload = {
                "name": USERS_TABLE_ROLE_POLICIES[1],
                "type": "role",
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
                "roles": [{
                    "id": roles['admin']['id'],
                    "required": True
                }]
            }
            admin_policy = self.get_and_create_client_authz_role_based_policy(payload=payload)

            # Creating Permissions

            user_policy_data = []

            for user_permission in USER_PERMISSIONS:
                if (user_permission == "zekoder-zeauth-user-list") or (
                        user_permission == "zekoder-zeauth-user-del") or (
                        user_permission == "zekoder-zeauth-user-update"):
                    user_policy_data.append(admin_policy["id"])

                elif (user_permission == "zekoder-zeauth-user-get"):
                    user_policy_data.append(user_policy["id"])
                    user_policy_data.append(admin_policy["id"])

                payload = {
                    "type": "scope",
                    "logic": "POSITIVE",
                    "decisionStrategy": "UNANIMOUS",
                    "name": user_permission,
                    "description": "permission",
                    "resources": [users_resource["_id"]],
                    "policies": user_policy_data,
                    "scopes": scope_id
                }
                try:
                    permission_obj = self.permission_user(payload=payload, token=token)
                    if permission_obj:
                        log.info("object create")
                    else:
                        pass
                except Exception as ex:
                    log.error(ex)

            client_roles = self.keycloak_admin.get_client_roles(client_id=self._get_client_id())
            user_roles = [rol for rol in client_roles if rol["name"] in DEFAULT_ADMIN_PERMISSIONS]
            # self.keycloak_admin.assign_client_role(client_id=self._get_client_id(), user_id=user, roles=user_roles)
        except Exception as err:
            error_template = "zeauth_bootstrap: An exception of type {0} occurred. error: {1}"
            log.error(error_template.format(type(err).__name__, str(err)))
            # log.error(f"user <{DEFAULT_ADMIN_EMAIL}> already exists")

        ProviderKeycloak.admin_user_created = True

    def update_password_policy(self) -> str:
        try:
            # password policies
            length = f"length({int(os.environ.get('LENGTH'))})"
            specialChars = f"specialChars({int(os.environ.get('SPECIAL_CHARACTERS'))})"
            upperCase = f"upperCase({int(os.environ.get('UPPERCASE'))})"
            digits = f"digits({int(os.environ.get('DIGITS'))})"

            # definiton of password policy
            password_policy = {"passwordPolicy": f"{length} and {specialChars} and {upperCase} and {digits}"}
            self.keycloak_admin.update_realm(realm_name=os.getenv('REALM_NAME'), payload=password_policy)
        except Exception as e:
            log.error(e)
            raise e

    def _create_user_signup(self, email: str, username: str, secret, firstname: str, lastname: str,
                            enabled: bool = True) -> str:
        user = {"email": email,
                "username": username,
                "enabled": enabled,
                "firstName": firstname,
                "lastName": lastname,
                "credentials": [{"value": secret, "type": "password", }]
                }
        try:
            return self.keycloak_admin.create_user(user, exist_ok=False)
        except keycloak.exceptions.KeycloakAuthenticationError as ex:
            self.setup_keycloak()
            return self.keycloak_admin.create_user(user, exist_ok=False)
        except keycloak.exceptions.KeycloakPostError as e:
            log.error(f'Error create user signup: {type(e)} - {str(e)}')
            err_json = json.loads(e.error_message)
            if err_json["errorMessage"] == "User exists with same username":
                raise DuplicateEmailError('The user is already exists.') from e
            if err_json["errorMessage"] == "Password policy not met":
                raise PasswordPolicyError('Password policy not met.') from e

        except Exception as e:
            log.error(f'Error create user signup: {type(e)} - {str(e)}')
            raise DuplicateEmailError('the user is already exists') from e

    def _get_client_id(self):
        clients = self.keycloak_admin.get_clients()
        return next((client["id"] for client in clients if client["clientId"] == os.environ.get('CLIENT_ID')), None)

    async def signup(self, user: User) -> User:
        self.setup_keycloak()
        try:
            created_user = self._create_user_signup(email=user.email, username=user.email, firstname=user.first_name,
                                                    lastname=user.last_name, secret=user.password)

            client_roles = self.keycloak_admin.get_client_roles(client_id=self._get_client_id())
            if user.roles:
                user_roles = [rol for rol in client_roles if rol["name"] in user.roles]
                self.keycloak_admin.assign_client_role(client_id=self._get_client_id(), user_id=created_user,
                                                       roles=user_roles)

            self.keycloak_admin.update_user(user_id=created_user,
                                            payload={
                                                "requiredActions": ["VERIFY_EMAIL"],
                                                "emailVerified": False
                                            })

            confirm_email_key = hash(uuid.uuid4().hex)
            if not user.username:
                user.username = user.email
            set_redis(confirm_email_key, user.username)

            confirm_email_url = f"https://zekoder.netlify.app/auth/confirm-email?token={confirm_email_key}"

            directory = os.path.dirname(__file__)
            with open(os.path.join(directory, "../../index.html"), "r", encoding="utf-8") as index_file:
                email_template = index_file.read() \
                    .replace("{{first_name}}", user.first_name) \
                    .replace("{{verification_link}}", confirm_email_url)

                await send_email(
                    recipients=[user.username],
                    subject="Confirm email",
                    body=email_template
                )

            log.info(f'sucessfully created new user: {created_user}')
            return Provider._enrich_user(user)

        except DuplicateEmailError as err:
            log.error(err)
            raise DuplicateEmailError(f"<{user.email}> already exists")
        except Exception as err:
            error_template = "signup Exception: An exception of type {0} occurred. error: {1}"
            log.error(error_template.format(type(err).__name__, str(err)))
            raise err

    def login(self, user_info):
        self.setup_keycloak()
        try:
            response = self.keycloak_openid.token(user_info.email, user_info.password, grant_type='password')
            user_info_resp = self.keycloak_openid.userinfo(response['access_token'])
            user = self.keycloak_admin.get_user(user_info_resp['sub'])
            log.info(response)
            if response:
                return cast_login_model(response, user)
        except KeycloakAuthenticationError as err:
            log.debug(f"Keycloak Authentication Error: {err}")
            raise InvalidCredentialsError('failed login') from err
        except KeycloakConnectionError as err:
            log.error(f"Un-able to connect with Keycloak. Error: {err}")
            raise CustomKeycloakConnectionError(err) from err
        except KeycloakPostError as err:
            log.error(err)
            raise CustomKeycloakPostError(err.error_message) from err
        except Exception as e:
            log.error(e)
            raise e

    async def resend_confirmation_email(self, user_info):
        self.setup_keycloak()
        try:
            users = self.keycloak_admin.get_users(query={
                "email": user_info.username
            })
            if len(users) == 0:
                raise UserNotFoundError(f"User '{user_info.username}' not in system")

            self.keycloak_admin.update_user(user_id=users[0]["id"],
                                            payload={
                                                "requiredActions": ["VERIFY_EMAIL"],
                                                "emailVerified": False
                                            })

            confirm_email_key = hash(uuid.uuid4().hex)
            set_redis(confirm_email_key, user_info.username)
            confirm_email_url = f"https://zekoder.netlify.app/auth/confirm-email?token={confirm_email_key}"
            directory = os.path.dirname(__file__)
            with open(os.path.join(directory, "../../index.html"), "r", encoding="utf-8") as index_file:
                email_template = index_file.read() \
                    .replace("{{first_name}}", users[0]["firstName"]) \
                    .replace("{{verification_link}}", confirm_email_url)

                await send_email(
                    recipients=[user_info.username],
                    subject="Confirm email",
                    body=email_template
                )

            return "Confirmation email sent!"
        except KeycloakAuthenticationError as err:
            log.debug(f"Keycloak Authentication Error: {err}")
            raise InvalidCredentialsError('failed login') from err
        except KeycloakConnectionError as err:
            log.error(f"Un-able to connect with Keycloak. Error: {err}")
            raise CustomKeycloakConnectionError(err) from err
        except KeycloakPostError as err:
            log.error(err)
            raise CustomKeycloakPostError(err.error_message) from err
        except Exception as err:
            log.error(err)
            raise err

    def verify_email(self, email_verify: ConfirmationEmailVerifySchema):
        self.setup_keycloak()
        try:
            try:
                email = get_redis(email_verify.token)
            except Exception as err:
                log.error(f"redis err: {err}")
                raise IncorrectResetKeyError(f"Token {email_verify.token} is incorrect!") from err

            users = self.keycloak_admin.get_users(query={"email": email})
            if users and len(users) == 1:
                self.keycloak_admin.update_user(user_id=users[0]["id"],
                                                payload={
                                                    "requiredActions": [],
                                                    "emailVerified": True
                                                })

            return "Email Verified!"
        except KeycloakConnectionError as err:
            log.error(f"Un-able to connect with Keycloak. Error: {err}")
            raise CustomKeycloakConnectionError(err) from err
        except KeycloakPutError as err:
            log.error(f"KeycloakPutError: {err}")
            message = json.loads(err.error_message)
            raise CustomKeycloakPutError(message["error_description"]) from err
        except Exception as err:
            log.error(f"Exception: {err}")
            raise err

    async def reset_password(self, user_info):
        self.setup_keycloak()
        try:
            users = self.keycloak_admin.get_users(query={
                "email": user_info.username
            })
            if len(users) == 0:
                raise UserNotFoundError(f"User '{user_info.username}' not in system")

            reset_key = hash(uuid.uuid4().hex)
            set_redis(reset_key, user_info.username)

            reset_password_url = f"dev.zekoder.com/resetpassword?token={reset_key}"
            await send_email(
                recipients=[user_info.username],
                subject="Reset Password",
                body=reset_password_url
            )
            return True
        except KeycloakConnectionError as err:
            log.error(f"Un-able to connect with Keycloak. Error: {err}")
            raise CustomKeycloakConnectionError(err) from err
        except KeycloakPostError as err:
            log.error(err)
            raise CustomKeycloakPostError(err.error_message) from err
        except Exception as err:
            log.error(err)
            raise err

    def reset_password_verify(self, reset_password: ResetPasswordVerifySchema):
        self.setup_keycloak()
        try:
            try:
                email = get_redis(reset_password.reset_key)
            except Exception as err:
                log.error(f"redis err: {err}")
                raise IncorrectResetKeyError(f"Reset key {reset_password.reset_key} is incorrect!") from err

            users = self.keycloak_admin.get_users(query={"email": email})
            if users and len(users) == 1:
                self.keycloak_admin.set_user_password(
                    user_id=users[0]["id"],
                    password=reset_password.new_password,
                    temporary=False
                )

            response = self.keycloak_openid.token(email, reset_password.new_password)
            log.info(response)
            if response:
                return response
        except KeycloakConnectionError as err:
            log.error(f"Un-able to connect with Keycloak. Error: {err}")
            raise CustomKeycloakConnectionError(err) from err
        except KeycloakPutError as err:
            log.error(f"KeycloakPutError: {err}")
            message = json.loads(err.error_message)
            raise CustomKeycloakPutError(message["error_description"]) from err
        except Exception as err:
            log.error(f"Exception: {err}")
            raise err

    def verify(self, token: str):
        retry_count = 0
        while True:
            retry_count += 1
            try:
                self.setup_keycloak()
                userinfo = self.keycloak_openid.userinfo(token)
                available_roles = self.keycloak_admin.get_composite_client_roles_of_user(
                    client_id=self._get_client_id(),
                    user_id=userinfo["sub"]
                )
                roles_names = [role["name"] for role in available_roles]
                verify = {"zk-zeauth-permissions": roles_names, "user": userinfo}

                log.info(verify)
                return verify
            except KeycloakAuthenticationError as err:
                error_template = "KeycloakAuthenticationError: retry: {}  An exception of type {0} occurred. error: {1}"
                log.error(error_template.format(retry_count, type(err).__name__, str(err)))
                log.debug(err)
                if retry_count == 3:
                    raise InvalidTokenError('failed token verification') from err
            except Exception as err:
                error_template = "keycloak verify:  An exception of type {0} occurred. error: {1}"
                log.error(error_template.format(type(err).__name__, str(err)))
                log.debug(err)
                raise InvalidTokenError('failed token verification') from err

    def get_client_roles_of_user(self, user_id):
        clients = self.keycloak_admin.get_clients()
        client_id = next((client["id"] for client in clients if client["clientId"] == os.environ.get('CLIENT_ID')),
                         None)

        roles = self.keycloak_admin.get_client_roles_of_user(user_id=user_id, client_id=client_id)
        return [rol["name"] for rol in roles]

    def _cast_user(self, data: dict):
        full_name = data['firstName']
        if data['lastName']:
            full_name = f"{full_name} {data['lastName']}"
        created_at = datetime.datetime.fromtimestamp(data['createdTimestamp'] / 1000)

        return User(
            id=data['id'],
            email=data['username'],
            verified=data['emailVerified'],
            user_status=data['enabled'],
            created_at=str(created_at).split(".")[0],
            permissions=[],
            roles=self.get_client_roles_of_user(user_id=data['id']),
            full_name=full_name
        )

    def list_users(self, page: str, page_size: int, search: str = None):
        retry_count = 0
        while True:
            retry_count += 1
            try:
                self.setup_keycloak()

                users = self.keycloak_admin.get_users(query={"first": page, "max": MAX_LIST_USERS, "search": search})
                users_data = [self._cast_user(user) for user in users]
                return users_data, page, page_size
            except KeycloakAuthenticationError as err:
                error_template = "list_users KeycloakAuthenticationError: An exception of type {0} occurred. error: {1}"
                log.error(error_template.format(type(err).__name__, str(err)))
                if retry_count == 2:
                    raise err
            except Exception as err:
                error_template = "list_users Exception: An exception of type {0} occurred. error: {1}"
                log.error(error_template.format(type(err).__name__, str(err)))
                raise err

    def user_active_on(self, user_id: str):
        self.setup_keycloak()
        try:
            if user := self.keycloak_admin.get_user(user_id=user_id):
                self.keycloak_admin.update_user(user_id=user_id, payload={"enabled": True})

                log.info(f'sucessfully updated user {user["id"]}')
                return UserActiveOnOff(uid=user["id"])
            else:
                raise NotExisitngResourceError('attempt to activate not existing user')
        except KeycloakGetError as err:
            error_template = "KeycloakGetError Exception: An exception of type {0} occurred. error: {1}"
            log.error(error_template.format(type(err).__name__, str(err)))
            raise NotExisitngResourceError('attempt to activate not existing user') from err
        except Exception as err:
            error_template = "user_active_on Exception: An exception of type {0} occurred. error: {1}"
            log.error(error_template.format(type(err).__name__, str(err)))
            raise err

    def user_active_off(self, user_id: str):
        self.setup_keycloak()
        try:
            if user := self.keycloak_admin.get_user(user_id=user_id):
                self.keycloak_admin.update_user(user_id=user_id, payload={"enabled": False})

                log.info(f'sucessfully updated user {user["id"]}')
                return UserActiveOnOff(uid=user["id"])
            else:
                raise NotExisitngResourceError('attempt to deactivate not existing user')
        except KeycloakGetError as err:
            error_template = "KeycloakGetError Exception: An exception of type {0} occurred. error: {1}"
            log.error(error_template.format(type(err).__name__, str(err)))
            raise NotExisitngResourceError('attempt to deactivate not existing user') from err
        except Exception as err:
            error_template = "user_active_off Exception: An exception of type {0} occurred. error: {1}"
            log.error(error_template.format(type(err).__name__, str(err)))
            raise err
