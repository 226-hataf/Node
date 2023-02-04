import uuid
import pytest
from httpx import AsyncClient
from api import app
from starlette.status import HTTP_200_OK, HTTP_401_UNAUTHORIZED, \
    HTTP_201_CREATED, HTTP_403_FORBIDDEN, HTTP_422_UNPROCESSABLE_ENTITY, \
    HTTP_202_ACCEPTED, HTTP_404_NOT_FOUND, HTTP_400_BAD_REQUEST
from config.db import get_db
from core.crud import get_user_by_email, get_client_by_name, check_client_exists_with_email
from business.models.dependencies import get_current_user
from core.db_models import models
from redis_service.redis_service import set_redis


async def mock_user_roles():
    return None

app.dependency_overrides[get_current_user] = mock_user_roles


class TestDefault:
    exist_user_email = "user@test.com"
    exist_user_pass = "Us@Test&34"
    exist_user_not_verified_email = "super-user@test.com"
    exist_user_not_verified_pass = "Sp@Test&34"
    test_email = "unit_test@test.com"
    fake_email = "no_name@test.com"
    fake_pass = "Ab@Cd&12"
    group_name = "user"
    new_client_email = "new_test_client@test.com"
    new_client_name = "new_test_client"

    @pytest.mark.asyncio
    async def test_default_login_success(self):  # user login success
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            email = TestDefault.exist_user_email
            passwrd = TestDefault.exist_user_pass

            json_data = {"email": f"{email}", "password": f"{passwrd}"}

            response = await ac.post("/login", json=json_data)
            assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_default_login_failed(self):  # user login failed
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            email = TestDefault.fake_email
            passwrd = TestDefault.fake_pass

            json_data = {"email": f"{email}", "password": f"{passwrd}"}

            response = await ac.post("/login", json=json_data)
            assert response.status_code == HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_default_login_user_not_verified(self,):  # user login not verified
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            email = TestDefault.exist_user_not_verified_email
            passwrd = TestDefault.exist_user_not_verified_pass

            json_data = {"email": f"{email}", "password": f"{passwrd}"}
            response = await ac.post("/login", json=json_data)

            assert response.status_code == HTTP_401_UNAUTHORIZED
            assert response.json() == {"detail": "user is not verified!"}

    @pytest.mark.asyncio
    async def test_default_signup_password_policy_error(self, ):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            email = TestDefault.test_email
            json_data = {
                "email": f"{email}",
                "roles": [
                    ""
                ],
                "username": "",
                "password": "Un",
                "first_name": "Unit",
                "last_name": "Test",
                "full_name": "Unit Test",
                "phone": "555",
                "permissions": [
                    ""
                ]
            }
            response = await ac.post("/signup", json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['invalid password format']

    @pytest.mark.asyncio
    async def test_default_signup_success(self, ):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            email = TestDefault.test_email
            json_data = {
                  "email": f"{email}",
                  "roles": [
                    ""
                  ],
                  "username": "",
                  "password": "Un@Test&34",
                  "first_name": "Unit",
                  "last_name": "Test",
                  "full_name": "Unit Test",
                  "phone": "555",
                  "permissions": [
                    ""
                  ]
            }
            response = await ac.post("/signup", json=json_data)
            assert response.status_code == HTTP_201_CREATED

    @pytest.mark.asyncio
    async def test_default_signup_with_exist_email_account(self, ):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            email = TestDefault.test_email
            json_data = {
                "email": f"{email}",
                "roles": [
                    ""
                ],
                "username": "",
                "password": "Un@Test&34",
                "first_name": "Unit",
                "last_name": "Test",
                "full_name": "Unit Test",
                "phone": "555",
                "permissions": [
                    ""
                ]
            }
            response = await ac.post("/signup", json=json_data)
            assert response.status_code == HTTP_403_FORBIDDEN
            assert response.json() == {"detail": f"'{email}' email is already linked to an account"}

    @pytest.mark.asyncio
    async def test_default_resend_confirmation_email_success(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            username = TestDefault.test_email

            json_data = {"username": f"{username}"}

            response = await ac.post("/resend_confirmation_email", json=json_data)
            assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_default_resend_confirmation_email_user_not_found(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            username = "non_exist@test.com"

            json_data = {"username": f"{username}"}

            response = await ac.post("/resend_confirmation_email", json=json_data)
            assert response.status_code == HTTP_404_NOT_FOUND

    @pytest.mark.asyncio
    async def test_default_delete_test_user_success(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            email = TestDefault.test_email

            user_id = get_user_by_email(db, email)

            response = await ac.delete(f'/users/{user_id.id}')
            json_response = response.json()
            assert response.status_code == HTTP_202_ACCEPTED
            assert json_response == {'detail': f"User <{user_id.id}> deleted successfully !"}

    @pytest.mark.asyncio
    async def test_default_encrypt_str(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            text = "test"
            params = {"str_for_enc": f"{text}"}

            response = await ac.post("/encrypt_str", params=params)
            assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_default_decrypt_str(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            text = "test"
            params = {"str_for_enc": f"{text}"}

            response = await ac.post("/encrypt_str", params=params)
            json_response = response.json()
            encrypt_str = json_response["encrypt_decrypt_str"]

            params = {"str_for_dec": f"{encrypt_str}"}

            response = await ac.post("/decrypt_str", params=params)
            assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_default_get_pub_key(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:

            response = await ac.get("/key")
            assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_default_encrypt_to_decrypt(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:

            json_data = {
                "encrypted": "g6kydJ5+Ls+sPaR3j9bOOXXEYzjrweLghGzTEoTKKJF/PIiafYTRdlpbXBfmsVjHxC0aUp+nSHRf2JXlkFEAYFfW1rCKnMCxivoTF0JkZIiCn65F9byjIZo2UD1y7Io6RfHOXLTCB+3k2AGiQpWH/4tLYQZpN+T7Qgy0loBFVtI="
            }

            response = await ac.post("/keys/decrypt", json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_200_OK
            assert json_response == {"decrypted": "Hello World"}

    @pytest.mark.asyncio
    async def test_default_verify_success(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            email = TestDefault.exist_user_email
            passwrd = TestDefault.exist_user_pass

            json_data = {"email": f"{email}", "password": f"{passwrd}"}

            response = await ac.post("/login", json=json_data)
            json_response = response.json()

            token = json_response["accessToken"]
            params = {"token": f"{token}"}

            response = await ac.post("/verify", params=params)
            assert response.status_code == HTTP_200_OK
    
    @pytest.mark.asyncio
    async def test_default_verify_failed(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:

            token = "faketoken"
            params = {"token": f"{token}"}

            response = await ac.post("/verify", params=params)
            assert response.status_code == HTTP_401_UNAUTHORIZED
            assert response.json() == {"detail": "failed token verification"}

    @pytest.mark.asyncio
    async def test_default_refresh_token_success(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            email = TestDefault.exist_user_email
            passwrd = TestDefault.exist_user_pass

            json_data = {"email": f"{email}", "password": f"{passwrd}"}

            response = await ac.post("/login", json=json_data)
            json_response = response.json()

            token = json_response["refreshToken"]
            params = {"token": f"{token}"}

            response = await ac.post("/refresh_token", params=params)
            assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_default_refresh_token_cannot_created(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            token = "qwe123"
            params = {"token": f"{token}"}

            response = await ac.post("/refresh_token", params=params)
            assert response.status_code == HTTP_403_FORBIDDEN
            assert response.json() == {"detail": "Your refresh_token cannot be created !"}

    @pytest.mark.asyncio
    async def test_default_refresh_token_for_client_account_success(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            # first create client
            group_name = TestDefault.group_name
            email = TestDefault.new_client_email

            json_data = {
                "name": f"{TestDefault.new_client_name}",
                "email": f"{email}",
                "groups": [
                    f"{group_name}"
                ]
            }
            await ac.post("/clients/", json=json_data)

            # login with this client
            client = check_client_exists_with_email(db, email)
            json_data = {
                "client_id": f"{client.id}",
                "client_secret": f"{client.client_secret}"
            }
            response = await ac.post("/clients/auth", json=json_data)
            json_response = response.json()
            token = json_response["refreshToken"]

            # get refreshtoken
            params = {"token": f"{token}"}
            response = await ac.post("/refresh_token", params=params)
            assert response.status_code == HTTP_200_OK

            # Delete client records
            client_name = TestDefault.new_client_name
            client = get_client_by_name(db, name=client_name)
            client_id = client.id
            await ac.delete(f"/clients/{client_id}")

    @pytest.mark.asyncio
    async def test_default_reset_password_verify_success(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            username = TestDefault.exist_user_email
            # first verified the user
            update = db.query(models.User).filter(models.User.email == username).first()
            db.execute(f"SET zekoder.id = '{update.id}'")
            if update:
                update.verified = True
                db.commit()
            db.refresh(update)

            reset_key = hash(uuid.uuid4().hex)
            set_redis(reset_key, username)

            json_data = {
                "reset_key": f"{reset_key}",
                "new_password": "Us@Test&34"
            }

            response = await ac.post("/reset-password/verify", json=json_data)
            assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_default_reset_password_verify_error(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            key = "111"
            json_data = {
                "reset_key": f"{key}",
                "new_password": ""
            }

            response = await ac.post("/reset-password/verify", json=json_data)
            assert response.status_code == HTTP_400_BAD_REQUEST
            assert response.json() == {"detail": f"Reset key {key} is incorrect!"}

    @pytest.mark.asyncio
    async def test_default_reset_password_success(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            username = TestDefault.exist_user_email

            json_data = {"username": f"{username}"}

            response = await ac.post("/reset-password", json=json_data)
            assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_default_reset_password_error(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            username = TestDefault.fake_email

            json_data = {"username": f"{username}"}

            response = await ac.post("/reset-password", json=json_data)
            assert response.status_code == HTTP_404_NOT_FOUND
            assert response.json() == {"detail": f"User '{username}' not in system"}

    @pytest.mark.asyncio
    async def test_default_verify_email_success(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            username = TestDefault.exist_user_email
            # first verified the user
            update = db.query(models.User).filter(models.User.email == username).first()
            db.execute(f"SET zekoder.id = '{update.id}'")
            if update:
                update.verified = True
                db.commit()
            db.refresh(update)

            confirm_email_key = hash(uuid.uuid4().hex)
            set_redis(confirm_email_key, username)

            json_data = {"token": f"{confirm_email_key}"}

            response = await ac.post("/verify_email", json=json_data)
            assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_default_verify_email_incorrect(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            confirm_email_key = "123"

            json_data = {"token": f"{confirm_email_key}"}

            response = await ac.post("/verify_email", json=json_data)
            assert response.status_code == HTTP_400_BAD_REQUEST
            assert response.json() == {"detail": f"Token {confirm_email_key} is incorrect!"}