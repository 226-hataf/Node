import pytest
from httpx import AsyncClient
from api import app
from starlette.status import HTTP_200_OK, HTTP_422_UNPROCESSABLE_ENTITY, \
    HTTP_404_NOT_FOUND, HTTP_201_CREATED, HTTP_403_FORBIDDEN, HTTP_202_ACCEPTED, HTTP_405_METHOD_NOT_ALLOWED
from config.db import get_db
from core.crud import get_user_by_email, get_multi_users_by_emails
from business.models.dependencies import get_current_user


async def mock_user_roles():
    return None

app.dependency_overrides[get_current_user] = mock_user_roles


class TestUsers:
    group_name = "user"
    not_exists_group_id = "8077c4ab-5fe7-4e14-b85d-e0f49b41cf5d"
    not_exists_user_id = "8077c4ab-5fe7-4e14-b85d-e0f49b41cf5d"
    invalid_user_id = "12345"

    @pytest.mark.asyncio
    async def test_user_list_users_sort_users(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:

            params = {
                "date_of_creation": "2023-01-01",
                "sort_by": "desc",
                "user_status": "true",
                "sort_column": "user_name",
                "date_of_last_login": "2023-02-21",
                "page": 1,
                "size": 20
            }
            response = await ac.get("/users/", params=params)
            assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_user_list_users_sort_created_at(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            params = {
                "date_of_creation": "2023-01-01",
                "sort_by": "desc",
                "user_status": "true",
                "sort_column": "created_at",
                "date_of_last_login": "2023-02-21",
                "page": 1,
                "size": 20
            }
            response = await ac.get("/users/", params=params)
            assert response.status_code == HTTP_200_OK


    @pytest.mark.asyncio
    async def test_user_to_group_success(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            email = "user@test.com"

            group_name = TestUsers.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            user_id = get_user_by_email(db, email)

            response = await ac.patch(f'/users/{str(user_id.id)}/group/{group_id}')
            json_response = response.json()
            assert response.status_code == HTTP_200_OK
            assert ''.join([x["users"] for x in json_response]) == f"{str(user_id.id)}"
            assert ''.join([x["groups"] for x in json_response]) == f"{group_id}"

    @pytest.mark.asyncio
    async def test_user_to_group_users_exist_in_the_group(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            email = "user@test.com"

            group_name = TestUsers.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            user_id = get_user_by_email(db, email)

            response = await ac.patch(f'/users/{str(user_id.id)}/group/{group_id}')
            json_response = response.json()
            assert response.status_code == HTTP_403_FORBIDDEN
            assert json_response == {"detail": "Available users are already in the group"}

    @pytest.mark.asyncio
    async def test_user_to_group_group_not_found(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            email = "user@test.com"

            group_id = TestUsers.not_exists_group_id
            user_id = get_user_by_email(db, email)
            response = await ac.patch(f'/users/{str(user_id.id)}/group/{group_id}')
            json_response = response.json()
            assert response.status_code == HTTP_404_NOT_FOUND
            assert json_response == {"detail": "Group not found"}

    @pytest.mark.asyncio
    async def test_user_to_group_with_invalid_uuid_format(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestUsers.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            user_id = TestUsers.invalid_user_id

            response = await ac.patch(f'/users/{user_id}/group/{group_id}')
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']

    @pytest.mark.asyncio
    async def test_user_deassign_exist_user_from_a_group(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            email = "user@test.com"

            group_name = TestUsers.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            user_id = get_user_by_email(db, email)

            response = await ac.patch(f'/users/{str(user_id.id)}/group/{group_id}/remove')
            assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_user_deassign_not_exist_user_from_a_group(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestUsers.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            user_id = TestUsers.not_exists_user_id

            response = await ac.patch(f'/users/{user_id}/group/{group_id}/remove')
            json_response = response.json()
            assert response.status_code == HTTP_404_NOT_FOUND
            assert json_response == {"detail": "User not exist"}

    @pytest.mark.asyncio
    async def test_user_deassign_not_exist_group_id(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            email = "user@test.com"

            group_id = TestUsers.not_exists_group_id
            user_id = get_user_by_email(db, email)

            response = await ac.patch(f'/users/{str(user_id.id)}/group/{group_id}/remove')
            json_response = response.json()
            assert response.status_code == HTTP_404_NOT_FOUND
            assert json_response == {"detail": "Group not found"}

    @pytest.mark.asyncio
    async def test_user_to_group_with_empty_user_request(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            user_id = ""
            group_name = TestUsers.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            response = await ac.patch(f'/users/{user_id}/group/{group_id}')
            json_response = response.json()
            assert response.status_code == HTTP_404_NOT_FOUND
            assert json_response == {"detail": "Not Found"}

    @pytest.mark.asyncio
    async def test_user_to_group_with_empty_group_request(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            email = "user@test.com"

            group_id = ""
            user_id = get_user_by_email(db, email)

            response = await ac.patch(f'/users/{str(user_id.id)}/group/{group_id}')
            json_response = response.json()
            assert response.status_code == HTTP_404_NOT_FOUND
            assert json_response == {"detail": "Not Found"}

    @pytest.mark.asyncio
    async def test_user_to_group_with_not_exist_user(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestUsers.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            user_id = TestUsers.not_exists_user_id

            response = await ac.patch(f'/users/{user_id}/group/{group_id}')
            json_response = response.json()
            assert response.status_code == HTTP_404_NOT_FOUND
            assert json_response == {"detail": "User not exist"}

    @pytest.mark.asyncio
    async def test_user_exist_user_activate_off(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            email = "user@test.com"

            q = 'OFF'
            user_id = get_user_by_email(db, email)

            response = await ac.put(f"/users/{str(user_id.id)}/off")
            json_response = response.json()
            assert response.status_code == HTTP_201_CREATED
            assert json_response == {"user_id": f"{str(user_id.id)}", "user_activation": f"{q}"}

    @pytest.mark.asyncio
    async def test_user_non_exist_user_activate_off(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            user_id = TestUsers.not_exists_user_id

            response = await ac.put(f"/users/{user_id}/off")
            json_response = response.json()
            assert response.status_code == HTTP_404_NOT_FOUND
            assert json_response == {"detail": "User not found"}

    @pytest.mark.asyncio
    async def test_user_activate_off_invalid_user_id(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            user_id = TestUsers.invalid_user_id

            response = await ac.put(f"/users/{user_id}/off")
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']

    @pytest.mark.asyncio
    async def test_user_exist_user_activate_on(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            email = "user@test.com"

            q = 'ON'
            user_id = get_user_by_email(db, email)

            response = await ac.put(f"/users/{str(user_id.id)}/on")
            json_response = response.json()
            assert response.status_code == HTTP_201_CREATED
            assert json_response == {"user_id": f"{str(user_id.id)}", "user_activation": f"{q}"}

    @pytest.mark.asyncio
    async def test_user_non_exist_user_activate_on(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            user_id = TestUsers.not_exists_user_id

            response = await ac.put(f"/users/{user_id}/on")
            json_response = response.json()
            assert response.status_code == HTTP_404_NOT_FOUND
            assert json_response == {"detail": "User not found"}

    @pytest.mark.asyncio
    async def test_user_activate_on_invalid_user_id(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            user_id = TestUsers.invalid_user_id

            response = await ac.put(f"/users/{user_id}/on")
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']
    
    @pytest.mark.asyncio
    async def test_user_get_exist_users_with_ids(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            emails = ["user@test.com", "admin@test.com"]

            user1, user2 = get_multi_users_by_emails(db, emails)

            json_data = {
                'users_ids': [
                    f"{user1}", f"{user2}"
                ]
            }
            response = await ac.post('/users/with_ids', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_200_OK
            assert [x["user"][0]['id'] for x in json_response] == [f"{user1}", f"{user2}"]

    @pytest.mark.asyncio
    async def test_user_get_non_exist_users_with_ids(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            user1 = TestUsers.not_exists_user_id
            user2 = TestUsers.not_exists_user_id

            json_data = {
                'users_ids': [
                    f"{user1}", f"{user2}"
                ]
            }
            response = await ac.post('/users/with_ids', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_200_OK
            assert json_response == []

    @pytest.mark.asyncio
    async def test_user_empty_list_errors(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:

            json_data = {
                'users_ids': [ ]
            }
            response = await ac.post('/users/with_ids', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['Empty list not excepted ! ']

    @pytest.mark.asyncio
    async def test_user_get_users_with_invalid_user_id_format(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            user1 = TestUsers.invalid_user_id

            json_data = {
                'users_ids': [
                    f"{user1}"
                ]
            }
            response = await ac.post('/users/with_ids', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']

    @pytest.mark.asyncio
    async def test_user_update_current_user_success(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            email = "user@test.com"

            user_id = get_user_by_email(db, email)

            json_data = {
                "phone": "555-55-66"
            }
            response = await ac.put(f'/users/{str(user_id.id)}', json=json_data)
            assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_user_update_non_exist_user(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            user_id = TestUsers.not_exists_user_id

            json_data = {
                "phone": "555-55-77"
            }
            response = await ac.put(f'/users/{user_id}', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_404_NOT_FOUND
            assert json_response == {"detail": "User not found"}

    @pytest.mark.asyncio
    async def test_user_delete_non_exist_user(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            user_id = TestUsers.not_exists_user_id

            response = await ac.delete(f'/users/{user_id}')
            json_response = response.json()
            assert response.status_code == HTTP_404_NOT_FOUND
            assert json_response == {"detail": "User not found"}

    @pytest.mark.asyncio
    async def test_user_delete_invalid_user_id(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            user_id = TestUsers.invalid_user_id

            response = await ac.delete(f'/users/{user_id}')
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']

    @pytest.mark.asyncio
    async def test_user_delete_empty_request(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            user_id = ""

            response = await ac.delete(f'/users/{user_id}')
            json_response = response.json()
            assert response.status_code == HTTP_405_METHOD_NOT_ALLOWED
            assert json_response == {'detail': 'Method Not Allowed'}

    @pytest.mark.asyncio
    async def test_user_create_new_user_success(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            json_data = {
                "email": "test1@test.com",
                "username": "test1@test.com",
                "password": "Te@Test&34",
                "first_name": "test",
                "last_name": "user",
                "verified": "true",
                "user_status": "true",
                "phone": "555"
            }

            response = await ac.post('/users/', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_201_CREATED
            assert json_response["email"] == 'test1@test.com'

    @pytest.mark.asyncio
    async def test_user_create_new_user_with_exist_email(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            json_data = {
                "email": "test1@test.com",
                "username": "test1@test.com",
                "password": "Te@Test&34",
                "first_name": "test",
                "last_name": "user",
                "verified": "true",
                "user_status": "true",
                "phone": "555"
            }

            response = await ac.post('/users/', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_403_FORBIDDEN
            assert json_response == {"detail": "Email already in use !"}

    @pytest.mark.asyncio
    async def test_user_create_new_user_with_empty_request(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            json_data = {

            }

            response = await ac.post('/users/', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['field required']

    @pytest.mark.asyncio
    async def test_user_create_with_invalid_email_format(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            json_data = {
                "email": "abc",
                "username": "",
                "password": "Te@Test&34",
                "first_name": "",
                "last_name": "",
                "verified": "true",
                "user_status": "true",
                "phone": ""
            }

            response = await ac.post('/users/', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['invalid email format']

    @pytest.mark.asyncio
    async def test_user_create_with_invalid_password_format(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            json_data = {
                "email": "test2@test.com",
                "username": "",
                "password": "invalid",
                "first_name": "",
                "last_name": "",
                "verified": "true",
                "user_status": "true",
                "phone": ""
            }

            response = await ac.post('/users/', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['invalid password format']

    @pytest.mark.asyncio
    async def test_user_delete_success(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            email = "test1@test.com"

            user_id = get_user_by_email(db, email)

            response = await ac.delete(f'/users/{user_id.id}')
            json_response = response.json()
            assert response.status_code == HTTP_202_ACCEPTED
            assert json_response == {'detail': f"User <{user_id.id}> deleted successfully !"}

