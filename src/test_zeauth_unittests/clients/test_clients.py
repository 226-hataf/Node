import pytest
from httpx import AsyncClient
from api import app
from starlette.status import HTTP_422_UNPROCESSABLE_ENTITY, \
    HTTP_404_NOT_FOUND, HTTP_201_CREATED, HTTP_202_ACCEPTED
from config.db import get_db
from core.crud import check_client_exists_with_email, get_client_by_name
from test_zeauth_unittests.conftest_db import override_get_db
from business.models.dependencies import get_current_user


async def mock_user_roles():
    return None

app.dependency_overrides[get_current_user] = mock_user_roles
app.dependency_overrides[get_db] = override_get_db  # override main DB to Test DB


class TestClients:
    client_name = "test_client"
    new_client_email = "new_test_client@test.com"
    new_client_name = "new_test_client"
    not_exist_client_id = "8077c4ab-5fe7-4e14-b85d-e0f49b41cf5d"
    not_exist_client_secret = "kd08a*a/d3%6dps#*-t"
    group_name = "user"
    fake_group = "fake_group"
    
    @pytest.mark.asyncio
    async def test_clients_create_new_client_with_repeated_group_names(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestClients.group_name

            json_data = {
                "name": f"{TestClients.client_name}",
                "email": "user@test.com",
                "groups": [
                    f"{group_name}",
                    f"{group_name}"
                ]
            }
            response = await ac.post("/clients/", json=json_data)
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert response.json() == {"detail": "Check group's name, "
                                                 "only available group names are required, "
                                                 "do not repeat group names"}

    @pytest.mark.asyncio
    async def test_clients_create_new_client_with_non_exist_group_name(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestClients.fake_group

            json_data = {
                "name": f"{TestClients.client_name}",
                "email": "user@test.com",
                "groups": [
                    f"{group_name}"
                ]
            }
            response = await ac.post("/clients/", json=json_data)
            assert response.status_code == HTTP_404_NOT_FOUND
            assert response.json() == {"detail": "Group/s not found !"}

    @pytest.mark.asyncio
    async def test_clients_create_new_client_all_field_must_be_set(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:

            json_data = {
                "name": f"{TestClients.client_name}",
                "email": "user@test.com"

            }
            response = await ac.post("/clients/", json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['All fields must be set in body']

    @pytest.mark.asyncio
    async def test_clients_create_new_client_empty_list_not_excepted(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:

            json_data = {
                "name": f"{TestClients.client_name}",
                "email": "user@test.com",
                "groups": [
                    ""
                ]
            }
            response = await ac.post("/clients/", json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['Empty list not excepted ! ']

    @pytest.mark.asyncio
    async def test_clients_create_new_client_value_string_not_excepted(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:

            json_data = {
                "name": f"{TestClients.client_name}",
                "email": "user@test.com",
                "groups": [
                    "string"
                ]
            }
            response = await ac.post("/clients/", json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['Value string not excepted ! ']

    @pytest.mark.asyncio
    async def test_clients_create_new_client_empty_value_not_excepted(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestClients.group_name

            json_data = {
                "name": "",
                "email": "user@test.com",
                "groups": [
                    f"{group_name}"
                ]
            }
            response = await ac.post("/clients/", json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['Empty value not excepted ! ']

    @pytest.mark.asyncio
    async def test_clients_create_new_client_with_exist_email_in_users_table(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestClients.group_name

            json_data = {
                "name": f"{TestClients.client_name}",
                "email": "user@test.com",
                "groups": [
                    f"{group_name}"
                ]
            }
            response = await ac.post("/clients/", json=json_data)
            assert response.status_code == HTTP_201_CREATED

    @pytest.mark.asyncio
    async def test_clients_create_new_client_with_exist_client_name(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestClients.group_name

            json_data = {
                "name": f"{TestClients.client_name}",
                "email": "user@test.com",
                "groups": [
                    f"{group_name}"
                ]
            }
            response = await ac.post("/clients/", json=json_data)
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert response.json() == {"detail": "Client already exist !"}

    @pytest.mark.asyncio
    async def test_clients_create_new_client_with_new_email_that_is_not_exist_in_users_table(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestClients.group_name
            email = TestClients.new_client_email

            json_data = {
                "name": f"{TestClients.new_client_name}",
                "email": f"{email}",
                "groups": [
                    f"{group_name}"
                ]
            }
            response = await ac.post("/clients/", json=json_data)
            assert response.status_code == HTTP_201_CREATED

    @pytest.mark.asyncio
    async def test_clients_auth_success(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            email = TestClients.new_client_email
            client = check_client_exists_with_email(db, email)

            json_data = {
                "client_id": f"{client.id}",
                "client_secret": f"{client.client_secret}"
            }

            response = await ac.post("/clients/auth", json=json_data)
            assert response.status_code == HTTP_201_CREATED

    @pytest.mark.asyncio
    async def test_clients_auth_client_not_exist(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            client_id = TestClients.not_exist_client_id
            client_secret = TestClients.not_exist_client_secret

            json_data = {
                "client_id": f"{client_id}",
                "client_secret": f"{client_secret}"
            }

            response = await ac.post("/clients/auth", json=json_data)
            assert response.status_code == HTTP_404_NOT_FOUND
            assert response.json() == {"detail": "Client not exist"}

    @pytest.mark.asyncio
    async def test_clients_delete_client(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            client_name = TestClients.client_name
            client = get_client_by_name(db, name=client_name)
            client_id = client.id

            response = await ac.delete(f"/clients/{client_id}")
            assert response.status_code == HTTP_202_ACCEPTED
            assert response.json() == {"detail": f"Client: <{client_id}> deleted successfully !"}

            client_name = TestClients.new_client_name
            client = get_client_by_name(db, name=client_name)
            client_id = client.id

            response = await ac.delete(f"/clients/{client_id}")
            assert response.status_code == HTTP_202_ACCEPTED
            assert response.json() == {"detail": f"Client: <{client_id}> deleted successfully !"}

    @pytest.mark.asyncio
    async def test_clients_delete_non_exist_client(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            client_id = TestClients.not_exist_client_id

            response = await ac.delete(f"/clients/{client_id}")
            assert response.status_code == HTTP_404_NOT_FOUND
            assert response.json() == {"detail": "Client Id not found"}

    @pytest.mark.asyncio
    async def test_clients_all_fields_needed(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            json_data = {
                "client_secret": ""
            }

            response = await ac.post("/clients/auth", json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['All fields must be set in body']

    @pytest.mark.asyncio
    async def test_clients_empty_value_error(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            client_id = TestClients.not_exist_client_id

            json_data = {
                "client_id": f"{client_id}",
                "client_secret": ""
            }

            response = await ac.post("/clients/auth", json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['Empty value not excepted ! ']

    @pytest.mark.asyncio
    async def test_clients_invalid_email_format(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestClients.group_name

            json_data = {
                "name": f"{TestClients.new_client_name}",
                "email": "invalidEmailFormat",
                "groups": [
                    f"{group_name}"
                ]
            }
            response = await ac.post("/clients/", json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['invalid email format']

    @pytest.mark.asyncio
    async def test_clients_empty_list_format(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            email = TestClients.new_client_email

            json_data = {
                "name": f"{TestClients.new_client_name}",
                "email": f"{email}",
                "groups": [

                ]
            }
            response = await ac.post("/clients/", json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['Empty list not excepted ! ']

    @pytest.mark.asyncio
    async def test_clients_string_name_value_not_excepted(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            email = TestClients.new_client_email
            group_name = TestClients.group_name

            json_data = {
                "name": "string",
                "email": f"{email}",
                "groups": [
                    f"{group_name}"
                ]
            }
            response = await ac.post("/clients/", json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['Value string not excepted ! ']


