import pytest
from httpx import AsyncClient
from api import app
from starlette.status import HTTP_200_OK, HTTP_422_UNPROCESSABLE_ENTITY, \
    HTTP_404_NOT_FOUND, HTTP_201_CREATED, HTTP_403_FORBIDDEN, HTTP_202_ACCEPTED, HTTP_405_METHOD_NOT_ALLOWED
from business.models.dependencies import get_current_user
from test_zeauth_unittests.conftest_db import override_get_db
from config.db import get_db


async def mock_user_roles():
    return None

app.dependency_overrides[get_current_user] = mock_user_roles
app.dependency_overrides[get_db] = override_get_db  # override main DB to Test DB


class TestRoles:
    non_exist_role_id = "a0d3aaee-77fc-457b-ba7f-321cc116388b"
    role_name = "zekoder-zeauth-users-get"
    role_name_non_exist = "test-role-non-exist"
    role_name_create = "test-role-new-success"
    role_description = "New Role Description"
    
    @pytest.mark.asyncio
    async def test_roles_list_success(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            params = {'skip': '0', 'limit': '2'}  # for two roles in a list
            response = await ac.get("/roles/", params=params)
            assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_roles_list_validation_error(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            params = {'skip': 'string', 'limit': 'string'}  # for two roles in a list
            response = await ac.get("/roles/", params=params)
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_roles_read_single_role(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            role_name = TestRoles.role_name
            response = await ac.get(f"/roles/{role_name}")
            assert response.status_code == HTTP_200_OK
            assert response.json()["name"] == "zekoder-zeauth-users-get"

    @pytest.mark.asyncio
    async def test_roles_read_non_exist_role_with_name(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            role_name = TestRoles.role_name_non_exist
            response = await ac.get(f"/roles/{role_name}")
            assert response.status_code == HTTP_404_NOT_FOUND
            assert response.json() == {"detail": "Role not found"}

    @pytest.mark.asyncio
    async def test_roles_create_new_role(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            json_data = {
                "name": f"{TestRoles.role_name_create}",
                "description": f"{TestRoles.role_description}"
            }
            response = await ac.post("/roles/", json=json_data)
            assert response.status_code == HTTP_201_CREATED

    @pytest.mark.asyncio
    async def test_roles_try_to_create_a_role_with_existing_role_name(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            json_data = {
                "name": f"{TestRoles.role_name_create}",
                "description": f"{TestRoles.role_description}"
            }
            response = await ac.post("/roles/", json=json_data)
            assert response.status_code == HTTP_403_FORBIDDEN
            assert response.json() == {"detail": "Role already exist !"}

    @pytest.mark.asyncio
    async def test_roles_update_a_role(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            role_name = TestRoles.role_name_create
            response = await ac.get(f'/roles/{role_name}')
            id = response.json()["id"]
            json_data = {
                "name": f"{TestRoles.role_name_create}",
                "description": "updated test description"
            }
            response = await ac.put(f'/roles/{id}', json=json_data)
            assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_roles_update_non_exist_role(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            id = TestRoles.non_exist_role_id
            json_data = {
                "name": f"{TestRoles.role_name_create}",
                "description": "updated test description"
            }
            response = await ac.put(f'/roles/{id}', json=json_data)
            assert response.status_code == HTTP_404_NOT_FOUND
            assert response.json() == {"detail": "Role not found"}

    @pytest.mark.asyncio
    async def test_roles_delete_role(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            role_name = TestRoles.role_name_create
            response = await ac.delete(f'/roles/{role_name}')
            assert response.status_code == HTTP_202_ACCEPTED
            assert response.json() == {"detail": f"Role <{role_name}> deleted successfully !"}

    @pytest.mark.asyncio
    async def test_roles_delete_non_existing_role(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            role_name = TestRoles.role_name_create
            response = await ac.delete(f'/roles/{role_name}')
            assert response.status_code == HTTP_404_NOT_FOUND
            assert response.json() == {"detail": "Role not found"}

    @pytest.mark.asyncio
    async def test_roles_delete_send_empty_request_role_name(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            role_name = ""
            response = await ac.delete(f'/roles/{role_name}')
            assert response.status_code == HTTP_405_METHOD_NOT_ALLOWED
            assert response.json() == {"detail": "Method Not Allowed"}

    @pytest.mark.asyncio
    async def test_roles_role_name_empty(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            json_data = {
                "name": "",
                "description": f"{TestRoles.role_description}"
            }
            response = await ac.post("/roles/", json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['Role name can not be empty !']

    @pytest.mark.asyncio
    async def test_roles_role_name_special_and_spaces_character(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            json_data = {
                "name": "+ +",
                "description": f"{TestRoles.role_description}"
            }
            response = await ac.post("/roles/", json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == [
                'Role name cannot contain special characters or spaces !']

    @pytest.mark.asyncio
    async def test_roles_role_name_string_not_accepted(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            json_data = {
                "name": "string",
                "description": f"{TestRoles.role_description}"
            }
            response = await ac.post("/roles/", json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['Role name is not acceptable !']

    @pytest.mark.asyncio
    async def test_roles_role_name_pattern_format_error(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            json_data = {
                "name": "roles-role",
                "description": f"{TestRoles.role_description}"
            }
            response = await ac.post("/roles/", json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ["Role's name pattern should be "
                                                                   "[provider short name]-[app short name]-[resource name]-[permission name]"]

    @pytest.mark.asyncio
    async def test_roles_role_name_contain_uppercase(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            json_data = {
                "name": "Roles-role-role-role",
                "description": f"{TestRoles.role_description}"
            }
            response = await ac.post("/roles/", json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['Role name cannot contain uppercase !']

    @pytest.mark.asyncio
    async def test_roles_role_name_latin_characters(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            json_data = {
                "name": "üiles-üle-role-role",
                "description": f"{TestRoles.role_description}"
            }
            response = await ac.post("/roles/", json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['Role name cannot contain latin characters !']
