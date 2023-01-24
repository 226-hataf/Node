import pytest
from httpx import AsyncClient
from api import app
from starlette.status import HTTP_200_OK, HTTP_422_UNPROCESSABLE_ENTITY, \
    HTTP_404_NOT_FOUND, HTTP_201_CREATED, HTTP_403_FORBIDDEN, HTTP_202_ACCEPTED, HTTP_405_METHOD_NOT_ALLOWED


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
        """
        TODO: Next do this !
        TODO: This test is passed but you have to implement override method to token.auth(model.permissions.update)
        """
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
        """
        TODO: Next do this !
        TODO: This test is passed but you have to implement override method to token.auth(model.permissions.update)
        """
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





