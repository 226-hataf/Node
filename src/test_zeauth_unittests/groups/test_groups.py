import pytest
from httpx import AsyncClient
from api import app
from starlette.status import HTTP_200_OK, HTTP_422_UNPROCESSABLE_ENTITY, \
    HTTP_404_NOT_FOUND, HTTP_201_CREATED, HTTP_403_FORBIDDEN, HTTP_202_ACCEPTED, HTTP_405_METHOD_NOT_ALLOWED

from config import db
from config.db import get_db
from core.db_models import models
from sqlalchemy.orm import Session

class TestGroups:
    non_exist_group_id = "a0d3aaee-77fc-457b-ba7f-321cc116388b"
    group_name = "user"
    group_name_non_exist = "tester"
    group_name_create = "fake-group"

    @pytest.mark.asyncio
    async def test_groups_list_success(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            params = {'skip': '0', 'limit': '3'}  # for three groups in a list
            response = await ac.get("/groups/", params=params)
        assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_groups_list_validation_error(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            params = {'skip': 'string', 'limit': 'string'}  # for two roles in a list
            response = await ac.get("/groups/", params=params)
        assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_groups_read_single_group(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestGroups.group_name
            response = await ac.get(f"/groups/{group_name}")
        assert response.status_code == HTTP_200_OK
        assert response.json()["name"] == "user"

    @pytest.mark.asyncio
    async def test_groups_read_non_exist_group_with_name(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestGroups.group_name_non_exist
            response = await ac.get(f"/groups/{group_name}")
        assert response.status_code == HTTP_404_NOT_FOUND
        assert response.json() == {"detail": "Group not found"}

    @pytest.mark.asyncio
    async def test_groups_create_new_group(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            json_data = {
                "name": f"{TestGroups.group_name_create}",
                "description": f"{TestGroups.group_name_create}"
            }
            response = await ac.post("/groups/", json=json_data)
        assert response.status_code == HTTP_201_CREATED

    @pytest.mark.asyncio
    async def test_groups_try_to_create_a_group_with_existing_group_name(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            json_data = {
                "name": f"{TestGroups.group_name_create}",
                "description": f"{TestGroups.group_name_create}"
            }
            response = await ac.post("/groups/", json=json_data)
        assert response.status_code == HTTP_403_FORBIDDEN
        assert response.json() == {"detail": "Group already exist !"}

    @pytest.mark.asyncio
    async def test_groups_update_a_group(self):
        """
        TODO: Next do this !
        TODO: This test is passed but you have to implement override method to token.auth(model.permissions.update)
        """
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestGroups.group_name_create
            response = await ac.get(f'/groups/{group_name}')
            id = response.json()["id"]
            json_data = {
                "name": f"{TestGroups.group_name_create}",
                "description": "updated test description"
            }
            response = await ac.put(f'/groups/{id}', json=json_data)
        assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_groups_update_non_exist_group(self):
        """
        TODO: Next do this !
        TODO: This test is passed but you have to implement override method to token.auth(model.permissions.update)
        """
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            id = TestGroups.non_exist_group_id
            json_data = {
                "name": f"{TestGroups.group_name_create}",
                "description": "updated test description"
            }
            response = await ac.put(f'/groups/{id}', json=json_data)
        assert response.status_code == HTTP_404_NOT_FOUND
        assert response.json() == {"detail": "Group not found"}

    @pytest.mark.asyncio
    async def test_groups_delete_group(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestGroups.group_name_create
            response = await ac.delete(f'/groups/{group_name}')
        assert response.status_code == HTTP_202_ACCEPTED
        assert response.json() == {"detail": f"Group <{group_name}> deleted successfully !"}

    @pytest.mark.asyncio
    async def test_groups_delete_non_existing_group(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestGroups.group_name_create
            response = await ac.delete(f'/groups/{group_name}')
        assert response.status_code == HTTP_404_NOT_FOUND
        assert response.json() == {"detail": "Group not found"}

    @pytest.mark.asyncio
    async def test_groups_delete_send_empty_request_group_name(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = ""
            response = await ac.delete(f'/groups/{group_name}')
        assert response.status_code == HTTP_405_METHOD_NOT_ALLOWED
        assert response.json() == {"detail": "Method Not Allowed"}

    @pytest.mark.asyncio
    async def test_groups_assign_roles_to_group_success(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestGroups.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            params = {'skip': '0', 'limit': '2'}  # for two roles in a list
            response = await ac.get("/roles/", params=params)
            roles1, roles2 = [rol["id"] for rol in response.json()]

            json_data = {"roles": [f"{roles1}", f"{roles2}"]}
            response = await ac.patch(f'/groups/{group_id}', json=json_data)
        assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_groups_assign_available_roles_to_group_again(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestGroups.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            params = {'skip': '0', 'limit': '2'}  # for two roles in a list
            response = await ac.get("/roles/", params=params)
            roles1, roles2 = [rol["id"] for rol in response.json()]

            json_data = {"roles": [f"{roles1}", f"{roles2}"]}
            response = await ac.patch(f'/groups/{group_id}', json=json_data)
        assert response.status_code == HTTP_403_FORBIDDEN
        assert response.json() == {"detail": "Available roles are already in the group"}

    @pytest.mark.asyncio
    async def test_groups_assign_roles_to_group_with_non_uuid_format(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_id = "1234-33"    # non uuid format

            params = {'skip': '0', 'limit': '2'}  # for two roles in a list
            response = await ac.get("/roles/", params=params)
            roles1, roles2 = [rol["id"] for rol in response.json()]

            json_data = {"roles": [f"{roles1}", f"{roles2}"]}
            response = await ac.patch(f'/groups/{group_id}', json=json_data)
            json_response = response.json()
        assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
        assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']
        assert [x["type"] for x in json_response["detail"]] == ['type_error.uuid']

    @pytest.mark.asyncio
    async def test_groups_assign_roles_to_group_with_empty_group_id_request(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_id = ""

            params = {'skip': '0', 'limit': '2'}  # for two roles in a list
            response = await ac.get("/roles/", params=params)
            roles1, roles2 = [rol["id"] for rol in response.json()]

            json_data = {"roles": [f"{roles1}", f"{roles2}"]}
            response = await ac.patch(f'/groups/{group_id}', json=json_data)
        assert response.status_code == HTTP_405_METHOD_NOT_ALLOWED
        assert response.json() == {"detail": "Method Not Allowed"}

    @pytest.mark.asyncio
    async def test_groups_assign_roles_to_group_with_non_exist_group_id(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_id = TestGroups.non_exist_group_id

            params = {'skip': '0', 'limit': '2'}  # for two roles in a list
            response = await ac.get("/roles/", params=params)
            roles1, roles2 = [rol["id"] for rol in response.json()]

            json_data = {"roles": [f"{roles1}", f"{roles2}"]}
            response = await ac.patch(f'/groups/{group_id}', json=json_data)
        assert response.status_code == HTTP_404_NOT_FOUND
        assert response.json() == {"detail": "Group not found"}

    @pytest.mark.asyncio
    async def test_groups_assign_roles_to_group_roles_id_empty_request(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestGroups.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            json_data = {"roles": [""]}
            response = await ac.patch(f'/groups/{group_id}', json=json_data)
            json_response = response.json()
        assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
        assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']
        assert [x["type"] for x in json_response["detail"]] == ['type_error.uuid']

    @pytest.mark.asyncio
    async def test_groups_assign_users_to_group_success(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            emails = ["user@test.com", "admin@test.com"]
            group_name = TestGroups.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            user1, user2 = [obj.id for obj in db.query(models.User).filter(models.User.email.in_(emails))]
            json_data = {"users": [f"{str(user1)}", f"{str(user2)}"]}
            response = await ac.patch(f'/groups/{group_id}', json=json_data)
        assert response.status_code == HTTP_200_OK












