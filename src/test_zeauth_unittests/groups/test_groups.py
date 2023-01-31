import pytest
from httpx import AsyncClient
from api import app
from starlette.status import HTTP_200_OK, HTTP_422_UNPROCESSABLE_ENTITY, \
    HTTP_404_NOT_FOUND, HTTP_201_CREATED, HTTP_403_FORBIDDEN, HTTP_202_ACCEPTED, HTTP_405_METHOD_NOT_ALLOWED
from config.db import get_db
from core.crud import get_user_by_email, get_multi_users_by_emails
from business.models.dependencies import get_current_user
from fastapi import Security


async def mock_user_roles():
    return Security(get_current_user, scopes=[""])

app.dependency_overrides[get_current_user] = mock_user_roles


class TestGroups:
    non_exist_group_id = "a0d3aaee-77fc-457b-ba7f-321cc116388b"
    not_exist_user_or_role_id = "e6f4f61b-dfbe-4296-8fe5-266f9970929e"
    group_id_non_uuid_format = "890779dc-85d6"
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

            user1, user2 = get_multi_users_by_emails(db, emails)
            json_data = {"users": [f"{str(user1)}", f"{str(user2)}"]}
            response = await ac.patch(f'/groups/{group_id}', json=json_data)
            assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_groups_assign_users_to_group_users_already_in_group(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            emails = ["user@test.com", "admin@test.com"]

            group_name = TestGroups.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            user1, user2 = get_multi_users_by_emails(db, emails)
            json_data = {"users": [f"{str(user1)}", f"{str(user2)}"]}
            response = await ac.patch(f'/groups/{group_id}', json=json_data)
            assert response.status_code == HTTP_403_FORBIDDEN
            assert response.json() == {"detail": "Available users are already in the group"}

    @pytest.mark.asyncio
    async def test_groups_assign_users_to_group_id_non_uuid_format_request(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            emails = ["user@test.com", "admin@test.com"]
            group_id = TestGroups.group_id_non_uuid_format

            user1, user2 = get_multi_users_by_emails(db, emails)
            json_data = {"users": [f"{str(user1)}", f"{str(user2)}"]}
            response = await ac.patch(f'/groups/{group_id}', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']
            assert [x["type"] for x in json_response["detail"]] == ['type_error.uuid']

    @pytest.mark.asyncio
    async def test_groups_assign_users_to_group_group_id_empty_request(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            emails = ["user@test.com", "admin@test.com"]
            group_id = ""

            user1, user2 = get_multi_users_by_emails(db, emails)
            json_data = {"users": [f"{str(user1)}", f"{str(user2)}"]}
            response = await ac.patch(f'/groups/{group_id}', json=json_data)
            assert response.status_code == HTTP_405_METHOD_NOT_ALLOWED
            assert response.json() == {"detail": "Method Not Allowed"}

    @pytest.mark.asyncio
    async def test_groups_assign_users_to_group_user_id_empty_request(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestGroups.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            json_data = {"users": [""]}
            response = await ac.patch(f'/groups/{group_id}', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']
            assert [x["type"] for x in json_response["detail"]] == ['type_error.uuid']

    @pytest.mark.asyncio
    async def test_groups_assign_users_and_roles_to_a_group_together_error(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            emails = ["user@test.com", "admin@test.com"]

            group_name = TestGroups.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            params = {'skip': '0', 'limit': '2'}  # for two roles in a list
            response = await ac.get("/roles/", params=params)
            roles1, roles2 = [rol["id"] for rol in response.json()]

            user1, user2 = get_multi_users_by_emails(db, emails)

            json_data = {
                "users": [f"{str(user1)}", f"{str(user2)}"],
                "roles": [f"{roles1}", f"{roles2}"]
            }
            response = await ac.patch(f'/groups/{group_id}', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['Neither users nor roles are set in body']

    @pytest.mark.asyncio
    async def test_groups_assign_no_users_and_no_roles_to_a_group_request(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestGroups.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            json_data = {}
            response = await ac.patch(f'/groups/{group_id}', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['Neither users nor roles are set in body']

    @pytest.mark.asyncio
    async def test_groups_assign_users_and_roles_at_the_same_time_with_non_roles(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            email = "user@test.com"

            group_name = TestGroups.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            user1 = get_user_by_email(db, email)

            json_data = {
                "users": [f"{str(user1)}"],
                "roles": [""]
            }
            response = await ac.patch(f'/groups/{group_id}', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['Neither users nor roles are set in body']

    @pytest.mark.asyncio
    async def test_groups_remove_users_from_groups_users_success(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            emails = ["user@test.com", "admin@test.com"]

            group_name = TestGroups.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            user1, user2 = get_multi_users_by_emails(db, emails)

            json_data = {
                "users": [f"{str(user1)}", f"{str(user2)}"]
            }
            response = await ac.patch(f'/groups/{group_id}/remove', json=json_data)
            assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_groups_remove_roles_from_groups_roles_success(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestGroups.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            params = {'skip': '0', 'limit': '2'}  # for two roles in a list
            response = await ac.get("/roles/", params=params)
            roles1, roles2 = [rol["id"] for rol in response.json()]

            json_data = {
                "roles": [f"{str(roles1)}", f"{str(roles2)}"]
            }
            response = await ac.patch(f'/groups/{group_id}/remove', json=json_data)
            assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_groups_remove_roles_from_groups_roles_group_id_not_found(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_id = TestGroups.non_exist_group_id

            params = {'skip': '0', 'limit': '2'}  # for two roles in a list
            response = await ac.get("/roles/", params=params)
            roles1, roles2 = [rol["id"] for rol in response.json()]

            json_data = {
                "roles": [f"{str(roles1)}", f"{str(roles2)}"]
            }
            response = await ac.patch(f'/groups/{group_id}/remove', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_404_NOT_FOUND
            assert json_response == {"detail": "Group not found"}

    @pytest.mark.asyncio
    async def test_groups_remove_users_from_groups_users_group_id_not_found(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            emails = ["user@test.com", "admin@test.com"]

            group_id = TestGroups.non_exist_group_id
            user1, user2 = get_multi_users_by_emails(db, emails)

            json_data = {
                "roles": [f"{str(user1)}", f"{str(user2)}"]
            }
            response = await ac.patch(f'/groups/{group_id}/remove', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_404_NOT_FOUND
            assert json_response == {"detail": "Group not found"}

    @pytest.mark.asyncio
    async def test_groups_remove_users_from_groups_users_user_id_not_found(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            user1 = TestGroups.not_exist_user_or_role_id

            group_name = TestGroups.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            json_data = {
                "users": [f"{str(user1)}"]
            }
            response = await ac.patch(f'/groups/{group_id}/remove', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_404_NOT_FOUND
            assert json_response == {"detail": "Users not exist"}

    @pytest.mark.asyncio
    async def test_groups_remove_roles_from_groups_roles_role_id_not_exist(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            roles1 = TestGroups.not_exist_user_or_role_id

            group_name = TestGroups.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            json_data = {
                "roles": [f"{str(roles1)}"]
            }
            response = await ac.patch(f'/groups/{group_id}/remove', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_404_NOT_FOUND
            assert json_response == {"detail": "Roles not exist"}

    @pytest.mark.asyncio
    async def test_groups_remove_users_and_roles_at_the_same_time_from_a_group(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            emails = ["user@test.com", "admin@test.com"]

            group_name = TestGroups.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            params = {'skip': '0', 'limit': '2'}  # for two roles in a list
            response = await ac.get("/roles/", params=params)
            roles1, roles2 = [rol["id"] for rol in response.json()]

            user1, user2 = get_multi_users_by_emails(db, emails)

            json_data = {
                "users": [f"{str(user1)}", f"{str(user2)}"],
                "roles": [f"{roles1}", f"{roles2}"]
            }
            response = await ac.patch(f'/groups/{group_id}/remove', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['Neither users nor roles are set in body']

    @pytest.mark.asyncio
    async def test_groups_remove_no_users_or_roles_request(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            group_name = TestGroups.group_name
            response = await ac.get(f'/groups/{group_name}')
            group_id = response.json()["id"]

            json_data = {}

            response = await ac.patch(f'/groups/{group_id}/remove', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['Neither users nor roles are set in body']

    @pytest.mark.asyncio
    async def test_groups_remove_users_or_roles_from_a_empty_group_id_request(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            emails = ["user@test.com", "admin@test.com"]

            group_id = ""

            params = {'skip': '0', 'limit': '2'}  # for two roles in a list
            response = await ac.get("/roles/", params=params)
            roles1, roles2 = [rol["id"] for rol in response.json()]

            user1, user2 = get_multi_users_by_emails(db, emails)

            json_data = {
                "users": [f"{str(user1)}", f"{str(user2)}"],
                "roles": [f"{roles1}", f"{roles2}"]
            }
            response = await ac.patch(f'/groups/{group_id}/remove', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_404_NOT_FOUND
            assert json_response == {"detail": "Not Found"}

    @pytest.mark.asyncio
    async def test_groups_remove_users_from_non_uuid_format_group_id_request(self):
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            db = get_db().__next__()
            emails = ["user@test.com", "admin@test.com"]

            group_id = TestGroups.group_id_non_uuid_format

            user1, user2 = get_multi_users_by_emails(db, emails)

            json_data = {
                "users": [f"{str(user1)}", f"{str(user2)}"]
            }
            response = await ac.patch(f'/groups/{group_id}/remove', json=json_data)
            json_response = response.json()
            assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
            assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']
            assert [x["type"] for x in json_response["detail"]] == ['type_error.uuid']















