from httpx import AsyncClient
import pytest
from api import app
from starlette.status import HTTP_307_TEMPORARY_REDIRECT
from business.models.schema_groups_role import GroupsRoleBase, GroupsUserBase
from business.models.schema_roles import RoleBaseSchema
from core.crud import get_user_by_email, get_role_by_name, get_group_by_name
from business.models.dependencies import get_current_user
from core.db_models import models
from test_zeauth_unittests.conftest_db import override_get_db
from config.db import get_db
from core import crud


async def mock_user_roles():
    return None


app.dependency_overrides[get_current_user] = mock_user_roles
app.dependency_overrides[get_db] = override_get_db  # override main DB to Test DB


class TestMain:
    non_exist_role_name = "test-unit-role-role"
    non_exist_role_id = "a0d3aaee-77fc-457b-ba7f-321cc116388b"
    non_exist_group_id = "e6f4f61b-dfbe-4296-8fe5-266f9970929e"
    non_exist_user_id = "a0d3aaee-77fc-457b-ba7f-321cc116388b"

    @pytest.mark.asyncio
    async def test_bootstrap_is_role_not_exists(self):
        db = get_db().__next__()
        role_name = TestMain.non_exist_role_name
        role_description = "test roles"
        role_create = RoleBaseSchema(name=role_name, description=role_description)
        res = crud.is_role_not_exists(db, role_create)
        assert res == 1

    @pytest.mark.asyncio
    async def test_bootstrap_is_groups_role_not_exists(self):
        db = get_db().__next__()
        roles_id = TestMain.non_exist_role_id
        group_id = TestMain.non_exist_group_id

        groups_role = GroupsRoleBase(roles=roles_id, groups=group_id)
        res = crud.is_groups_role_not_exists(db, groups_role)
        assert res == 1

    @pytest.mark.asyncio
    async def test_bootstrap_is_groups_user_not_exists(self):
        db = get_db().__next__()
        user_id = TestMain.non_exist_user_id
        group_id = TestMain.non_exist_group_id

        groups_user = GroupsUserBase(users=user_id, groups=group_id)
        res = crud.is_groups_user_not_exists(db, groups_user)
        assert res == 1

    @pytest.mark.asyncio
    async def test_bootstrap_create_groups_role(self):
        db = get_db().__next__()
        role_id = get_role_by_name(db, "zekoder-zeauth-users-list")
        group_id = get_group_by_name(db, "user")

        groups_role = GroupsRoleBase(roles=role_id.id, groups=group_id.id)
        res = crud.create_groups_role(db, groups_role)
        assert str(group_id.id) == str(res.groups)
        # remove groups roles after test is done
        delete_group_roles = db.query(models.GroupsRole) \
            .filter(models.GroupsRole.groups == group_id.id) \
            .filter(models.GroupsRole.roles == role_id.id) \
            .first()
        db.delete(delete_group_roles)
        db.commit()

    @pytest.mark.asyncio
    async def test_bootstrap_create_groups_user(self):
        db = get_db().__next__()
        user = get_user_by_email(db, "user@test.com")
        group_id = get_group_by_name(db, "user")

        group_user = GroupsUserBase(users=user.id, groups=group_id.id)
        res = crud.create_groups_user(db, group_user)
        assert str(group_id.id) == str(res.groups)
        # remove groups users after test is done
        delete_group_users = db.query(models.GroupsUser) \
            .filter(models.GroupsUser.groups == group_id.id) \
            .filter(models.GroupsUser.users == user.id) \
            .first()
        db.delete(delete_group_users)
        db.commit()

    @pytest.mark.asyncio
    async def test_social_google(self):
        async with AsyncClient(app=app, base_url="https://zekoder-zeauth-dev-25ahf2meja-uc.a.run.app/") as ac:

            response = await ac.get("/brokers/google")
            assert response.status_code == HTTP_307_TEMPORARY_REDIRECT

    @pytest.mark.asyncio
    async def test_social_facebook(self):
        async with AsyncClient(app=app, base_url="https://zekoder-zeauth-dev-25ahf2meja-uc.a.run.app/") as ac:
            response = await ac.get("/brokers/facebook")
            assert response.status_code == HTTP_307_TEMPORARY_REDIRECT

    @pytest.mark.asyncio
    async def test_social_twitter(self):
        async with AsyncClient(app=app, base_url="https://zekoder-zeauth-dev-25ahf2meja-uc.a.run.app/") as ac:
            response = await ac.get("/brokers/twitter")
            assert response.status_code == HTTP_307_TEMPORARY_REDIRECT
