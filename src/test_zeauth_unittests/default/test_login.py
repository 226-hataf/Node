import asyncio

import pytest
from httpx import AsyncClient
from api import app
from starlette.status import HTTP_200_OK, HTTP_401_UNAUTHORIZED, HTTP_500_INTERNAL_SERVER_ERROR
from business.providers import get_provider
from business.providers.base import Provider
from config.db import get_db
from core import crud
from test_zeauth_unittests.conftest_db import override_get_db


app.dependency_overrides[get_db] = override_get_db  # override main DB to Test DB


class TestLogin:
    @pytest.mark.asyncio
    async def test_login_success(self):  # user login success
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:

            json_data = {"email": "user@test.com", "password": "Us@Test&34"}
            response = await ac.post("/login", json=json_data)
        assert response.status_code == HTTP_200_OK

    @pytest.mark.asyncio
    async def test_login_failed(self):  # user login failed
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:

            json_data = {"email": "no_name@test.com", "password": "Ab@Cd&12"}
            response = await ac.post("/login", json=json_data)

        assert response.status_code == HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_login_user_not_verified(self,):  # user login not verified
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:

            json_request = {"email": "super-user@test.com", "password": "Sp@Test&34"}
            response = await ac.post("/login", json=json_request)

        assert response.status_code == HTTP_401_UNAUTHORIZED
        assert response.json() == {"detail": "user is not verified!"}
