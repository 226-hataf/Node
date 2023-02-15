import pytest
from httpx import AsyncClient
from starlette.status import HTTP_200_OK
from api import app


class TestRoot:
    @pytest.mark.asyncio
    async def test_root(self):  # root
        async with AsyncClient(app=app, base_url="http://localhost:8080/") as ac:
            res = await ac.get("/")
            assert res.status_code == HTTP_200_OK
            assert res.json() == {'message': 'ZeKoder Security Management API'}





