from fastapi import status
from fastapi.testclient import TestClient
from api import app

client = TestClient(app)


class TestEnv:
    """
    TODO: https://nose.readthedocs.io/en/latest/testing.html
    check this out to prepare for the next tests
    """
    role_id = "b379e70a-86b6-11ed-9197-77f2920fbaf9"
    role_id_non_uuid_format = "890779dc-85d6"

    users1 = "608f16de-86a5-11ed-aa9a-7fd0581785c5"
    users2 = "448c113a-86a5-11ed-ade8-27ce4ff8439f"

    roles1 = "b379e70a-86b6-11ed-9197-77f2920fbaf9"
    roles2 = "b456dc32-86b6-11ed-9197-dfa4647856ad"

    role_name = "zekoder-zeauth-users-create"
    role_name_non_exist = "zekoder-zeauth"
    role_name_create = "New Role"
    role_description = "New Role Description"
    role_name_delete = "New Role"


def test_read_all_roles():
    params = {
        'skip': '0',
        'limit': '2'  # for two roles in a list
    }
    response = client.get('/roles/', params=params)
    json_response = response.json()
    assert response.status_code == 200
    assert [x["name"] for x in json_response] == ["zekoder-zeauth-users-create", "zekoder-zeauth-users-list"]


def test_read_all_roles_validation_error():
    params = {
        'skip': 'string',
        'limit': 'string'
    }
    response = client.get('/roles/', params=params)
    assert response.status_code == 422


def test_read_a_role():
    role_name = TestEnv.role_name
    response = client.get(f'/roles/{role_name}')
    json_response = response.json()
    assert response.status_code == 200
    assert json_response["name"] == "zekoder-zeauth-users-create"


def test_read_non_exist_role():
    role_name = TestEnv.role_name_non_exist
    response = client.get(f'/roles/{role_name}')
    assert response.status_code == 404
    assert response.json() == {"detail": "Role not found"}


def test_create_new_role():
    json_data = {
        "name": f"{TestEnv.role_name_create}",
        "description": f"{TestEnv.role_description}"
    }
    response = client.post('/roles/', json=json_data)
    assert response.status_code == 201


def test_create_existing_role():
    json_data = {
        "name": f"{TestEnv.role_name_create}",
        "description": f"{TestEnv.role_description}"
    }
    response = client.post('/roles/', json=json_data)
    assert response.status_code == 403  # Bad request
    assert response.json() == {"detail": "Role already exist !"}


def test_create_empty_role():
    json_data = {
        'name': '',
        'description': '',
    }
    response = client.post('/roles/', json=json_data)
    json_response = response.json()
    assert response.status_code == 422  # Validation Error
    assert [x["msg"] for x in json_response["detail"]] == ['Role name can not be empty ! ']
    assert [x["type"] for x in json_response["detail"]] == ['assertion_error']


def test_update_a_role():
    id = TestEnv.role_id
    json_data = {
        "name": f"{TestEnv.role_name_delete}",
        "description": "updated test description",
        "role_id": f"{id}"
    }
    response = client.put(f'/roles/{id}', json=json_data)
    json_response = response.json()
    assert response.status_code == 200


def test_delete_role():
    role_name = TestEnv.role_name_delete
    response = client.delete(f'/roles/{role_name}')
    json_response = response.json()
    assert response.status_code == 202
    assert json_response == {"detail": f"Role <{role_name}> deleted successfully !"}


def test_delete_non_existing_role():
    role_name = TestEnv.role_name_non_exist
    response = client.delete(f'/roles/{role_name}')
    json_response = response.json()
    assert response.status_code == 404
    assert json_response == {"detail": "Role not found"}


def test_delete_send_empty_role_name():
    role_name = ""
    response = client.delete(f'/roles/{role_name}')
    json_response = response.json()
    assert response.status_code == 405
    assert json_response == {"detail": "Method Not Allowed"}




