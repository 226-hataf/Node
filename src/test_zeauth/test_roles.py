from fastapi import status
from fastapi.testclient import TestClient
from api import app

client = TestClient(app)


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


def test_read_role():
    role_name = "zekoder-zeauth-users-create"
    response = client.get(f'/roles/{role_name}')
    json_response = response.json()
    assert response.status_code == 200
    assert json_response["name"] == "zekoder-zeauth-users-create"


def test_read_non_exist_role():
    role_name = "zekoder-zeauth-users"
    response = client.get(f'/roles/{role_name}')
    assert response.status_code == 404
    assert response.json() == {
        "detail": "Role not found"
    }


def test_create_new_role():
    json_data = {
        'name': 'new role2',
        'description': 'the new role2',
    }
    #response = client.post('/roles/', json=json_data)
    #assert response.status_code == 201


def test_create_existing_role():
    """
    TODO: I will add Roles name pattern test here in the next Task: ZEK-657
    """
    """
    json_data = {
        'name': 'new role2',
        'description': 'the new role2',
    }
    response = client.post('/roles/', json=json_data)
    assert response.status_code == 400  # Bad request
    assert response.json() == {
        "detail": "Role already exist !"
    }
    """


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


def test_delete_role():
    """
    role_name = "new role2"
    response = client.delete(f'/roles/{role_name}')
    json_response = response.json()
    assert response.status_code == 202
    assert json_response == {
        "detail": f"Role <{role_name}> deleted successfully !"}
    """


def test_delete_non_existing_role():
    role_name = "new role2"
    response = client.delete(f'/roles/{role_name}')
    json_response = response.json()
    assert response.status_code == 404
    assert json_response == {
        "detail": "Role not found"}


def test_delete_send_empty_role_name():
    role_name = ""
    response = client.delete(f'/roles/{role_name}')
    json_response = response.json()
    assert response.status_code == 405
    assert json_response == {
        "detail": "Method Not Allowed"}


def test_update_role():
    """
    TODO: zekoder.id !!
    """
    """
    json_data = {
        'name': 'updated test role',
        'description': 'updated test description',
    }
    id = "50db192c-8556-11ed-9ebb-2bd4816654b1"     # with valid role UUID
    response = client.put(f'/roles/{id}', json=json_data)
    json_response = response.json()
    assert response.status_code == 200
    """

