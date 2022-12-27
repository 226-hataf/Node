from fastapi.testclient import TestClient
from api import app

client = TestClient(app)


def test_read_all_groups():
    params = {
        'skip': '0',
        'limit': '3'  # for two roles in a list
    }
    response = client.get('/groups/', params=params)
    json_response = response.json()
    assert response.status_code == 200
    assert [x["name"] for x in json_response] == ["admin", "super-user", "user"]


def test_read_all_groups_validation_error():
    params = {
        'skip': 'string',
        'limit': 'string'
    }
    response = client.get('/groups/', params=params)
    assert response.status_code == 422


def test_read_a_group():
    role_name = "user"
    response = client.get(f'/groups/{role_name}')
    json_response = response.json()
    assert response.status_code == 200
    assert json_response["name"] == "user"


def test_read_non_exist_group():
    group_name = "user-user"
    response = client.get(f'/groups/{group_name}')
    assert response.status_code == 404
    assert response.json() == {
        "detail": "Group not found"
    }


def test_create_new_group():
    json_data = {
        'name': 'new group',
        'description': 'the new group',
    }
    #response = client.post('/groups/', json=json_data)
    #assert response.status_code == 201


def test_create_existing_group():
    json_data = {
        'name': 'new group',
        'description': 'the new group',
    }
    response = client.post('/groups/', json=json_data)
    assert response.status_code == 400  # Bad request
    assert response.json() == {
        "detail": "Group already exist !"
    }


def test_create_empty_group():
    json_data = {
        'name': '',
        'description': '',
    }
    response = client.post('/groups/', json=json_data)
    json_response = response.json()
    assert response.status_code == 422  # Validation Error
    assert [x["msg"] for x in json_response["detail"]] == ['Group name can not be empty ! ']
    assert [x["type"] for x in json_response["detail"]] == ['assertion_error']


def test_delete_group():
    group_name = "new group"
    response = client.delete(f'/groups/{group_name}')
    json_response = response.json()
    assert response.status_code == 202
    assert json_response == {
        "detail": f"Group <{group_name}> deleted successfully !"}


def test_delete_non_existing_group():
    group_name = "non group"
    response = client.delete(f'/groups/{group_name}')
    json_response = response.json()
    assert response.status_code == 404
    assert json_response == {
        "detail": "Group not found"}


def test_delete_send_empty_group_name():
    group_name = ""
    response = client.delete(f'/groups/{group_name}')
    json_response = response.json()
    assert response.status_code == 405
    assert json_response == {
        "detail": "Method Not Allowed"}


def test_update_a_group():
    """
    TODO: zekoder.id !!
    """
    """
    json_data = {
        'name': 'updated test group',
        'description': 'updated test description',
    }
    id = "c4ff7b76-83db-11ed-8467-7f88816a45ec"     # with valid group UUID
    response = client.put(f'/groups/{id}', json=json_data)
    json_response = response.json()
    assert response.status_code == 200
    """