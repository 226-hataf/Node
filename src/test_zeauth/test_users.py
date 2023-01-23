from fastapi.testclient import TestClient
from api import app


client = TestClient(app)


class TestEnv:

    user_id = "de76de3e-9577-11ed-983c-83ad79d0c28b"
    user_id2 = "b9ae5870-933d-11ed-bfa0-bf475bd063ff"
    invalid_user_id = "12345"
    not_exists_user = "8077c4ab-5fe7-4e14-b85d-e0f49b41cf5d"
    not_exists_user2 = "39857a6f-6da9-47c1-9f7d-6fc4aff19dfa"
    group_id = "c2d8326a-86b6-11ed-9197-cf76c39d044b"
    not_exists_group_id = "8077c4ab-5fe7-4e14-b85d-e0f49b41cf5d"


def test_user_to_group_success():
    user_id = TestEnv.user_id
    group_id = TestEnv.group_id
    response = client.patch(f"/users/{user_id}/group/{group_id}")
    json_response = response.json()
    assert response.status_code == 200
    assert ''.join([x["users"] for x in json_response]) == f"{user_id}"
    assert ''.join([x["groups"] for x in json_response]) == f"{group_id}"


def test_user_to_group_group_not_found():
    user_id = TestEnv.user_id
    group_id = TestEnv.not_exists_group_id
    response = client.patch(f"/users/{user_id}/group/{group_id}")
    json_response = response.json()
    assert response.status_code == 404
    assert json_response == {"detail": "Group not found"}


def test_user_to_group_again():
    user_id = TestEnv.user_id
    group_id = TestEnv.group_id
    response = client.patch(f"/users/{user_id}/group/{group_id}")
    json_response = response.json()
    assert response.status_code == 403
    assert json_response == {"detail": "Available users are already in the group"}


def test_user_to_group_with_invalid_uuid():
    user_id = TestEnv.invalid_user_id
    group_id = TestEnv.group_id
    response = client.patch(f"/users/{user_id}/group/{group_id}")
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']


def test_user_deassign_from_a_group():
    user_id = TestEnv.user_id
    group_id = TestEnv.group_id
    response = client.patch(f"/users/{user_id}/group/{group_id}/remove")
    assert response.status_code == 200


def test_user_deassign_not_exist_user_from_a_group():
    user_id = TestEnv.not_exists_user
    group_id = TestEnv.group_id
    response = client.patch(f"/users/{user_id}/group/{group_id}/remove")
    json_response = response.json()
    assert response.status_code == 404
    assert json_response == {"detail": "User not exist"}


def test_user_deassign_with_not_exist_group_id():
    user_id = TestEnv.user_id
    group_id = TestEnv.not_exists_group_id
    response = client.patch(f"/users/{user_id}/group/{group_id}/remove")
    json_response = response.json()
    assert response.status_code == 404
    assert json_response == {"detail": "Group not found"}


def test_user_to_group_empty_user_request():
    user_id = ""
    group_id = TestEnv.group_id
    response = client.patch(f"/users/{user_id}/group/{group_id}")
    json_response = response.json()
    assert response.status_code == 404
    assert json_response == {"detail": "Not Found"}


def test_user_to_group_empty_group_request():
    user_id = TestEnv.user_id
    group_id = ""
    response = client.patch(f"/users/{user_id}/group/{group_id}")
    json_response = response.json()
    assert response.status_code == 404
    assert json_response == {"detail": "Not Found"}


def test_user_to_group_with_not_exist_user():
    user_id = TestEnv.not_exists_user
    group_id = TestEnv.group_id
    response = client.patch(f"/users/{user_id}/group/{group_id}")
    json_response = response.json()
    assert response.status_code == 404
    assert json_response == {"detail": "User not exist"}


def test_exist_user_active_off():
    user_id = TestEnv.user_id
    q = 'OFF'
    response = client.put(f"/users/{user_id}/off")
    json_response = response.json()
    assert response.status_code == 201
    assert json_response == {"user_id": f"{user_id}", "user_activation": f"{q}"}


def test_non_exist_user_try_active_off():
    user_id = TestEnv.not_exists_user
    q = 'OFF'
    response = client.put(f"/users/{user_id}/off")
    json_response = response.json()
    assert response.status_code == 404
    assert json_response == {"detail": "User not found"}


def test_invalid_user_id_try_active_off():
    user_id = TestEnv.invalid_user_id
    q = 'OFF'
    response = client.put(f"/users/{user_id}/off")
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']


def test_exist_user_active_on():
    user_id = TestEnv.user_id
    q = 'ON'
    response = client.put(f"/users/{user_id}/on")
    json_response = response.json()
    assert response.status_code == 201
    assert json_response == {"user_id": f"{user_id}", "user_activation": f"{q}"}


def test_non_exist_user_try_active_on():
    user_id = TestEnv.not_exists_user
    q = 'ON'
    response = client.put(f"/users/{user_id}/on")
    json_response = response.json()
    assert response.status_code == 404
    assert json_response == {"detail": "User not found"}


def test_invalid_user_id_try_active_on():
    user_id = TestEnv.invalid_user_id
    q = 'ON'
    response = client.put(f"/users/{user_id}/on")
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']


def test_get_exist_users_with_ids():
    user_id = TestEnv.user_id
    user_id2 = TestEnv.user_id2
    json_data = {
        'users_ids': [
            f"{user_id}", f"{user_id2}"
        ]
    }
    response = client.post('/users/with_ids', json=json_data)
    json_response = response.json()
    assert response.status_code == 200
    assert [x["user"][0]['id'] for x in json_response] == [f"{user_id}", f"{user_id2}"]


def test_get_non_exist_users_with_ids():
    user_id = TestEnv.not_exists_user
    user_id2 = TestEnv.not_exists_user2
    json_data = {
        'users_ids': [
            f"{user_id}", f"{user_id2}"
        ]
    }
    response = client.post('/users/with_ids', json=json_data)
    json_response = response.json()
    assert response.status_code == 200
    assert json_response == []


def test_invalid_user_id_get_users_with_ids():
    user_id = TestEnv.invalid_user_id
    json_data = {
        "users_ids": [
            f"{user_id}"
        ]
    }
    response = client.post('/users/with_ids', json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']


def test_empty_response_get_users_with_ids():
    json_data = {
        "users_ids": [
            ""
        ]
    }
    response = client.post('/users/with_ids', json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']


def test_update_current_user_success():
    user_id = TestEnv.user_id
    json_data = {
        "first_name": "Alper",
        "last_name": "UYGUR",
        "verified": "true",
        "user_status": "true",
        "phone": "555-55-55"
    }
    response = client.put(f'/users/{user_id}', json=json_data)
    json_response = response.json()
    assert response.status_code == 200
    assert json_response == {"first_name": "Alper", "last_name": "UYGUR", "verified": True, "user_status": True,
                             "phone": "555-55-55"}


def test_update_non_exist_user():
    user_id = TestEnv.not_exists_user
    json_data = {
        "first_name": "Alper",
        "last_name": "UYGUR",
        "verified": "true",
        "user_status": "true",
        "phone": "555-55-55"
    }
    response = client.put(f'/users/{user_id}', json=json_data)
    json_response = response.json()
    assert response.status_code == 404
    assert json_response == {"detail": "User not found"}


def test_invalid_user_id_update():
    user_id = TestEnv.invalid_user_id
    json_data = {
        "first_name": "alper",
        "last_name": "uygur",
        "verified": "true",
        "user_status": "true",
        "phone": ""
    }
    response = client.put(f'/users/{user_id}', json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']


def test_send_empty_request_user_update():
    user_id = TestEnv.user_id
    json_data = {

    }
    response = client.put(f"/users/{user_id}", json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['Request body can not be empty !']


def test_extra_field_request_user_update():
    user_id = TestEnv.user_id
    json_data = {
        "first_name": "alper",
        "last_name": "uygur",
        "verified": "true",
        "user_status": "true",
        "phone": "555-55-55",
        "extra_field": "extra_field"
    }
    response = client.put(f"/users/{user_id}", json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['extra fields not permitted']


def test_empty_fields_request_user_update():
    user_id = TestEnv.user_id
    json_data = {
        "first_name": "",
        "last_name": "",
        "verified": "true",
        "user_status": "true",
        "phone": ""
    }
    response = client.put(f"/users/{user_id}", json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['Empty value not excepted ! ', 'Empty value not excepted ! ']


def test_delete_non_exist_user():
    user_id = TestEnv.not_exists_user
    response = client.delete(f'/users/{user_id}')
    json_response = response.json()
    assert response.status_code == 404
    assert json_response == {"detail": "User not found"}


def test_invalid_request_delete_user():
    user_id = TestEnv.invalid_user_id
    response = client.delete(f'/users/{user_id}')
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']


def test_empty_request_delete_user():
    user_id = ""
    response = client.delete(f'/users/{user_id}')
    json_response = response.json()
    assert response.status_code == 405
    assert json_response == {'detail': 'Method Not Allowed'}


def test_create_new_user_success():
    json_data = {
        "email": "test1@test.com",
        "username": "test1@test.com",
        "password": "Te@Test&34",
        "first_name": "test",
        "last_name": "user",
        "verified": "true",
        "user_status": "true",
        "phone": "555"
    }
    response = client.post('/users/', json=json_data)
    json_response = response.json()
    assert response.status_code == 201
    assert json_response["email"] == 'test1@test.com'


def test_create_new_user_with_exist_email():
    json_data = {
        "email": "a.uygur@cyberneticlabs.io",
        "username": "a.uygur@cyberneticlabs.io",
        "password": "Te@Test&34",
        "first_name": "test",
        "last_name": "user",
        "verified": "true",
        "user_status": "true",
        "phone": "555"
    }
    response = client.post('/users/', json=json_data)
    json_response = response.json()
    assert response.status_code == 403
    assert json_response == {"detail": "Email already in use !"}


def test_create_new_user_with_empty_request():
    json_data = {

    }
    response = client.post("/users/", json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['field required']


def test_create_user_with_invalid_email_format():
    json_data = {
        "email": "abc",
        "username": "",
        "password": "Te@Test&34",
        "first_name": "",
        "last_name": "",
        "verified": "true",
        "user_status": "true",
        "phone": ""
    }
    response = client.post('/users/', json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['invalid email format']



def test_create_user_with_invalid_password_format():

    json_data = {
        "email": "test2@test.com",
        "username": "",
        "password": "invalid",
        "first_name": "",
        "last_name": "",
        "verified": "true",
        "user_status": "true",
        "phone": ""
    }
    response = client.post('/users/', json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['invalid password format']


def test_create_user_with_extra_field_add_to_request():
    json_data = {
        "email": "test2@test.com",
        "username": "",
        "password": "Te@Te&22",
        "first_name": "",
        "last_name": "",
        "verified": "true",
        "user_status": "true",
        "phone": "",
        "phone2222222222": ""
    }
    response = client.post('/users/', json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['extra fields not permitted']
