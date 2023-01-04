from fastapi.testclient import TestClient
from api import app

client = TestClient(app)


class TestEnv:
    """
    TODO: https://nose.readthedocs.io/en/latest/testing.html
    check this out to prepare for the next tests
    """
    group_id = "c2d8326a-86b6-11ed-9197-cf76c39d044b"
    group_id_non_uuid_format = "890779dc-85d6"
    not_exists_group_id = "8077c4ab-5fe7-4e14-b85d-e0f49b41cf5d"

    users1 = "608f16de-86a5-11ed-aa9a-7fd0581785c5"
    users2 = "448c113a-86a5-11ed-ade8-27ce4ff8439f"
    not_exist_user = "e6f4f61b-dfbe-4296-8fe5-266f9970929e"

    roles1 = "b379e70a-86b6-11ed-9197-77f2920fbaf9"
    roles2 = "b456dc32-86b6-11ed-9197-dfa4647856ad"
    not_exist_role = "99b380f0-cb43-4ddc-b1b5-69b04ca5ce4b"

    group_name = "user"
    group_name_non_exist = "user-admin-super"
    group_name_create = "unittest group"
    group_description = "the unittest group"
    group_name_delete = "unittest group"


def test_read_all_groups():
    params = {
        'skip': '0',
        'limit': '3'  # for three groups in a list
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
    group_name = TestEnv.group_name
    response = client.get(f'/groups/{group_name}')
    json_response = response.json()
    assert response.status_code == 200
    assert json_response["name"] == "user"


def test_read_non_exist_group():
    group_name = TestEnv.group_name_non_exist
    response = client.get(f'/groups/{group_name}')
    assert response.status_code == 404
    assert response.json() == {"detail": "Group not found"}


def test_create_new_group():
    json_data = {
        "name": f"{TestEnv.group_name_create}",
        "description": f"{TestEnv.group_description}"
    }
    response = client.post('/groups/', json=json_data)
    assert response.status_code == 201


def test_create_existing_group():
    json_data = {
        "name": f"{TestEnv.group_name_create}",
        "description": f"{TestEnv.group_description}"
    }
    response = client.post('/groups/', json=json_data)
    assert response.status_code == 403  # Bad request
    assert response.json() == {"detail": "Group already exist !"}


def test_create_empty_group():
    json_data = {
        "name": '',
        "description": '',
    }
    response = client.post('/groups/', json=json_data)
    json_response = response.json()
    assert response.status_code == 422  # Validation Error
    assert [x["msg"] for x in json_response["detail"]] == ['Group name can not be empty ! ']
    assert [x["type"] for x in json_response["detail"]] == ['assertion_error']


def test_update_a_group():
    id = TestEnv.group_id
    json_data = {
        "name": f"{TestEnv.group_name_delete}",
        "description": "updated test description",
        "group_id": f"{id}"
    }
    response = client.put(f'/groups/{id}', json=json_data)
    json_response = response.json()
    assert json_response.status_code == 200


def test_delete_group():
    group_name = TestEnv.group_name_delete
    response = client.delete(f'/groups/{group_name}')
    json_response = response.json()
    assert response.status_code == 202
    assert json_response == {"detail": f"Group <{group_name}> deleted successfully !"}


def test_delete_non_existing_group():
    group_name = TestEnv.group_name_non_exist
    response = client.delete(f'/groups/{group_name}')
    json_response = response.json()
    assert response.status_code == 404
    assert json_response == {"detail": "Group not found"}


def test_delete_send_empty_group_name():
    group_name = ""
    response = client.delete(f'/groups/{group_name}')
    json_response = response.json()
    assert response.status_code == 405
    assert json_response == {"detail": "Method Not Allowed"}


def test_roles_to_group_success():
    group_id = TestEnv.group_id
    json_data = {"roles": [f"{TestEnv.roles1}", f"{TestEnv.roles2}"]}
    response = client.patch(f'/groups/{group_id}', json=json_data)
    json_response = response.json()
    assert response.status_code == 200
    assert json_response == [{"roles": [f"{TestEnv.roles1}", f"{TestEnv.roles2}"]}]


def test_roles_to_group_already_in_group_throw_error():
    group_id = TestEnv.group_id
    json_data = {"roles": [f"{TestEnv.roles1}", f"{TestEnv.roles2}"]}
    response = client.patch(f'/groups/{group_id}', json=json_data)
    json_response = response.json()
    assert response.status_code == 403
    assert json_response == {"detail": "Available roles are already in the group"}


def test_roles_to_group_group_id_non_uuid_format_request():
    group_id = TestEnv.group_id_non_uuid_format
    json_data = {"roles": [f"{TestEnv.roles1}", f"{TestEnv.roles2}"]}
    response = client.patch(f'/groups/{group_id}', json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']
    assert [x["type"] for x in json_response["detail"]] == ['type_error.uuid']


def test_roles_to_group_group_id_empty_request():
    group_id = ""
    json_data = {"roles": [f"{TestEnv.roles1}", f"{TestEnv.roles2}"]}
    response = client.patch(f'/groups/{group_id}', json=json_data)
    json_response = response.json()
    assert response.status_code == 405
    assert json_response == {"detail": "Method Not Allowed"}


def test_roles_to_group_group_id_not_found():
    group_id = TestEnv.not_exists_group_id
    json_data = {"roles": [f"{TestEnv.roles1}", f"{TestEnv.roles2}"]}
    response = client.patch(f'/groups/{group_id}', json=json_data)
    json_response = response.json()
    assert response.status_code == 404
    assert json_response == {"detail": "Group not found"}


def test_roles_to_group_roles_id_empty_request():
    """if roles_id none, then roles uuid not valid uuid"""
    group_id = TestEnv.group_id
    json_data = {"roles": [""]}
    response = client.patch(f'/groups/{group_id}', json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']
    assert [x["type"] for x in json_response["detail"]] == ['type_error.uuid']


def test_users_to_group_success():
    group_id = TestEnv.group_id
    json_data = {"users": [f"{TestEnv.users1}", f"{TestEnv.users2}"]}
    response = client.patch(f'/groups/{group_id}', json=json_data)
    json_response = response.json()
    assert response.status_code == 200
    assert json_response == [{"users": [f"{TestEnv.users2}", f"{TestEnv.users1}"]}]


def test_users_to_group_already_in_group_throw_error():
    group_id = TestEnv.group_id
    json_data = {"users": [f"{TestEnv.users1}", f"{TestEnv.users2}"]}
    response = client.patch(f'/groups/{group_id}', json=json_data)
    json_response = response.json()
    assert response.status_code == 403
    assert json_response == {"detail": "Available users are already in the group"}


def test_users_to_group_group_id_non_uuid_format_request():
    group_id = TestEnv.group_id_non_uuid_format
    json_data = {"users": [f"{TestEnv.users1}", f"{TestEnv.users2}"]}
    response = client.patch(f'/groups/{group_id}', json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']
    assert [x["type"] for x in json_response["detail"]] == ['type_error.uuid']


def test_users_to_group_group_id_empty_request():
    group_id = ""
    json_data = {"users": [f"{TestEnv.users1}", f"{TestEnv.users2}"]}
    response = client.patch(f'/groups/{group_id}', json=json_data)
    json_response = response.json()
    assert response.status_code == 405
    assert json_response == {"detail": "Method Not Allowed"}


def test_users_to_group_users_id_empty_request():
    """if users_id none, then users uuid not valid uuid"""
    group_id = TestEnv.group_id
    json_data = {"users": [""]}
    response = client.patch(f'/groups/{group_id}', json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']
    assert [x["type"] for x in json_response["detail"]] == ['type_error.uuid']


def test_users_and_roles_at_the_same_time_assign_to_a_group_error():
    group_id = TestEnv.group_id
    json_data = {
        "users": [
            f"{TestEnv.users1}"
        ],
        "roles": [
            f"{TestEnv.roles1}"
        ]
    }
    response = client.patch(f'/groups/{group_id}', json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['Neither users nor roles are set in body']


def test_no_users_and_no_roles_request_error():
    group_id = TestEnv.group_id
    json_data = {}
    response = client.patch(f'/groups/{group_id}', json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['Neither users nor roles are set in body']


def test_users_and_roles_at_the_same_time_with_none_roles_assign_to_a_group_error():
    group_id = TestEnv.group_id
    json_data = {
        "users": [
            f"{TestEnv.users1}"
        ],
        "roles": [
            ""
        ]
    }
    response = client.patch(f'/groups/{group_id}', json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['Neither users nor roles are set in body']


def test_remove_users_or_roles_from_group_users_success():
    group_id = TestEnv.group_id
    json_data = {"users": [f"{TestEnv.users1}", f"{TestEnv.users2}"]}
    response = client.patch(f'/groups/{group_id}/remove', json=json_data)
    assert response.status_code == 200


def test_remove_users_or_roles_from_group_roles_success():
    group_id = TestEnv.group_id
    json_data = {"roles": [f"{TestEnv.roles1}", f"{TestEnv.roles2}"]}
    response = client.patch(f'/groups/{group_id}/remove', json=json_data)
    assert response.status_code == 200


def test_remove_roles_from_a_group_group_id_not_found():
    group_id = TestEnv.not_exists_group_id
    json_data = {"roles": [f"{TestEnv.roles1}", f"{TestEnv.roles2}"]}
    response = client.patch(f'/groups/{group_id}/remove', json=json_data)
    json_response = response.json()
    assert response.status_code == 404
    assert json_response == {"detail": "Group not found"}


def test_remove_users_from_a_group_group_id_not_found():
    group_id = TestEnv.not_exists_group_id
    json_data = {"users": [f"{TestEnv.users1}", f"{TestEnv.users2}"]}
    response = client.patch(f'/groups/{group_id}/remove', json=json_data)
    json_response = response.json()
    assert response.status_code == 404
    assert json_response == {"detail": "Group not found"}


def test_remove_users_from_a_group_not_exist_user():
    group_id = TestEnv.group_id
    json_data = {"users": [f"{TestEnv.not_exist_user}"]}
    response = client.patch(f'/groups/{group_id}/remove', json=json_data)
    json_response = response.json()
    assert response.status_code == 404
    assert json_response == {"detail": "Users not exist"}


def test_remove_roles_from_a_group_not_exist_role():
    group_id = TestEnv.group_id
    json_data = {"roles": [f"{TestEnv.not_exist_role}"]}
    response = client.patch(f'/groups/{group_id}/remove', json=json_data)
    json_response = response.json()
    assert response.status_code == 404
    assert json_response == {"detail": "Roles not exist"}


def test_remove_users_and_roles_at_the_same_time_from_a_group():
    group_id = TestEnv.group_id
    json_data = {
        "users": [
            f"{TestEnv.users1}"
        ],
        "roles": [
            f"{TestEnv.roles1}"
        ]
    }
    response = client.patch(f'/groups/{group_id}/remove', json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['Neither users nor roles are set in body']


def test_remove_no_users_and_no_roles_request_error():
    group_id = TestEnv.group_id
    json_data = {}
    response = client.patch(f'/groups/{group_id}/remove', json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['Neither users nor roles are set in body']


def test_remove_users_and_roles_at_the_same_time_with_none_roles():
    group_id = TestEnv.group_id
    json_data = {
        "users": [
            f"{TestEnv.users1}"
        ],
        "roles": [
            ""
        ]
    }
    response = client.patch(f'/groups/{group_id}/remove', json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['Neither users nor roles are set in body']


def test_remove_users_and_roles_at_the_same_time_with_none_users():
    group_id = TestEnv.group_id
    json_data = {
        "users": [
            ""
        ],
        "roles": [
            f"{TestEnv.roles1}"
        ]
    }
    response = client.patch(f'/groups/{group_id}/remove', json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['Neither users nor roles are set in body']


def test_remove_users_or_roles_from_a_group_with_group_id_empty_request():
    group_id = ""
    json_data = {"users": [f"{TestEnv.users1}", f"{TestEnv.users2}"]}
    response = client.patch(f'/groups/{group_id}/remove', json=json_data)
    json_response = response.json()
    assert response.status_code == 404
    assert json_response == {"detail": "Not Found"}


def test_remove_users_from_group_group_id_non_uuid_format_request():
    group_id = TestEnv.group_id_non_uuid_format
    json_data = {"users": [f"{TestEnv.users1}", f"{TestEnv.users2}"]}
    response = client.patch(f'/groups/{group_id}/remove', json=json_data)
    json_response = response.json()
    assert response.status_code == 422
    assert [x["msg"] for x in json_response["detail"]] == ['value is not a valid uuid']
    assert [x["type"] for x in json_response["detail"]] == ['type_error.uuid']
