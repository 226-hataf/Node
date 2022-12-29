from fastapi.testclient import TestClient
from api import app

client = TestClient(app)


class TestEnv:

    user_id = "2f3c92fa-86a5-11ed-8a13-634c2704cdf0"
    not_exists_user = "8077c4ab-5fe7-4e14-b85d-e0f49b41cf5d"
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


def test_user_to_group_again():
    user_id = TestEnv.user_id
    group_id = TestEnv.group_id
    response = client.patch(f"/users/{user_id}/group/{group_id}")
    json_response = response.json()
    assert response.status_code == 403
    assert json_response == {"detail": "Available users are already in the group"}


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
