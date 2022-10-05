from src.business.providers.firebase import ProviderFirebase
from src.test_zeauth.firebase_fixtures import mocked_firebase_init_app, mocked_firestore_client, \
    mocked_firebase_auth_list_users, mocked_zeauth_bootstrap


def test_list_users_success(mocked_firebase_init_app, mocked_firestore_client, mocked_firebase_auth_list_users,
                            mocked_zeauth_bootstrap):
    firebase = ProviderFirebase()

    list_users, next_page_token, max_results = firebase.list_users(page_size=3, page=3)
    user = list_users[0]
    assert user.id == "2343543543432"
    assert user.email == "abdul@gmail.com"
    assert user.verified is True
    assert user.created_at == "10-10-2022"
