from src.business.providers.firebase import ProviderFirebase
from src.test_zeauth.firebase_fixtures import mocked_firebase_init_app, mocked_firestore_client, \
    mocked_firebase_auth_get_user, mocked_zeauth_bootstrap, mocked_firebase_auth_delete_user


def test_delete_user_success(mocked_firebase_init_app, mocked_firestore_client, mocked_firebase_auth_get_user,
                             mocked_zeauth_bootstrap, mocked_firebase_auth_delete_user):
    firebase = ProviderFirebase()

    delete_user = firebase.delete_user(user_id="2343543543432")
    assert delete_user.uid == "2343543543432"
