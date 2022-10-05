from src.business.providers.firebase import ProviderFirebase
from src.test_zeauth.firebase_fixtures import mocked_firebase_init_app, mocked_firestore_client, \
    mocked_firebase_auth_get_user, mocked_zeauth_bootstrap


def test_get_user_success(mocked_firebase_init_app, mocked_firestore_client, mocked_firebase_auth_get_user,
                            mocked_zeauth_bootstrap):
    firebase = ProviderFirebase()

    get_user = firebase.get_user(user_id="2343543543432")
    assert get_user.id == "2343543543432"
    assert get_user.email == "abdul@gmail.com"
    assert get_user.verified is True
    assert get_user.created_at == "10-10-2022"
