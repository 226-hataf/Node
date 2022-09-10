from src.business.providers.firebase import ProviderFirebase
from src.test_zeauth.firebase_fixtures import mocked_firebase_init_app, mocked_firestore_client, \
    mocked_firebase_auth_verify_id_token, mocked_zeauth_bootstrap


def test_verify_success(mocked_firebase_init_app, mocked_firestore_client, mocked_firebase_auth_verify_id_token,
                        mocked_zeauth_bootstrap):
    firebase = ProviderFirebase()

    delete_user = firebase.verify(token="2343543543432")
    assert delete_user.uid == "2343543543432"
