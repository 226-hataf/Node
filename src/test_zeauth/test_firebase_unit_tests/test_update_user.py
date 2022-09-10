from src.business.models.users import User
from src.business.providers.firebase import ProviderFirebase
from src.test_zeauth.firebase_fixtures import mocked_firebase_init_app, mocked_firestore_client, \
    mocked_firebase_auth_get_user, mocked_zeauth_bootstrap, mocked_firebase_auth_update_user


def test_update_user_success(mocked_firebase_init_app, mocked_firestore_client, mocked_firebase_auth_get_user,
                             mocked_zeauth_bootstrap, mocked_firebase_auth_update_user):
    firebase = ProviderFirebase()
    user = User(email="abdul@gmail.com", phone="2344534554", password="12334", full_name="Abdul Rehman", avatar_url="")
    update_user = firebase.update_user(user_id="2343543543432", user=user)
    assert update_user.uid == "2343543543432"
