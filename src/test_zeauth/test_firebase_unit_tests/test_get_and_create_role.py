from src.business.providers.firebase import ProviderFirebase
from src.test_zeauth.firebase_fixtures import mocked_firebase_init_app, mocked_firestore_client, \
    mocked_zeauth_bootstrap


def test_get_role_success(mocked_firebase_init_app, mocked_firestore_client, mocked_zeauth_bootstrap):
    ProviderFirebase.db = None
    firebase = ProviderFirebase()
    update_user = firebase.get_role(name="abdul")
    assert update_user.name == mocked_firestore_client.client().collection().document().get().to_dict().name


def test_create_role_success(mocked_firebase_init_app, mocked_firestore_client, mocked_zeauth_bootstrap):
    ProviderFirebase.db = None
    firebase = ProviderFirebase()
    update_user = firebase.create_role(name="abdul", permissions=["test"], description="test")
    assert update_user == ["test"]
