from src.business.providers.firebase import ProviderFirebase
from src.test_zeauth.firebase_fixtures import mocked_firebase_init_app, mocked_firestore_client, \
    mocked_firebase_auth_get_user, mocked_firebase_auth_update_user, mocked_firebase_auth_get_user_error, \
    mocked_zeauth_bootstrap
import pytest


def test_user_active_on_success(mocked_firebase_init_app, mocked_firestore_client, mocked_firebase_auth_get_user,
                                mocked_firebase_auth_update_user, mocked_zeauth_bootstrap):
    firebase = ProviderFirebase()

    user_active_on = firebase.user_active_on(user_id="2343543543432")

    assert user_active_on.uid == '2343543543432'


def test_user_active_on_fail(mocked_firebase_init_app, mocked_firestore_client, mocked_firebase_auth_get_user_error):
    firebase = ProviderFirebase()

    with pytest.raises(Exception) as user_active_on_fail:
        firebase.user_active_on(user_id="2343543543432")
    assert str(user_active_on_fail.value) == "attempt to activate not existing user"


def test_user_active_off_success(mocked_firebase_init_app, mocked_firestore_client, mocked_firebase_auth_get_user,
                                mocked_firebase_auth_update_user, mocked_zeauth_bootstrap):
    firebase = ProviderFirebase()

    user_active_off = firebase.user_active_off(user_id="2343543543432")

    assert user_active_off.uid == '2343543543432'


def test_user_active_off_fail(mocked_firebase_init_app, mocked_firestore_client, mocked_firebase_auth_get_user_error):
    firebase = ProviderFirebase()

    with pytest.raises(Exception) as user_active_off_fail:
        firebase.user_active_off(user_id="2343543543432")
    assert str(user_active_off_fail.value) == "attempt to deactivate not existing user"