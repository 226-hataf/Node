from src.business.models.users import UserLoginSchema, User
from src.business.providers.firebase import ProviderFirebase
from src.test_zeauth.firebase_fixtures import mocked_firebase_init_app, mocked_firestore_client, \
    mocked_auth_create_user, mocked_zeauth_bootstrap, mocked_login_request_post


def test_signup_success(mocked_firebase_init_app, mocked_firestore_client, mocked_auth_create_user,
                        mocked_zeauth_bootstrap):
    firebase = ProviderFirebase()

    signup_schema = User(email="abdul@gmail.com", username="abdul@gmail.com", first_name="Abdul", last_name="Rehman",
                         full_name="Abdul Rehman")
    assert signup_schema.email == "abdul@gmail.com"
    assert signup_schema.username == "abdul@gmail.com"
    assert signup_schema.first_name == "Abdul"
    assert signup_schema.last_name == "Rehman"

    signup = firebase.signup(signup_schema)
    assert signup.email == "abdul@gmail.com"
    assert signup.username == "abdul@gmail.com"
    assert signup.first_name == "Abdul"
    assert signup.last_name == "Rehman"


def test_login_success(mocked_firebase_init_app, mocked_firestore_client, mocked_login_request_post):
    firebase = ProviderFirebase()

    login_schema = UserLoginSchema(email="abdul@gmail.com", password="test123")
    assert login_schema.email == "abdul@gmail.com"
    assert login_schema.password == "test123"

    logged_in = firebase.login(login_schema)

    assert logged_in.user.id == '2334423423'
    assert logged_in.user.email == 'abdul@gmail.com'
