from sqlalchemy.exc import IntegrityError
from business.providers.base import *
from core import log, crud
from core.AES import AesStringCipher

AES_KEY = os.environ.get('AES_KEY')


class ProviderZekoderAuth(Provider):
    def __init__(self) -> None:
        self.aes = AesStringCipher(AES_KEY)
        super().__init__()

    def _cast_user(self, user):
        return User(
            id=str(user.id),
            email=user.email,
            user_name=user.user_name,
            verified=user.verified,
            user_status=user.user_status,
            first_name=user.first_name,
            last_name=user.last_name,
            full_name=user.first_name + ' ' + user.last_name if user.last_name else '',
            phone=user.phone,
            last_login_at=user.last_login_at,
            created_at=user.created_on,
            update_at=user.updated_on
        )

    async def signup(self, user: UserRequest, db):
        log.info("signup in Zekoder Auth")
        try:
            encrypted_password = self.aes.encrypt_str(raw=user.password)
            log.info(f"encrypted_password {encrypted_password}")
            log.info(type(encrypted_password))

            user_resp = crud.create_user(db, user={
                "email": user.email,
                "user_name": user.username,
                "password": str(encrypted_password),
                "verified": False,
                "user_status": True,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "phone": user.phone,
            })
            log.info(user_resp.id)
            log.info(f"user {user_resp.email} created successfully.")
            return self._cast_user(user_resp)

        except IntegrityError as err:
            log.error(err)
            raise DuplicateEmailError() from err
        except Exception as err:
            log.debug(err)
            raise err

    def login(self, user_info, db):
        try:
            encrypted_password = self.aes.encrypt_str(raw=user_info.password)

            if response := crud.get_user_by_email(db=db, email=user_info.email, password=str(encrypted_password)):
                return self._cast_user(response)
            else:
                raise InvalidCredentialsError('failed login')
        except Exception as err:
            log.error(err)
            raise err

