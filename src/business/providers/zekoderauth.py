from sqlalchemy.exc import IntegrityError
from business.providers.base import *
from core import log, crud
from core.AES import AesStringCipher
AES_KEY = os.environ.get('AES_KEY')


class ProviderZekoderAuth(Provider):

    async def signup(self, user: UserRequest, db):
        log.info("signup in Zekoder Auth")
        try:
            aes = AesStringCipher(AES_KEY)
            encrypted_password = aes.encrypt_str(raw=user.password)
            log.info(f"encrypted_password {encrypted_password}")

            user_resp = crud.create_user(db, user={
                "email": user.email,
                "user_name": user.username,
                "password": encrypted_password,
                "verified": False,
                "user_status": True,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "phone": user.phone,
            })
            log.info(f"user {user_resp.email} created successfully.")
            return User(
                id=user_resp.id,
                email=user_resp.email,
                user_name=user_resp.user_name,
                verified=user_resp.verified,
                user_status=user_resp.user_status,
                first_name=user_resp.first_name,
                last_name=user_resp.last_name,
                full_name=user_resp.first_name + ' ' + user_resp.last_name if user_resp.last_name else '',
                phone=user_resp.phone,
                last_login_at=user_resp.last_login_at,
                created_at=user_resp.created_on,
                update_at=user_resp.updated_on
            )

        except IntegrityError as err:
            log.error(err)
            raise DuplicateEmailError() from err
        except Exception as err:
            log.debug(err)
            raise err
