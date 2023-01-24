from dotenv import load_dotenv
load_dotenv()
from config.db import get_db
import os
import importlib
from fastapi import HTTPException
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from business.models.users import UserLoginSchema, ResendConfirmationEmailSchema, ResetPasswordSchema, \
    ResetPasswordVerifySchema, ConfirmationEmailVerifySchema, EncryptDecryptStrSchema, DecryptedContentSchema, \
    EncryptedContentSchema
import uvicorn
from business.providers.base import *
from business.providers import get_provider
from business import User
from core import log
from fastapi.responses import JSONResponse
from fastapi import Depends
from sqlalchemy.orm import Session


metadata = [
    {
        "name": "users",
        "description": "Endpoints where **Users** operations are made.",
    },
    {
        "name": "default",
        "description": "Endpoints where **Authentication/Authorization** operations are made.",
    },
    {
        "name": "broker",
        "description": "Endpoints where **Social Login** operations are made. "
                       "You can not use this endpoints directly from here !",
    },
    {
        "name": "groups",
        "description": "Endpoints where **Group** definitions are made, "
                       "you can also assign **multiple roles or users** for a specific group",
    },
    {
        "name": "roles",
        "description": "Endpoints where **Role** definitions are made",
    },
{
        "name": "clients",
        "description": "Endpoints where **Client** definitions are made",
    },
]

app = FastAPI(title="ZeAuth Security Module", openapi_tags=metadata)

origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
)

auth_provider: Provider = get_provider()


@app.get('/')
async def root():
    return {"message": "ZeKoder Security Management API"}


@app.post('/signup', status_code=201, response_model=User, response_model_exclude={"password"})
def signup(user: UserRequest, db: Session = Depends(get_db)):
    try:
        signed_up_user = auth_provider.signup(user=user, db=db)
        return signed_up_user.dict()
    except PasswordPolicyError as e:
        log.debug(e)
        raise HTTPException(status_code=403, detail=f"Password Policy not met.")
    except DuplicateEmailError as e:
        log.debug(e)
        raise HTTPException(status_code=403, detail=f"'{user.email}' email is already linked to an account")
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail='unknown error. check the logs')


@app.post("/login")
async def user_login(user_info: UserLoginSchema, db: Session = Depends(get_db)):
    try:
        return auth_provider.login(user_info, db=db)
    except InvalidCredentialsError as e:
        log.error(e)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "username or password is not matching our records")
    except UserNotVerifiedError as err:
        log.error(err)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user is not verified!")
    except Exception as err:
        log.error(err)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Internal server error') from err


@app.post("/resend_confirmation_email")
async def resend_confirmation_email(user_info: ResendConfirmationEmailSchema, db: Session = Depends(get_db)):
    try:
        return await auth_provider.resend_confirmation_email(db, user_info)
    except UserNotFoundError as err:
        log.error(err)
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(err)) from err
    except Exception as err:
        log.error(err)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Internal server error') from err


@app.post("/verify_email")
def verify_email(token: ConfirmationEmailVerifySchema, db: Session = Depends(get_db)):
    try:
        return auth_provider.verify_email(db, token)
    except UserNotFoundError as err:
        log.error(err)
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(err)) from err
    except IncorrectResetKeyError as err:
        log.error(err)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(err)) from err
    except Exception as err:
        log.error(err)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Internal server error') from err


@app.post("/reset-password")
async def reset_password(user_info: ResetPasswordSchema, db: Session = Depends(get_db)):
    try:
        response = await auth_provider.reset_password(user_info, db)
        if response:
            return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "email has been sent"})
    except UserNotFoundError as err:
        log.error(err)
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(err)) from err
    except NotExistingResourceError as err:
        log.error(err)
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, str(err)) from err
    except Exception as err:
        log.error(f'Error reset password: {type(err)} - {str(err)}')
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Internal server error') from err


@app.post("/reset-password/verify")
def reset_password_verify(reset_pass: ResetPasswordVerifySchema, db: Session = Depends(get_db)):
    try:
        if _ := auth_provider.reset_password_verify(reset_pass, db):
            return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Password has been reset."})
    except IncorrectResetKeyError as err:
        log.error(err)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(err)) from err
    except NotExistingResourceError as err:
        log.error(err)
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, str(err)) from err
    except Exception as err:
        log.error(err)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Internal server error') from err


@app.post("/encrypt_str", response_model=EncryptDecryptStrSchema)
def encrypt_str(str_for_enc: str):
    try:
        return auth_provider.encrypt_str(str_for_enc)
    except Exception as err:
        log.error(err)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Internal server error') from err


@app.post("/decrypt_str", response_model=EncryptDecryptStrSchema)
def decrypt_str(str_for_dec: str):
    try:
        return auth_provider.decrypt_str(str_for_dec)
    except Exception as err:
        log.error(err)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Internal server error') from err


@app.get("/key", status_code=200, description="The asymmetric public key")
async def get_pub_key():
    """Get public key"""
    try:
        return auth_provider.get_pub_encrypt_key()
    except Exception as err:
        log.error(err)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Internal server error') from err


@app.post("/keys/decrypt", status_code=200, response_model=DecryptedContentSchema, description="Encrypt to decrypt")
def encrypt_to_decrypt(encrypted: EncryptedContentSchema):
    """Decrypts encrypted content"""
    try:
        return auth_provider.enc_to_decrypt(encrypted)
    except Exception as err:
        log.error(err)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Internal server error') from err


@app.post('/verify', description="Verify users and clients jwt token")
async def verify(token: str):
    """verify users and clients jwt token"""
    try:
        decoded = auth_provider.verify(token)
        return decoded
    except InvalidTokenError as e:
        log.error(e)
        raise HTTPException(401, "failed token verification")


@app.post('/refresh_token')
async def refresh_token(token: str):
    """
    Generates refresh tokens
    :param token(access_token):
    :return: refresh_token
    """
    try:
        result = auth_provider.refreshtoken(token)
        return result
    except InvalidTokenError as e:
        log.error(e)
        raise HTTPException(status_code=403, detail=f"Your refresh_token cannot be created !")


# load all routes dynamically
for module in os.listdir(f"{os.path.dirname(__file__)}/routes"):
    if module == '__init__.py' or module[-3:] != '.py':
        continue
    module_name = module[:-3]
    log.debug(f"importing <{module_name}> endpoints")

    try:
        pkg = importlib.import_module(f"routes.{module[:-3]}")
        app.include_router(pkg.router, prefix=f"/{module_name}")
    except Exception as e:
        log.error(f"failed importing <{module_name}> endpoints")
        print(e)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

if __name__ == "__main__":
    uvicorn.run("api:app", host="localhost", port=int(os.environ.get('UVICORN_PORT', 8080)),
                reload=bool(os.environ.get('UVICORN_RELOAD', True)), debug=bool(os.environ.get('UVICORN_DEBUG', True)),
                workers=int(os.environ.get('UVICORN_WORKERS', 1)))
