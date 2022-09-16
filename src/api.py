import os
import importlib
from fastapi import HTTPException
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from business.models.users import UserLoginSchema, ResendConfirmationEmailSchema, ResetPasswordSchema, ResetPasswordVerifySchema
from dotenv import load_dotenv
import uvicorn
from business.providers.base import *
from business.providers import get_provider
from business import User
from core import log
from fastapi.responses import JSONResponse

load_dotenv()

app = FastAPI(title="ZeAuth")

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
    return {"message": "ZeKoder security managment API"}


@app.post('/signup', status_code=201, response_model=User, response_model_exclude={"password"})
async def signup(user: User):
    try:
        signed_up_user = await auth_provider.signup(user=user)
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
async def user_login(user_info: UserLoginSchema):
    try:
        return auth_provider.login(user_info)
    except InvalidCredentialsError as e:
        log.error(e)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "username or password is not matching our records")
    except CustomKeycloakPostError as err:
        log.error(err)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'Account not Verified!') from err
    except Exception as err:
        log.error(err)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Internal server error') from err


@app.post("/resend_confirmation_email")
async def resend_confirmation_email(user_info: ResendConfirmationEmailSchema):
    try:
        return await auth_provider.resend_confirmation_email(user_info)
    except UserNotFoundError as err:
        log.error(err)
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(err)) from err
    except Exception as err:
        log.error(err)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Internal server error') from err


@app.post("/reset-password")
async def reset_password(user_info: ResetPasswordSchema):
    try:
        response = await auth_provider.reset_password(user_info)
        if response:
            return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "email has been sent"})

    except UserNotFoundError as err:
        log.error(err)
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(err)) from err
    except NotExisitngResourceError as err:
        log.error(err)
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, str(err)) from err
    except Exception as err:
        log.error(f'Error reset password: {type(err)} - {str(err)}')
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Internal server error') from err


@app.post("/reset-password/verify")
def reset_password_verify(reset_pass: ResetPasswordVerifySchema):
    try:
        response = auth_provider.reset_password_verify(reset_pass)
        if response:
            return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Password has been reset."})

    except CustomKeycloakPutError as err:
        log.error(err)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(err)) from err
    except IncorrectResetKeyError as err:
        log.error(err)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(err))
    except NotExisitngResourceError as err:
        log.error(err)
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, str(err)) from err
    except Exception as err:
        log.error(err)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Internal server error') from err


@app.post('/verify')
async def verify(token: str):
    """verify jwt token"""
    try:
        decoded = auth_provider.verify(token)
        return decoded
    except InvalidTokenError as e:
        log.error(e)
        raise HTTPException(401, "failed token verification")


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
