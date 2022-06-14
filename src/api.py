import os
import importlib

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import uvicorn
from business.providers.base import Provider
from business.providers import get_provider
from core import log

load_dotenv()

app = FastAPI()


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
    return {"message" :"ZeKoder security managment API"}



@app.post('/verify')
async def verify(token: str):
    """verify jwt token"""
    decoded = auth_provider.verify(token)
    return decoded

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
    uvicorn.run("api:app", host="localhost", port=int(os.environ.get('UVICORN_PORT', 8080)), reload=bool(os.environ.get('UVICORN_RELOAD', True)), debug=bool(os.environ.get('UVICORN_DEBUG', True)), workers=int(os.environ.get('UVICORN_WORKERS',1)))