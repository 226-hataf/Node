from fastapi import APIRouter, Depends, HTTPException, Security
from sqlalchemy.orm import Session
from config.db import get_db
from dotenv import load_dotenv
from business.models.schema_clients import ClientCreateSchema, ClientJWTSchema, ClientSchema
from src.business.models.dependencies import get_current_user
from core.types import ZKModel
from core import log, crud

load_dotenv()

router = APIRouter()

model = ZKModel(**{
    "name": 'client',
    "plural": 'clients',
    "permissions": {
        'read': ['zk-zeauth-read'],
        'list': ['zk-zeauth-list'],
        'create': ['zk-zeauth-create'],
        'update': ['zk-zeauth-update'],
        'delete': ['zk-zeauth-delete']
    }
})


# Create Client
@router.post('/', tags=[model.plural], status_code=201, response_model=ClientSchema, description="Create a Client")
async def create(client: ClientCreateSchema, db: Session = Depends(get_db),
                 user: str = Security(get_current_user, scopes=["clients-create"])):
    """
    TODO: To create a new client account the user must has role zekoder-zeauth-admin, we must add this !
    TODO: crud side is not done, add it when DB is ready
    TODO: DB table must be created for client
    """
    try:
        new_client = crud.create_new_client(db, client)
        return new_client
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="Unknown Error, Check the logs!")


# Auth using client account
@router.post('/auth', tags=[model.plural], status_code=201, response_model=ClientJWTSchema,
             description="To Auth using client account")
async def auth(client_auth: ClientSchema, db: Session = Depends(get_db)):
    """
    TODO: crud side is not done, add it when DB is ready
    """
    try:
        client_auth = crud.create_client_auth(db, client_auth)
        return client_auth
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="Unknown Error, Check the logs!")


@router.delete('/{client_id}', tags=[model.plural], status_code=202, description="Delete Client Account")
async def delete(client_id: str, db: Session = Depends(get_db),
                 user: str = Security(get_current_user, scopes=["clients-del"])):
    """
    TODO: crud side is not done, add it when DB is ready
    """
    try:
        crud.remove_client(db, client_id)
        return {"detail": f"Client: <{client_id}> deleted successfully !"}
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error, check the logs")
