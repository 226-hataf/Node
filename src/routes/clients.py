from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from config.db import get_db
from dotenv import load_dotenv
from business.models.schema_clients import ClientCreateSchema, ClientJWTSchema, ClientSchema, UUIDCheckForClientIdSchema
from core.crud import get_client_by_uuid_and_secret, get_client_by_uuid, get_groups_by_name_list, \
    check_client_exists_with_email
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
async def create(client: ClientCreateSchema, db: Session = Depends(get_db)):
    """
    TODO: To create a new client account the user must has role zekoder-zeauth-admin, we must add this !
    """
    client_exist = check_client_exists_with_email(db, client.email)
    if client_exist:
        raise HTTPException(status_code=422, detail="Client already exist !")

    groups_list_check = get_groups_by_name_list(db, client.groups)
    if (len(groups_list_check) != len(client.groups)) and not groups_list_check == []:
        raise HTTPException(status_code=422, detail="Check group's name, "
                                                    "only available group names are required, "
                                                    "do not repeat group names")
    if not groups_list_check:
        raise HTTPException(status_code=404, detail="Group/s not found !")
    try:
        new_client = crud.create_new_client(db, client)
        return new_client
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="Unknown Error, Check the logs!")


# Auth using client account
@router.post('/auth', tags=[model.plural], status_code=201,
             response_model=ClientJWTSchema, description="Client Auth")
async def auth(client_auth: ClientSchema, db: Session = Depends(get_db)):
    """Client auth"""
    client_exists = get_client_by_uuid_and_secret(db, client_auth.client_id, client_auth.client_secret)
    if client_exists is None:
        raise HTTPException(status_code=404, detail="Client not exist")
    try:
        return crud.create_client_auth(db, client_auth)
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error, check the logs")


@router.delete('/{client_id}', tags=[model.plural], status_code=202, description="Delete Client Account")
async def delete(client_id: UUIDCheckForClientIdSchema = Depends(UUIDCheckForClientIdSchema), db: Session = Depends(get_db)):
    """Delete current Client"""
    delete_client = get_client_by_uuid(db, client_id)
    if not delete_client:
        raise HTTPException(status_code=404, detail="Client Id not found")
    try:
        deleted_id = crud.remove_client(db, client_id)
        return {"detail": f"Client: <{deleted_id}> deleted successfully !"}
    except Exception as e:
        log.error(e)
        raise HTTPException(status_code=500, detail="unknown error, check the logs")

