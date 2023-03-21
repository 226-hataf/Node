import os
from fastapi import APIRouter, Depends, HTTPException, Security
from sqlalchemy.orm import Session
import uuid
from business.models.users import UserResponseModel
from business.providers.base import CreateNotificationError, TemplateNotificationError
from config.db import get_db
from dotenv import load_dotenv
from business.models.dependencies import get_current_user
from business.models.schema_clients import ClientCreateSchema, ClientJWTSchema, ClientSchema, UUIDCheckForClientIdSchema
from core.crud import get_client_by_uuid_and_secret, get_client_by_uuid, get_groups_by_name_list, \
    check_client_exists_with_email, create_template_for_notification, create_notification, send_notification_email
from core.types import ZKModel
from core import log, crud
from redis_service.redis_service import set_redis

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
RESEND_CONFIRMATION_EMAIL_URL = os.environ.get('RESEND_CONFIRMATION_EMAIL_URL')

# Create Client
@router.post('/', tags=[model.plural], status_code=201, response_model=ClientSchema, description="Create a Client")
async def create(client: ClientCreateSchema, db: Session = Depends(get_db),
                 user: UserResponseModel = Security(get_current_user, scopes=["clients-create"])):
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
        # Now send notification signup email to client's email
        if new_client:
            activation_email_key = hash(uuid.uuid4().hex)
            set_redis(activation_email_key, client.email)
            # we will use RESEND_CONFIRMATION_EMAIL_URL to send activation_email. These links are same
            activation_email_url = f"{RESEND_CONFIRMATION_EMAIL_URL}/auth/confirm-email?token={activation_email_key}"
            template = crud.get_template_by_name('signup_temp_bootstrap')
            new_template = ''.join(template).replace("{{first_name}}", client.name) \
                .replace("{{verification_link}}", activation_email_url)
            template_name = 'signup_with_activation_email'
            title = "Activation Email"
            body = new_template
            # First; create a new template from Bootstrapped main signup template
            # Because every signup has to get a new template for specific signup client
            response = create_template_for_notification(body, template_name, title)
            if response.json()['id']:
                # Second; Create notification
                template = response.json()['id']
                recipients = client.email
                notification_response = create_notification(recipients, template)
                if notification_response.json()['id']:
                    # And; send activation email link to client's email !
                    notification_id = notification_response.json()['id']
                    send_notification_email(db, client.email,
                                            status='signup_with_activation_email',
                                            notificationid=notification_id)
                else:
                    raise CreateNotificationError
            else:
                raise TemplateNotificationError
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
async def delete(client_id: UUIDCheckForClientIdSchema = Depends(UUIDCheckForClientIdSchema),
                 db: Session = Depends(get_db),
                 user: UserResponseModel = Security(get_current_user, scopes=["clients-del"])):
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
