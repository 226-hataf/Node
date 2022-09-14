from fastapi_mail import FastMail, MessageSchema
from config.mail_config import conf


async def send_email(recipients: list, subject: str, body: str):
    message = MessageSchema(
        subject=subject,
        recipients=recipients,
        body=body,
        subtype="html"
    )

    fm = FastMail(conf)
    await fm.send_message(message)
