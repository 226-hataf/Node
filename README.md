1. Python version is **3.10.6**
2. Auth type should be **FUSIONAUTH**. 
3. Install Redis.

**Environemnt variables**

| Environment variables |                                           Value                                           |
|-----------------------|:-----------------------------------------------------------------------------------------:| 
| AUTH_PROVIDER         |                                        FUSIONAUTH                                         |
| FUSIONAUTH_APIKEY     |                                           ****                                            |
| applicationId         |                                           ****                                            |
 FUSIONAUTH_URL        |                             https://accounts.dev.zekoder.net                              |
GOOGLE_REDIRECT_URL    |                                           ****                                            |
GOOGLE_APP_ID        |                                           ****                                            |
identityProviderIdGoogle |                           82339786-3dff-42a6-aac6-1f1ceecb6c46                            |
| CLIENT_ID             |                                          account                                          |
| DIGITS                |                                             1                                             |
| LENGTH                |                                             8                                             |
| REALM_NAME            |                                        zeauth-dev                                         |
| SECRET                |                                           ****                                            |
| SPECIAL_CHARACTERS    |                                             1                                             |
| UPPERCASE             |                                             1                                             |
| MAIL_SERVER           |                                         ........                                          |
| MAIL_PORT             |                                            587                                            |
| MAIL_USERNAME         |                                         ........                                          |
| MAIL_PASSWORD         |                                           *****                                           |
| MAIL_FROM             |                                    noreply@zekoder.net                                    |
| REDIS_PORT            |                                        redis port                                         |
| REDIS_HOST            |                                        redis host                                         |
| UVICORN_PORT          |                                           8080                                            |
| UVICORN_WORKERS       |                                             1                                             |
| UVICORN_DEBUG         |                                           True                                            |
| UVICORN_RELOAD        |                                           True                                            |
| Command for Deploy    | gcloud run deploy zkdoer-zeauth-dev --project jsc-chatbot --region us-central1 --source . |



Must be enabled for Cloud run

- Cloud build
- Cloud run
- Cloud Run Admin API