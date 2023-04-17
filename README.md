1. Python version is **3.10.6**
2. Auth type should be **FUSIONAUTH**. 
3. Install Redis.

**Environemnt variables**

| Environment variables        |                                           Value                                           |
|------------------------------|:-----------------------------------------------------------------------------------------:| 
| AUTH_PROVIDER                |                                        FUSIONAUTH                                         |
| FUSIONAUTH_APIKEY            |                                           ****                                            |
| applicationId                |                                           ****                                            |
| ZEAUTH_URL               |                             https://accounts.dev.zekoder.net                              |
 RESET_PASSWORD_URL            |                                https://zekoder.netlify.app                            |
 RESEND_CONFIRMATION_EMAIL_URL |                  https://zekoder.netlify.app                                |
SEND_NOTIFICATION_EMAIL_URL    |                  https://zenotify-service.zekoder.zestudio.zekoder.zekoder.net            |
ZENOTIFY_BASE_URL    |                  http://zenotify.zekoder.zestudio.zekoder.zekoder.net            |
NOTIFICATION_PROVIDER    |                  0f8c65d3-e4c4-4a89-b638-c31a8262e0fb            |
| FRONTEND_REDIRECT_URL        |                    https://zekoder.netlify.app/auth/verifysociallogin                     |
| GOOGLE_REDIRECT_URL          |                                           ****                                            |
| TWITTER_REDIRECT_URL         |                                           ****                                            |
| FACEBOOK_REDIRECT_URL        |                                           ****                                            |
| GOOGLE_APP_ID                |                                           ****                                            |
| GOOGLE_CLIENT_SECRET         |                                           ****                                            |
| TWITTER_CONSUMER_KEY         |                                           ****                                            |
| TWITTER_CONSUMER_SECRET      |                                           ****                                            |
| FACEBOOK_APP_ID              |                                           ****                                            |
| FACEBOOK_CLIENT_SECRET       |                                           ****                                            |
| identityProviderIdGoogle     |                           82339786-3dff-42a6-aac6-1f1ceecb6c46                            |
| identityProviderIdFacebook   |                           56abdcc7-8bd9-4321-9621-4e9bbebae494                            |
| identityProviderIdTwitter    |                           45bb233c-0901-4236-b5ca-ac46e2e0a5a5                            |
| JWT_SECRET_KEY               |                                           ****                                            |
| REDIS_KEY_PREFIX             |                                           ****                                            |
| REDIS_CLIENT_KEY_PREFIX             |                                           ****                                            |
| DATA_ENCRYPTION_PUB_KEY      |                                           ****                                            |
| DATA_ENCRYPTION_PRIV_KEY     |                                           ****                                            |
| ACCESS_TOKEN_EXPIRY_MINUTES  |                                           ****                                            |
 REFRESH_TOKEN_EXPIRY_MINUTES |                                           ****                                            |
REFRESH_CLIENT_TOKEN_EXPIRY_MINUTES |                                           ****                                            |
CLIENT_TOKEN_EXPIRY_MINUTES |                                           ****                                            |
 DIGITS                       |                                             1                                             |
| LENGTH                       |                                             8                                             |
| REALM_NAME                   |                                        zeauth-dev                                         |
| SECRET                       |                                           ****                                            |
| SPECIAL_CHARACTERS           |                                             1                                             |
| UPPERCASE                    |                                             1                                             |
| MAIL_SERVER                  |                                         ........                                          |
| MAIL_PORT                    |                                            587                                            |
| MAIL_USERNAME                |                                         ........                                          |
| MAIL_PASSWORD                |                                           *****                                           |
| MAIL_FROM                    |                                    noreply@zekoder.net                                    |
| REDIS_PORT                   |                                        redis port                                         |
| REDIS_HOST                   |                                        redis host                                         |
| UVICORN_PORT                 |                                           8080                                            |
| UVICORN_WORKERS              |                                             1                                             |
| UVICORN_DEBUG                |                                           True                                            |
| UVICORN_RELOAD               |                                           True                                            |
| Command for Deploy           | gcloud run deploy zkdoer-zeauth-dev --project jsc-chatbot --region us-central1 --source . |



Must be enabled for Cloud run

- Cloud build
- Cloud run
- Cloud Run Admin API