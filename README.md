​
Environemnt variables:
​

AUTH_TYPE: Valid values [firebase, keycloak]

AUTH_PROVIDER: firebase
GOOGLE_APPLICATIONS_CREDENTIALS: C:/Users/ezgis/Desktop/zeauth/zeauth/jsc-chatbot-sa.json

AUTH_PROVIDER: keycloak
CLIENT_ID=account
DIGITS=1
KEYCLOAK_URL=https://accounts.dev.zekoder.com
LENGTH=8
REALM_NAME=zeauth-dev
SECRET=...
SPECIAL_CHARACTERS=1
UPPERCASE=1

UVICORN_PORT: 8080
UVICORN_WORKERS: 1
UVICORN_DEBUG: True
UVICORN_RELOAD: True 
gcloud run deploy zkdoer-zeauth-dev --project jsc-chatbot --region us-central1 --source .
