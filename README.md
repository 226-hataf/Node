​
Environemnt variables:
​

AUTH_TYPE: Valid values [firebase, keycloak]

AUTH_PROVIDER: firebase
GOOGLE_APPLICATIONS_CREDENTIALS: C:/Users/ezgis/Desktop/zeauth/zeauth/jsc-chatbot-sa.json

```
AUTH_PROVIDER: keycloak
CLIENT_ID=account
DIGITS=1
KEYCLOAK_URL=https://accounts.dev.zekoder.com
LENGTH=8
REALM_NAME=zeauth-dev
SECRET=...
SPECIAL_CHARACTERS=1
UPPERCASE=1
```

```
UVICORN_PORT: 8080
UVICORN_WORKERS: 1
UVICORN_DEBUG: True
UVICORN_RELOAD: True 
gcloud run deploy zkdoer-zeauth-dev --project jsc-chatbot --region us-central1 --source .
```

Email server configuration
```
MAIL_SERVER: -------
MAIL_PORT: 587
MAIL_USERNAME: ------
MAIL_PASSWORD: ****************
MAIL_FROM: noreply@zekoder.net
```

Redis configurations
```
REDIS_PORT: 6379
REDIS_HOST: localhost
REDIS_PASSWORD: 
```


Must be enabled for Cloud run

- Cloud build
- Cloud run
- Cloud Run Admin API