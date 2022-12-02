@router.get('/google/callback', tags=[model.name])
async def call_back_google(request: Request):
    code = request.query_params['code']
    google_client_id = os.environ.get('GOOGLE_APP_ID')
    client_secret = os.environ.get('GOOGLE_CLIENT_SECRET')
    google_redirect_uri = os.environ.get('GOOGLE_REDIRECT_URL')
    aud = os.environ.get('GOOGLE_APP_ID')
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    data = f'code={code}' \
           f'&client_id={google_client_id}' \
           f'&client_secret={client_secret}' \
           f'&redirect_uri={google_redirect_uri}' \
           f'&grant_type=authorization_code'

    response = requests.post('https://oauth2.googleapis.com/token', headers=headers, data=data)
    data = response.json()
    access_token = data['id_token']
    data_jwt = jwt.decode(access_token, audience=aud, options={"verify_signature": False})
    return data_jwt