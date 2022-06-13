from typing import Optional

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer

from business.providers import get_provider
from business.providers.base import Provider

auth_schema = HTTPBearer()
auth_provider: Provider = get_provider()

class CommonDependencies():
    def __init__(self, page: Optional[str] = 1, size: Optional[int] = 20):
        self.page = page
        self.size = size


class ProtectedMethod:
    def __init__(self, token: str = Depends(auth_schema)):
        self.credentials = token.credentials

    def auth(self, model_required_permissions):
        verified = auth_provider.verify(self.credentials)
        for permission in model_required_permissions:
            if permission in verified['zk-zeauth-permissions']:
                return
        raise HTTPException(403, "user not authorized to do this action")



import pyrebase

#Configure and Connext to Firebase

firebaseConfig = {'apiKey': "AIzaSyDm2HeGl3bApix5KsbhI8NOjdwXkhNTaJM",
                  'authDomain': "trialauth-7eea1.firebaseapp.com",
                  'databaseURL': "https://trialauth-7eea1.firebaseio.com",
                  'projectId': "trialauth-7eea1",
                  'storageBucket': "trialauth-7eea1.appspot.com",
                  'messagingSenderId': "441088628124",
                  'appId': "1:441088628124:web:59f51ba5b6a475032f2459",
                  'measurementId': "G-TNR2V3DEQD"}

firebase=pyrebase.initialize_app(firebaseConfig)
auth=firebase.auth()

#Login function

def login():
    print("Log in...")
    email=input("Enter email: ")
    password=input("Enter password: ")
    try:
        login = auth.sign_in_with_email_and_password(email, password)
        print("Successfully logged in!")
        # print(auth.get_account_info(login['idToken']))
       # email = auth.get_account_info(login['idToken'])['users'][0]['email']
       # print(email)
    except:
        print("Invalid email or password")
    return

#Signup Function

def signup():
    print("Sign up...")
    email = input("Enter email: ")
    password=input("Enter password: ")
    try:
        user = auth.create_user_with_email_and_password(email, password)
        ask=input("Do you want to login?[y/n]")
        if ask=='y':
            login()
    except: 
        print("Email already exists")
    return

#Main

ans=input("Are you a new user?[y/n]")

if ans == 'n':
    login()
elif ans == 'y':
    signup()
