from logging import currentframe
from os import access, stat
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, EmailStr
from typing import List
from fastapi_jwt_auth import AuthJWT
from pydantic.networks import url_regex
from starlette.status import HTTP_401_UNAUTHORIZED
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()


class Settings(BaseModel):
    authjwt_secret_key: str = 'e8ae5c5d5cd7f0f1bec2303ad04a7c80f09f759d480a7a5faff5a6bbaa4078d0'


@AuthJWT.load_config
def get_config():
    return Settings()


class User(BaseModel):
    name: str
    email: EmailStr
    password: str

    class Config:
        schema_extra = {
            "example": {
                "name": "john doe",
                "email": "johndoe@gmail.com",
                "password": "password"
            }
        }


class UserLogin(BaseModel):
    email: EmailStr
    password: str

    class Config:
        schema_extra = {
            "example": {
                "name": "johndoe@mail.com",
                "password": "password"
            }
        }


users = []

origins = [
    "*",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


@app.get("/")
def index():
    return {"message": "Hello"}

# create a user


@app.post('/signup', status_code=201)
def create_user(user: User):
    new_user = {
        "name": user.name,
        "email": user.email,
        "password": user.password
    }

    users.append(new_user)

    return new_user

# getting all users


@app.get('/all', response_model=List[User])
def get_users():
    return users


@app.post('/login')
def login(user: UserLogin, Authorize: AuthJWT = Depends()):
    # print(user.__dict__)
    for u in users:
        if (u["email"] == user.email) and (u["password"] == user.password):
            access_token = Authorize.create_access_token(subject=user.email)
            refresh_token = Authorize.create_refresh_token(
                subject=user.email)

            return {"access_token": access_token, "refresh_token": refresh_token}

        raise HTTPException(status_code='401',
                            detail="Invalid email or password")


@app.get('/protected')
def get_logged_in_user(Authorize: AuthJWT = Depends()):
    # print(Authorize.__dict__)
    try:
        Authorize.jwt_required()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    current_user = Authorize.get_jwt_subject()

    return {"current_user": current_user}


@app.get('/new_token')
def create_new_token(Authorize: AuthJWT = Depends()):

    try:
        Authorize.jwt_refresh_token_required()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    current_user = Authorize.get_jwt_subject()

    access_token = Authorize.create_access_token(subject=current_user)

    return {"new_access_token": access_token}


@app.post('/fresh_login')
def fresh_login(user: UserLogin, Authorize: AuthJWT = Depends()):
    for u in users:
        if (u["email"] == user.email) and (u["password"] == user.password):
            fresh_token = Authorize.create_access_token(
                subject=user.email, fresh=True)

            return {"fresh_token": fresh_token}

        raise HTTPException(status=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid Email or Password")


@app.get('/fresh_url')
def get_user(Authorize: AuthJWT = Depends()):
    try:
        Authorize.fresh_jwt_required()
    except Exception as e:
        raise HTTPException(status=HTTP_401_UNAUTHORIZED,
                            detail="Invalid Token")

    current_user = Authorize.get_jwt_subject()

    return {"current_user": current_user}
