from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import *
from pydantic import BaseModel
from starlette import status

from setting import *
from fastapi import Depends, HTTPException


class Settings(BaseModel):
    authjwt_secret_key: str = AUTH_SECRET_KEY
    authjwt_token_location = ("headers",)
    authjwt_cookie_secure = False
    authjwt_algorithm = AUTH_ALGORITHM


@AuthJWT.load_config
def get_config():
    return Settings()


def login_required(Auth: AuthJWT = Depends()):
    try:
        Auth.jwt_required()
        subject = Auth.get_jwt_subject()
        return subject
    except JWTDecodeError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Json Web Token Decode Error ')
    except MissingTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Json Web Token Missing Token')
    except AuthJWTException:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Json Web Token invalid')


# def jwt(subject, auth: AuthJWT = Depends()):
#     refresh = auth.create_refresh_token(subject)
#     access = auth.create_access_token(subject)
