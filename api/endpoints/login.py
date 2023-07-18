from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..dependency.auth import validate_phone_number, user_exist, avoid_creating_additional_code, code_is_expired, \
    login_password
from utils.sender import send_otp_code
from utils.random import random_otp_code
from db.dependencies import get_db
from starlette import status
from schemas import schema
from ..dependency.jwt import AuthJWT
from models.otpcode import OtpCode

router = APIRouter(prefix="/login")


@router.get("/a/")
def rt():
    return "ok"


@router.post('/phone/', dependencies=[Depends(user_exist), Depends(avoid_creating_additional_code)])
def login_token(data: schema.OtpCode, db: Session = Depends(get_db)):
    otpCode = OtpCode(code=random_otp_code(), phone_number=data.phone_number)
    db.add(otpCode)
    db.commit()
    send_otp_code(otpCode, data.phone_number)
    return "send opt code"


@router.post('/code/', dependencies=[Depends(user_exist), Depends(code_is_expired)])
def login_token(data: schema.UserData, Authorize: AuthJWT = Depends()):
    access_token = Authorize.create_access_token(subject=data.phone_number)
    refresh_token = Authorize.create_refresh_token(subject=data.phone_number)
    return {"access_token": access_token, "refresh_token": refresh_token}


@router.post("/password/", dependencies=[Depends(validate_phone_number)])
def login_password(data: str = Depends(login_password), Authorize: AuthJWT = Depends()):
    refresh_token = Authorize.create_refresh_token(subject=data)
    access_token = Authorize.create_access_token(subject=data)
    return {"access_token": access_token, 'refresh_token': refresh_token}
