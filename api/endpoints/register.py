from typing import Dict

from sqlalchemy.orm import Session
from ..dependency.auth import validate_phone_number, code_is_expired, validate_otp_request_rate, validate_user, \
    falsifier_activate_otp_code
from utils.sender import send_otp_code
from utils.random import random_otp_code
from db.dependencies import get_db
from starlette import status
from fastapi import APIRouter, Depends
from schemas import schema
from models.otpcode import OtpCode
from models.profile import Profile
from models.user import User
from ..dependency.jwt import AuthJWT

router = APIRouter(prefix="/register")


@router.post('/phone/',
             dependencies=[Depends(validate_phone_number),
                           Depends(validate_otp_request_rate),
                           Depends(validate_user),
                           Depends(falsifier_activate_otp_code)])
def register_user_with_phone_number(user: schema.UserBase, db: Session = Depends(get_db)) -> str:
    """
    get phone number and validate them not found in database \n
    after create a random code and send to user
    """
    otpCode = OtpCode(code=random_otp_code(), phone_number=user.phone_number)
    db.add(otpCode)
    db.commit()
    db.refresh(otpCode)
    send_otp_code(otpCode, user.phone_number)
    return 'Send opt code'


@router.post('/code/', dependencies=[Depends(code_is_expired)], status_code=status.HTTP_201_CREATED)
def register_for_token(data: schema.UserData, db: Session = Depends(get_db),
                       Authorize: AuthJWT = Depends()) -> schema.TokenJTW:
    """
    get phone number and otp code \n
    validate them and if current register user and send *JWT* **access token** , **refresh token**
    """
    user = User(phone_number=data.phone_number)
    profile = Profile(phone_number=data.phone_number)
    db.add(user)
    db.add(profile)
    db.commit()
    access_token = Authorize.create_access_token(subject=data.phone_number)
    refresh_token = Authorize.create_refresh_token(subject=data.phone_number)
    return {"access_token": access_token, "refresh_token": refresh_token}
