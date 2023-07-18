from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..dependency.auth import validate_phone_number, user_exist, avoid_creating_additional_code, code_is_expired, \
    login_password
from utils.sender import send_otp_code
from utils.random import random_otp_code
from db.dependencies import get_db
from schemas import schema
from ..dependency.jwt import AuthJWT
from models.otpcode import OtpCode

router = APIRouter(prefix="/login")


@router.post('/phone/', dependencies=[Depends(user_exist), Depends(avoid_creating_additional_code)])
def validate_phone_number_send_code(data: schema.UserBase, db: Session = Depends(get_db)) -> str:
    """
    Validate the  **phone number** \n
    validate user exist in database \n
    If approved, the **confirmation code** will be created and sent
    """
    otpCode = OtpCode(code=random_otp_code(), phone_number=data.phone_number)
    db.add(otpCode)
    db.commit()
    send_otp_code(otpCode, data.phone_number)
    return "send opt code"


@router.post('/code/', dependencies=[Depends(user_exist), Depends(code_is_expired)])
def login_with_phone_number_and_code(data: schema.UserData, Authorize: AuthJWT = Depends()) -> schema.TokenJTW:
    """
    validate code has not expired \n
    validate user exist in database \n
    if otp code is not expired login user \n
    send *JWT* **access token** , **refresh token**
    """
    access_token = Authorize.create_access_token(subject=data.phone_number)
    refresh_token = Authorize.create_refresh_token(subject=data.phone_number)
    return {"access_token": access_token, "refresh_token": refresh_token}


@router.post("/password/", dependencies=[Depends(validate_phone_number)])
def login_with_password(data: str = Depends(login_password), Authorize: AuthJWT = Depends()) -> schema.TokenJTW:
    """
    validate user exist in database \n
    if password is current login user \n
    send *JWT* **access token** , **refresh token**
    """
    refresh_token = Authorize.create_refresh_token(subject=data)
    access_token = Authorize.create_access_token(subject=data)
    return {"access_token": access_token, 'refresh_token': refresh_token}
