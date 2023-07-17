from datetime import datetime, timedelta
from random import randint
from fastapi import status, APIRouter, HTTPException, Depends, Body
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import *
from pydantic import BaseModel
from sqlalchemy.orm import Session
from core.schemas import schema
from core.security.hasher import get_password_hash, verify_password
from core.security.validate_email import is_valid_email_regex
from core.utils.sender import send_otp_code
from models.dependencies import get_db
from models.models import User, OtpCode, Profile
from fastapi import Depends
from setting import *
from core.utils.random import random_otp_code
from core.dependency.auth import *

router = APIRouter()


class Settings(BaseModel):
    authjwt_secret_key: str = AUTH_SECRET_KEY
    authjwt_token_location = ("headers",)
    authjwt_cookie_secure = False
    authjwt_algorithm = AUTH_ALGORITHM


@AuthJWT.load_config
def get_config():
    return Settings()


# ------------------------------------------------------------------------------------


@router.post('/register/phone/',
             dependencies=[Depends(validate_phone_number), Depends(validate_otp_request_rate), Depends(validate_user),
                           Depends(falsifier_activate_otp_code)],
             status_code=status.HTTP_200_OK)
def register_user_with_phone_number(user: schema.UserBase, db: Session = Depends(get_db), ):
    otpCode = OtpCode(code=random_otp_code(), phone_number=user.phone_number)
    db.add(otpCode)
    db.commit()
    db.refresh(otpCode)
    # send_otp_code(otpCode, user.phone_number)
    return 'We send opt code for your phone number'


@router.post('/register/code/', status_code=status.HTTP_201_CREATED)
def register_for_token(data: schema.UserData, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    user_code = db.query(OtpCode).filter(
        OtpCode.phone_number == data.phone_number and OtpCode.code == data.code).order_by(
        OtpCode.id.desc()).first()
    if user_code and (user_code.time + timedelta(minutes=2)) < datetime.now():
        user_code.expired = False
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='The verification code has expired or invalid')
    user = User(phone_number=data.phone_number)
    profile = Profile(phone_number=data.phone_number)
    db.delete(user_code)
    db.add(user)
    db.add(profile)
    db.commit()
    db.refresh(user)
    access_token = Authorize.create_access_token(subject=data.phone_number)
    refresh_token = Authorize.create_refresh_token(subject=data.phone_number)
    return {"access_token": access_token, "refresh_token": refresh_token}


@router.post('/login/phone/', status_code=status.HTTP_200_OK)
def login_token(data: schema.OtpCode, db: Session = Depends(get_db)):
    user_exist = db.query(User).filter(User.phone_number == data.phone_number).first()
    if user_exist is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="This phone number not found")
    last_otp_time = db.query(OtpCode).filter(OtpCode.phone_number == data.phone_number).order_by(
        OtpCode.id.desc()).first()
    if last_otp_time and (last_otp_time.time + timedelta(minutes=2)) > datetime.now():
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail='Please wait for 2 minutes before requesting a new OTP')
    otpCode = OtpCode(code=randint(10000, 99999), phone_number=data.phone_number)
    db.add(otpCode)
    db.commit()
    db.refresh(otpCode)
    send_otp_code(otpCode, data.phone_number)
    return {"detail": "We send opt code for your phone number", "code": otpCode}


@router.post('/login/code/', status_code=status.HTTP_200_OK)
def login_token(data: schema.UserData, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    user_exist = db.query(User).filter(User.phone_number == data.phone_number).first()
    if user_exist is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="This phone number not found")
    code_valid = db.query(OtpCode).filter(OtpCode.code == data.code).first()
    if code_valid and (code_valid.time + timedelta(minutes=2)) < datetime.now():
        code_valid.expired = False
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='The verification code has expired or invalid')
    access_token = Authorize.create_access_token(subject=data.phone_number)
    refresh_token = Authorize.create_refresh_token(subject=data.phone_number)
    return {"access_token": access_token, "refresh_token": refresh_token}


@router.post("/login/password/", status_code=status.HTTP_200_OK)
def login_password(data: schema.LoginPassword, Authorize: AuthJWT = Depends(), db: Session = Depends(get_db)):
    password = data.password
    phone_number = data.phone_number
    user = db.query(User).filter(User.phone_number == phone_number).first()
    verifyPassword = verify_password(password, user.password)
    if verifyPassword is False:
        return "password invalid"
    refresh_token = Authorize.create_refresh_token(subject=phone_number)
    access_token = Authorize.create_access_token(subject=phone_number)
    return {"access_token": access_token, 'refresh_token': refresh_token}


@router.post('/set/password/', status_code=status.HTTP_200_OK)
def set_password(data: schema.UserCreate, Authorize: AuthJWT = Depends(), db: Session = Depends(get_db)):
    try:
        phone_number = Authorize.get_jwt_subject()
        user = db.query(User).filter(User.phone_number == phone_number).first()
        Authorize.jwt_required()
        hash_password = get_password_hash(data.password)
        user.password = hash_password
        db.commit()
        db.refresh(user)
        return {"password": data.password, 'user': user}
    except JWTDecodeError or MissingTokenError or AuthJWTException:
        return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                             detail='Json Web Token invalid')


@router.put('/update/password/', status_code=status.HTTP_200_OK)
def update_password(data: schema.PasswordUpdate, Authorize: AuthJWT = Depends(), db: Session = Depends(get_db)):
    try:
        Authorize.jwt_required()
        phone_number = Authorize.get_jwt_subject()
        user = db.query(User).filter(User.phone_number == phone_number).first()
        old_password = data.password
        verifyPassword = verify_password(old_password, user.password)
        if verifyPassword:
            user.password = get_password_hash(data.new_password)
            db.commit()
            db.refresh(user)
            return {'detail': 'Password update'}
        return {'detail': 'Password be most mach'}
    except JWTDecodeError or MissingTokenError or AuthJWTException:
        return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                             detail='Json Web Token invalid')


@router.put('/update/profile/', status_code=status.HTTP_200_OK)
def update_profile(data: schema.Profile | None = None, Authorize: AuthJWT = Depends(), db: Session = Depends(get_db)):
    try:
        Authorize.jwt_required()
        phone_number = Authorize.get_jwt_subject()
        profile = db.query(Profile).filter(Profile.phone_number == phone_number).first()
        if profile is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Profile not found')
        if data:
            profile.first_name = data.first_name
            profile.last_name = data.last_name
            if is_valid_email_regex(data.email) and data.email is not None:
                profile.email = data.email
            else:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid email address')
        db.commit()
        db.refresh(profile)
        return "Change in profile successfully saved"
    except JWTDecodeError or MissingTokenError or AuthJWTException:
        return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                             detail='Json Web Token invalid')


@router.get("/show/profile/", status_code=status.HTTP_200_OK)
def show_profile(Authorize: AuthJWT = Depends(), db: Session = Depends(get_db)):
    try:
        Authorize.jwt_required()
        phone_number = Authorize.get_jwt_subject()
        profile = db.query(Profile).filter(Profile.phone_number == phone_number).first()
        if profile is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='This profile not found')
        return profile
    except JWTDecodeError or MissingTokenError or AuthJWTException:
        return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                             detail='Json Web Token invalid')


@router.get("/a/")
def tesff():
    return "ok"
