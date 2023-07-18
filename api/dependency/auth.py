from fastapi_jwt_auth import AuthJWT
from schemas.schema import UserBase, UserData, LoginPassword
from models.otpcode import OtpCode
from models.user import User
from models.profile import Profile
from db.dependencies import get_db
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from security.hasher import verify_password
import re

def validate_phone_number(user: UserBase):
    if not re.match("^09\d{9}$", user.phone_number):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="phone_number is invalid")


def validate_otp_request_rate(user: UserBase, db: Session = Depends(get_db)):
    last_otp_time = db.query(OtpCode).filter(OtpCode.phone_number == user.phone_number).order_by(
        OtpCode.id.desc()).first()
    if last_otp_time and (last_otp_time.time + timedelta(minutes=2)) > datetime.now():
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail='Please wait for 2 minutes before requesting a new OTP')


def validate_user(user: UserBase, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.phone_number == user.phone_number).first()
    if db_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='Phone number already exists')


def falsifier_activate_otp_code(user: UserBase, db: Session = Depends(get_db)):
    db_otp = db.query(OtpCode).filter(OtpCode.phone_number == user.phone_number)
    if db_otp.first():
        db_otp.update({OtpCode.expired: False})
        db.commit()


def login_password(data: LoginPassword, db: Session = Depends(get_db)):
    password = data.password
    phone_number = data.phone_number
    user = db.query(User).filter(User.phone_number == phone_number).first()

    verifyPassword = verify_password(password, user.password)
    if verifyPassword is False:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="password invalid")
    return phone_number


def user_exist(data: UserBase, db: Session = Depends(get_db)):
    user_exist = db.query(User).filter(User.phone_number == data.phone_number).first()
    if user_exist is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="This phone number not found")


def avoid_creating_additional_code(data: UserBase, db: Session = Depends(get_db)):
    last_otp_time = db.query(OtpCode).filter(OtpCode.phone_number == data.phone_number).order_by(
        OtpCode.id.desc()).first()

    if last_otp_time and (last_otp_time.time + timedelta(minutes=2)) > datetime.now():
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail='Please wait for 2 minutes before requesting a new OTP')


def profile_is_not_none(Auth: AuthJWT = Depends(), db: Session = Depends(get_db)):
    sub = Auth.get_jwt_subject()
    profile = db.query(Profile).filter(Profile.phone_number == sub).first()
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='This profile not found')


def show_profile(Auth: AuthJWT = Depends(), db: Session = Depends(get_db)):
    sub = Auth.get_jwt_subject()
    profile = db.query(Profile).filter(Profile.phone_number == sub).first()
    return profile


def code_is_expired(data: UserData, db: Session = Depends(get_db)):
    code_valid = db.query(OtpCode).filter(OtpCode.code == data.code).first()
    if code_valid and (code_valid.time + timedelta(minutes=2)) < datetime.now():
        code_valid.expired = False
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Code has expired or invalid')
