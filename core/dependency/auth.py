from ..schemas.schema import UserBase
from fastapi import HTTPException, status
import re
from models.models import OtpCode
from models.dependencies import get_db
from models.dependencies import get_db, SessionLocal
from fastapi import Depends
from sqlalchemy.orm import Session
from models.models import User
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta


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

# def validate_otp(data: UserBase, db: Session = Depends(get_db)):
#     database = db.query(User).filter(User.phone_number == data.phone_number).first()
#     # if database:
#     #     return {f"__ {database} ___ "}
