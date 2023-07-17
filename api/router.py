from random import randint
from core.schemas import schema
from core.security.hasher import get_password_hash, verify_password
from core.security.validate_email import is_valid_email_regex
from core.utils.sender import send_otp_code
from models.models import Profile
from core.utils.random import random_otp_code
from core.dependency.auth import *
from core.dependency.jwt import login_required, AuthJWT
from fastapi import APIRouter, HTTPException, Depends

router = APIRouter()


@router.post('/register/phone/',
             dependencies=[Depends(validate_phone_number),
                           Depends(validate_otp_request_rate),
                           Depends(validate_user),
                           Depends(falsifier_activate_otp_code)],
             status_code=status.HTTP_200_OK)
def register_user_with_phone_number(user: schema.UserBase, db: Session = Depends(get_db), ):
    otpCode = OtpCode(code=random_otp_code(), phone_number=user.phone_number)
    db.add(otpCode)
    db.commit()
    db.refresh(otpCode)
    # send_otp_code(otpCode, user.phone_number)
    return 'Send opt code'


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


@router.post("/login/password/", dependencies=[Depends(validate_phone_number)], status_code=status.HTTP_200_OK)
def login_password(data: str = Depends(login_password), Authorize: AuthJWT = Depends()):
    refresh_token = Authorize.create_refresh_token(subject=data)
    access_token = Authorize.create_access_token(subject=data)
    return {"access_token": access_token, 'refresh_token': refresh_token}


@router.post('/set/password/', status_code=status.HTTP_200_OK)
def set_password(data: schema.UserCreate, auth: str = Depends(login_required), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.phone_number == auth).first()
    hash_password = get_password_hash(data.password)
    user.password = hash_password
    db.commit()
    db.refresh(user)
    return {"password": data.password, 'user': user}


@router.put('/update/password/', status_code=status.HTTP_200_OK)
def update_password(data: schema.PasswordUpdate, auth: str = Depends(login_required), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.phone_number == auth).first()
    old_password = data.password
    verifyPassword = verify_password(old_password, user.password)
    if verifyPassword:
        user.password = get_password_hash(data.new_password)
        db.commit()
        db.refresh(user)
        return 'Password update'
    raise HTTPException(detail='Password be most mach', status_code=status.HTTP_409_CONFLICT)


@router.put('/update/profile/', status_code=status.HTTP_200_OK)
def update_profile(data: schema.Profile | None = None, auth: str = Depends(login_required),
                   db: Session = Depends(get_db)):
    # phone_number = Authorize.get_jwt_subject()
    profile = db.query(Profile).filter(Profile.phone_number == auth).first()
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


@router.get("/show/profile/", status_code=status.HTTP_200_OK)
def show_profile(auth: str = Depends(login_required), db: Session = Depends(get_db)):
    profile = db.query(Profile).filter(Profile.phone_number == auth).first()
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='This profile not found')
    return profile


@router.get("/a/")
def tesff():
    return "ok"


@router.post("/b/")
def post(auth: str = Depends(login_required)):
    return auth
    # return "twine Ok"
