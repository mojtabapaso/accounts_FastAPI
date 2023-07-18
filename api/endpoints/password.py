from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from security.hasher import verify_password, get_password_hash
from security.validate_email import is_valid_email_regex
from db.dependencies import get_db
from starlette import status
from schemas import schema
from models.user import User
from models.profile import Profile
from ..dependency.jwt import login_required

router = APIRouter()


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
def update_profile(data: schema.Profile | None = None, phone: str = Depends(login_required),
                   db: Session = Depends(get_db)):
    profile = db.query(Profile).filter(Profile.phone_number == phone).first()
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
    return "Change profile successfully"
