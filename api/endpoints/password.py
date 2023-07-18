from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from security.hasher import verify_password, get_password_hash
from db.dependencies import get_db
from starlette import status
from schemas import schema
from models.user import User
from ..dependency.jwt import login_required

router = APIRouter(prefix="/password")


@router.post('/set/')
def set_password(data: schema.UserCreate, auth: str = Depends(login_required), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.phone_number == auth).first()
    hash_password = get_password_hash(data.password)
    user.password = hash_password
    db.commit()
    db.refresh(user)
    return {"password": data.password, 'user': user}


@router.put('/update/')
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



