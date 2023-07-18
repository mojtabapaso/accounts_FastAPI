from models.profile import Profile
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from starlette import status
from schemas import schema
from api.dependency.auth import profile_is_not_none, show_profile
from api.dependency.jwt import login_required
from db.dependencies import get_db
from security.validate_email import is_valid_email_regex

router = APIRouter()


@router.get("/show/profile/", dependencies=[Depends(profile_is_not_none)], status_code=status.HTTP_200_OK)
def show_profile(auth=Depends(login_required), profile=Depends(show_profile)):
    return profile

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