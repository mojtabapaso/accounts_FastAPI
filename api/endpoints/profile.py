from fastapi import APIRouter, Depends
from starlette import status

from api.dependency.auth import profile_is_not_none, show_profile
from api.dependency.jwt import login_required

router = APIRouter()


@router.get("/show/profile/", dependencies=[Depends(profile_is_not_none)], status_code=status.HTTP_200_OK)
def show_profile(auth=Depends(login_required), profile=Depends(show_profile)):
    return profile
