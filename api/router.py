from api.dependency.jwt import login_required, AuthJWT
from fastapi import APIRouter, Depends

router = APIRouter()


@router.get("/a/")
def health():
    return "ok"


@router.post("/b/")
def post(auth: str = Depends(login_required)):
    return auth
