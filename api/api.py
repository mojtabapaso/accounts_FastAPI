from .endpoints import profile, register, login, password
from fastapi import FastAPI

app = FastAPI()

app.include_router(profile.router, tags=["Profile"])
app.include_router(register.router, tags=["Register"])
app.include_router(login.router, tags=["Login"])
app.include_router(password.router, tags=["Password"])
