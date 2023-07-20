from .endpoints import profile, register, login, password
from fastapi import FastAPI

tags_metadata = [

    {
        "name": "Register",
        "description": "User Registration is done here",
    },
    {
        "name": "Login",
        "description": "User Login is done here",
    },
    {
        "name": "Profile",
        "description": "User Profile is done here",
    },
    {
        "name": "Password",
        "description": "Change and Set Password User here",
    },
]
description = """
# Simple Manager Account with FastAPI . 🚀
# Attribute :
## Register
## Login
## Profile
## Password
"""
app = FastAPI(openapi_tags=tags_metadata, title="Simple FastAPI 🚀 Project",
              description=description,
              version="0.0.1",
              contact={
                  "name": "to Mojtaba",
                  "email": "mojtabapaso@gmail.com",
              },
              license_info={
                  "name": "License MIT",
                  "identifier": "MIT",
              }, )

app.include_router(register.router, tags=["Register"])
app.include_router(login.router, tags=["Login"])
app.include_router(profile.router, tags=["Profile"])
app.include_router(password.router, tags=["Password"])
