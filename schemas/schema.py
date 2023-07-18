from pydantic import BaseModel, Field
from typing import Union, Dict


class UserBase(BaseModel):
    phone_number: str = Field(example="09331264063")


class UserData(UserBase):
    code: str = Field(example="123456")


class Password(BaseModel):
    password: str = Field(example="password")


class PasswordUpdate(Password):
    new_password: str = Field(example="new password")


class Profile(BaseModel):
    email: Union[str, None] = Field(default=None, example="email@gmail.com")
    first_name: Union[str, None] = Field(example="name")
    last_name: Union[str, None] = Field(example="last name")


class LoginPassword(BaseModel):
    password: str = Field(example="password")
    phone_number: str = Field(example="09331264063")


class TokenJTW(BaseModel):
    access_token: str = Field(example="Asd23CeDVfdd...")
    refresh_token: str = Field(example="PoaCvrcs...")

# class User(UserBase):
#     id: int
#     is_active: bool
#
#     class Config:
#         orm_mode = True
