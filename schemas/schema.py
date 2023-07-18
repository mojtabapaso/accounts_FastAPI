from pydantic import BaseModel, Field
from typing import Union


class OtpCode(BaseModel):
    phone_number: str


class UserBase(BaseModel):
    phone_number: str = Field(example="09331264063")


class UserCreate(BaseModel):
    password: str


# class User(UserBase):
#     id: int
#     is_active: bool
#
#     class Config:
#         orm_mode = True


class UserData(UserBase):
    code: str = Field(example="123456")


class Token(BaseModel):
    token: dict

#
# class UserInDB(User):
#     hashed_password: str


class Password(BaseModel):
    password: str


class PasswordUpdate(Password):
    new_password: str


class Profile(BaseModel):
    email: Union[str, None] = Field(default=None, example="email@gmail.com")
    first_name: Union[str, None] = Field(example="name")
    last_name: Union[str, None] = Field(example="last name")


class LoginPassword(Password, UserBase):
    pass
