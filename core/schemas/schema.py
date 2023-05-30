from pydantic import BaseModel


class OtpCode(BaseModel):
    phone_number: str


class UserBase(BaseModel):
    phone_number: str


class UserCreate(BaseModel):
    password: str


class User(UserBase):
    id: int
    is_active: bool

    class Config:
        orm_mode = True


class UserData(UserBase):
    code: int


class Token(BaseModel):
    access_token: str
    token_type: str


class UserInDB(User):
    hashed_password: str


class Password(BaseModel):
    password: str


class PasswordUpdate(Password):
    new_password: str


class Profile(BaseModel):
    email: str | None = None
    first_name: str | None = None
    last_name: str | None = None

class LoginPassword(Password,UserBase):
    pass