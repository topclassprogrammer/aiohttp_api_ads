from string import ascii_letters, digits, punctuation

import re
from pydantic import BaseModel, field_validator

PASSWORD_CHARS = ascii_letters + digits + punctuation


class UserBase(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def check_email(cls, value):
        pattern = r'^[a-zA-Z0-9.-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
        res = re.fullmatch(pattern, value)
        if not res:
            raise ValueError('Incorrect email')
        return value

    @field_validator("password")
    @classmethod
    def check_password(cls, value):
        if value and len(value) < 8:
            raise ValueError('The password is less than 8 characters')
        elif any(char not in PASSWORD_CHARS for char in value):
            raise ValueError('Incorrect character(s) in password')
        return value


class CreateUser(UserBase):
    first_name: str
    last_name: str
    email: str
    password: str


class UpdateUser(UserBase):
    first_name: str | None = None
    last_name: str | None = None
    email: str | None = None
    password: str | None = None


class AdvertBase(BaseModel):
    title: str | None = None
    description: str | None = None
    owner: int | str | None = None


class CreateAdvert(AdvertBase):
    title: str
    description: str


class UpdateAdvert(AdvertBase):
    title: str | None = None
    description: str | None = None
