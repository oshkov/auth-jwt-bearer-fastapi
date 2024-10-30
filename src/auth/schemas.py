from pydantic import BaseModel


class UserCreate(BaseModel):
    username: str
    email: str
    password: str


class UserRead(BaseModel):
    id: int
    email: str
    username: str


class UserLogin(BaseModel):
    email: str
    password: str


class UserEdit(BaseModel):
    username: str
    password: str