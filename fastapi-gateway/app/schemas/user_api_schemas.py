from pydantic import BaseModel


class RegisterUserPayload(BaseModel):
    username: str
    email: str
    password: str
    first_name: str
    last_name: str
    alias_name: str | None = None
    avatar_profile: str | None = None


class UpdateUserPayload(BaseModel):
    username: str | None = None
    email: str | None = None
    alias_name: str | None = None
    avatar_profile: str | None = None
