
from pydantic import BaseModel


class ValidatedOIDCClaims(BaseModel):
    iss: str
    sub: str
    aud: str | list[str]
    exp: int
    iat: int
    auth_time: int
    acr: str

    # New fields
    email: str | None = None
    email_verified: bool | None = None
    name: str | None = None
    given_name: str | None = None
    preferred_username: str | None = None
    nickname: str | None = None
    groups: list[str] | None = None
