from typing import List, Optional

from pydantic import BaseModel


class ValidatedOIDCClaims(BaseModel):
    iss: str
    sub: str
    aud: str | List[str]
    exp: int
    iat: int
    auth_time: int
    acr: str

    # New fields
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    name: Optional[str] = None
    given_name: Optional[str] = None
    preferred_username: Optional[str] = None
    nickname: Optional[str] = None
    groups: Optional[List[str]] = None
