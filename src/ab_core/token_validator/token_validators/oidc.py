from typing import List, Literal, Sequence, Union

import httpx
from aiocache import SimpleMemoryCache, cached
from jose import JWTError, jwt
from pydantic import AnyHttpUrl, Field, HttpUrl

from ..schema.token_validator_type import TokenValidatorType
from ..schema.validated_token import ValidatedOIDCClaims
from .base import TokenValidatorBase


class OIDCTokenValidator(TokenValidatorBase[ValidatedOIDCClaims]):
    """
    Validates a JWT from an OIDC provider
    and returns a ValidatedOIDCClaims model.
    """

    type: Literal[TokenValidatorType.OIDC] = TokenValidatorType.OIDC

    issuer: HttpUrl
    jwks_uri: AnyHttpUrl
    audience: Union[str, Sequence[str]]
    algorithms: List[str] = Field(default_factory=lambda: ["RS256"])

    # @field_validator("audience", mode="before")
    # def normalize_audience(cls, v: Union[str, Sequence[str]]) -> List[str]:
    #     return list(v) if isinstance(v, (list, tuple, set)) else [str(v)]

    @cached(ttl=300, cache=SimpleMemoryCache)
    async def _get_jwks(self) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.get(self.jwks_uri.encoded_string(), timeout=5)
            resp.raise_for_status()
            return resp.json()

    async def validate(self, token: str) -> ValidatedOIDCClaims:
        jwks = await self._get_jwks()
        header = jwt.get_unverified_header(token)
        key = next((k for k in jwks["keys"] if k.get("kid") == header.get("kid")), None)
        if key is None:
            raise JWTError("No matching 'kid' found in JWKS")

        claims_dict = jwt.decode(
            token,
            key=key,
            algorithms=self.algorithms,
            audience=self.audience,
            issuer=str(self.issuer),
        )

        return ValidatedOIDCClaims.model_validate(claims_dict)
