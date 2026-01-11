from collections.abc import Sequence
from typing import List, Literal

import httpx
from aiocache import SimpleMemoryCache, cached
from jose import JWTError, jwt
from pydantic import AnyHttpUrl, Field, HttpUrl, field_validator

from ..schema.token_validator_type import TokenValidatorType
from ..schema.validated_token import ValidatedOIDCClaims
from .base import TokenValidatorBase


class OIDCTokenValidator(TokenValidatorBase[ValidatedOIDCClaims]):
    """Validates a JWT from an OIDC provider
    and returns a ValidatedOIDCClaims model.
    """

    type: Literal[TokenValidatorType.OIDC] = TokenValidatorType.OIDC

    issuer: HttpUrl
    jwks_uri: AnyHttpUrl
    audience: str
    algorithms: list[str] = Field(default_factory=lambda: ["RS256"])

    verify_signature: bool = Field(
        default=True,
        description="Whether to verify the JWT signature.",
    )
    verify_aud: bool = Field(
        default=True,
        description="Whether to verify the 'aud' (audience) claim.",
    )
    verify_iat: bool = Field(
        default=True,
        description="Whether to verify the 'iat' (issued at) claim.",
    )
    verify_exp: bool = Field(
        default=True,
        description="Whether to verify the 'exp' (expiration) claim.",
    )
    verify_nbf: bool = Field(
        default=True,
        description="Whether to verify the 'nbf' (not before) claim.",
    )
    verify_iss: bool = Field(
        default=True,
        description="Whether to verify the 'iss' (issuer) claim.",
    )
    verify_sub: bool = Field(
        default=True,
        description="Whether to verify the 'sub' (subject) claim.",
    )
    verify_jti: bool = Field(
        default=True,
        description="Whether to verify the 'jti' (JWT ID) claim.",
    )
    verify_at_hash: bool = Field(
        default=True,
        description="Whether to verify the 'at_hash' claim.",
    )
    require_aud: bool = Field(
        default=False,
        description="Whether the 'aud' claim is required.",
    )
    require_iat: bool = Field(
        default=False,
        description="Whether the 'iat' claim is required.",
    )
    require_exp: bool = Field(
        default=False,
        description="Whether the 'exp' claim is required.",
    )
    require_nbf: bool = Field(
        default=False,
        description="Whether the 'nbf' claim is required.",
    )
    require_iss: bool = Field(
        default=False,
        description="Whether the 'iss' claim is required.",
    )
    require_sub: bool = Field(
        default=False,
        description="Whether the 'sub' claim is required.",
    )
    require_jti: bool = Field(
        default=False,
        description="Whether the 'jti' claim is required.",
    )
    require_at_hash: bool = Field(
        default=False,
        description="Whether the 'at_hash' claim is required.",
    )
    leeway: int = Field(
        default=0,
        description="The leeway in seconds for time-based claims.",
    )

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
            options=dict(
                verify_signature=self.verify_signature,
                verify_aud=self.verify_aud,
                verify_iat=self.verify_iat,
                verify_exp=self.verify_exp,
                verify_nbf=self.verify_nbf,
                verify_iss=self.verify_iss,
                verify_sub=self.verify_sub,
                verify_jti=self.verify_jti,
                verify_at_hash=self.verify_at_hash,
                require_aud=self.require_aud,
                require_iat=self.require_iat,
                require_exp=self.require_exp,
                require_nbf=self.require_nbf,
                require_iss=self.require_iss,
                require_sub=self.require_sub,
                require_jti=self.require_jti,
                require_at_hash=self.require_at_hash,
                leeway=self.leeway,
            ),
        )

        return ValidatedOIDCClaims.model_validate(claims_dict)
