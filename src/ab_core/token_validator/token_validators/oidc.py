from functools import cached_property
from typing import Literal

import httpx
import jwt
import jwt.exceptions
import jwt.types
from aiocache import SimpleMemoryCache, cached
from pydantic import AnyHttpUrl, Field, HttpUrl, computed_field

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
    audience: list[str]
    algorithms: list[str] = Field(default_factory=lambda: ["RS256"])

    verify_signature: bool = Field(
        default=True,
        description="Whether to verify the JWT signature.",
    )
    strict_aud: bool = Field(
        default=False,
        description="Check that the `aud` claim is a single value (not a list), and matches `audience` exactly.",
    )
    verify_aud: bool = Field(
        default=True,
        description="Whether to verify the 'aud' (audience) claim.",
    )
    verify_exp: bool = Field(
        default=True,
        description="Whether to verify the 'exp' (expiration) claim.",
    )
    verify_iat: bool = Field(
        default=True,
        description="Whether to verify the 'iat' (issued at) claim.",
    )
    verify_iss: bool = Field(
        default=True,
        description="Whether to verify the 'iss' (issuer) claim.",
    )
    verify_jti: bool = Field(
        default=True,
        description="Whether to verify the 'jti' (JWT ID) claim.",
    )
    verify_nbf: bool = Field(
        default=True,
        description="Whether to verify the 'nbf' (not before) claim.",
    )
    verify_sub: bool = Field(
        default=True,
        description="Whether to verify the 'sub' (subject) claim.",
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
    enforce_minimum_key_length: bool = Field(
        default=False,
        description="Raise `jwt.exceptions.InvalidKeyError` instead of warning when keys are below minimum recommended length.",
    )
    leeway: int = Field(
        default=0,
        description="The leeway in seconds for time-based claims.",
    )

    @computed_field(return_type=list[str])
    @cached_property
    def required_claims(self) -> list[str]:
        """Compute the list of required claims based on the `require_*` boolean fields."""
        required_claims = []
        if self.require_aud:
            required_claims.append("aud")
        if self.require_iat:
            required_claims.append("iat")
        if self.require_exp:
            required_claims.append("exp")
        if self.require_nbf:
            required_claims.append("nbf")
        if self.require_iss:
            required_claims.append("iss")
        if self.require_sub:
            required_claims.append("sub")
        if self.require_jti:
            required_claims.append("jti")
        return required_claims

    @cached(ttl=300, cache=SimpleMemoryCache)
    async def _get_jwks(self) -> dict:
        """Fetch the JWKS from the `jwks_uri`. Cached for 5 minutes to avoid excessive calls."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(self.jwks_uri.encoded_string(), timeout=5)
            resp.raise_for_status()
            return resp.json()

    async def validate(self, token: str) -> ValidatedOIDCClaims:
        """Validate the given JWT and return a ValidatedOIDCClaims model."""
        jwks = await self._get_jwks()
        header = jwt.get_unverified_header(token)
        key = next((k for k in jwks["keys"] if k.get("kid") == header.get("kid")), None)
        if key is None:
            raise jwt.exceptions.PyJWKSetError("No matching 'kid' found in JWKS")

        claims_dict = jwt.decode(
            token,
            key=key,
            algorithms=self.algorithms,
            options=jwt.types.Options(
                verify_signature=self.verify_signature,
                require=self.required_claims,
                strict_aud=self.strict_aud,
                verify_aud=self.verify_aud,
                verify_iat=self.verify_iat,
                verify_exp=self.verify_exp,
                verify_nbf=self.verify_nbf,
                verify_iss=self.verify_iss,
                verify_sub=self.verify_sub,
                verify_jti=self.verify_jti,
            ),
            audience=self.audience,
            issuer=str(self.issuer),
            leeway=self.leeway,
        )

        return ValidatedOIDCClaims.model_validate(claims_dict)
