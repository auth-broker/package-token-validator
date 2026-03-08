"""OIDC token validator implementation."""

from functools import cached_property
from typing import Literal

import httpx
import jwt
import jwt.exceptions
import jwt.types
from aiocache import SimpleMemoryCache, cached
from pydantic import AnyHttpUrl, BaseModel, Field, HttpUrl, computed_field

from ..schema.token_validator_type import TokenValidatorType
from ..schema.validated_token import ValidatedOIDCClaims
from .base import TokenValidatorBase


class OIDCIssuerConfig(BaseModel):
    """Configuration for a single trusted OIDC issuer."""

    issuer: HttpUrl = Field(
        description="The issuer URL. Must match the `iss` claim in tokens from this provider.",
    )
    jwks_uri: AnyHttpUrl = Field(
        description="JWKS endpoint for this issuer, used to fetch public keys for signature verification.",
    )
    audience: list[str] = Field(
        description="Valid audience values for tokens issued by this issuer.",
    )


class OIDCTokenValidator(TokenValidatorBase[ValidatedOIDCClaims]):
    """Validates a JWT from one of a list of trusted OIDC issuers.

    Supports multiple issuers (e.g. a web app provider and a restricted n8n provider),
    each with their own JWKS URI and audience. The token's `iss` claim is peeked at
    without signature verification to select the correct issuer config, then full
    cryptographic validation is performed against that issuer's JWKS.
    """

    type: Literal[TokenValidatorType.OIDC] = TokenValidatorType.OIDC

    issuers: list[OIDCIssuerConfig] = Field(
        description=(
            "List of trusted OIDC issuers. Each entry specifies an issuer URL, JWKS URI, "
            "and audience list. The token's `iss` claim is used to select the matching config."
        ),
    )
    algorithms: list[str] = Field(
        default_factory=lambda: ["RS256"],
        description="Allowed signing algorithms.",
    )

    verify_signature: bool = Field(default=True, description="Whether to verify the JWT signature.")
    strict_aud: bool = Field(
        default=False, description="Check that the `aud` claim is a single value and matches `audience` exactly."
    )
    verify_aud: bool = Field(default=True, description="Whether to verify the 'aud' (audience) claim.")
    verify_exp: bool = Field(default=True, description="Whether to verify the 'exp' (expiration) claim.")
    verify_iat: bool = Field(default=True, description="Whether to verify the 'iat' (issued at) claim.")
    verify_iss: bool = Field(default=True, description="Whether to verify the 'iss' (issuer) claim.")
    verify_jti: bool = Field(default=True, description="Whether to verify the 'jti' (JWT ID) claim.")
    verify_nbf: bool = Field(default=True, description="Whether to verify the 'nbf' (not before) claim.")
    verify_sub: bool = Field(default=True, description="Whether to verify the 'sub' (subject) claim.")

    require_aud: bool = Field(default=False, description="Whether the 'aud' claim is required.")
    require_iat: bool = Field(default=False, description="Whether the 'iat' claim is required.")
    require_exp: bool = Field(default=False, description="Whether the 'exp' claim is required.")
    require_nbf: bool = Field(default=False, description="Whether the 'nbf' claim is required.")
    require_iss: bool = Field(default=False, description="Whether the 'iss' claim is required.")
    require_sub: bool = Field(default=False, description="Whether the 'sub' claim is required.")
    require_jti: bool = Field(default=False, description="Whether the 'jti' claim is required.")
    enforce_minimum_key_length: bool = Field(
        default=False,
        description=(
            "Raise `jwt.exceptions.InvalidKeyError` instead of warning when keys are below minimum recommended length."
        ),
    )
    leeway: int = Field(default=0, description="The leeway in seconds for time-based claims.")

    @computed_field(return_type=list[str])
    @cached_property
    def required_claims(self) -> list[str]:
        """Compute the list of required claims based on the `require_*` boolean fields."""
        claims = []
        if self.require_aud:
            claims.append("aud")
        if self.require_iat:
            claims.append("iat")
        if self.require_exp:
            claims.append("exp")
        if self.require_nbf:
            claims.append("nbf")
        if self.require_iss:
            claims.append("iss")
        if self.require_sub:
            claims.append("sub")
        if self.require_jti:
            claims.append("jti")
        return claims

    @cached_property
    def _issuer_map(self) -> dict[str, OIDCIssuerConfig]:
        """Pre-built map of issuer URL string → OIDCIssuerConfig for O(1) lookup."""
        return {str(config.issuer): config for config in self.issuers}

    @cached(ttl=300, cache=SimpleMemoryCache)
    async def _get_jwks(self, jwks_uri: str) -> dict:
        """Fetch the JWKS from the given URI. Cached per URI for 5 minutes."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(jwks_uri, timeout=5)
            resp.raise_for_status()
            return resp.json()

    async def validate(self, token: str) -> ValidatedOIDCClaims:
        """Validate the given JWT and return a ValidatedOIDCClaims model.

        1. Peek at `iss` without signature verification to select the issuer config.
        2. Fetch the JWKS for that issuer and match the signing key by `kid`.
        3. Fully validate the token (signature, iss, aud, exp, etc.).
        """
        # Step 1: peek at iss without verifying — safe because we only use it
        # to select which JWKS to fetch. Full iss validation happens in step 3.
        unverified = jwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=self.algorithms,
        )
        iss = unverified.get("iss")
        issuer_config = self._issuer_map.get(iss)
        if issuer_config is None:
            raise jwt.exceptions.InvalidIssuerError(f"Untrusted issuer: {iss!r}")

        # Step 2: fetch JWKS for this issuer and find the matching key
        jwks = await self._get_jwks(str(issuer_config.jwks_uri))
        header = jwt.get_unverified_header(token)
        jwk_data = next((k for k in jwks["keys"] if k.get("kid") == header.get("kid")), None)
        if jwk_data is None:
            raise jwt.exceptions.PyJWKSetError("No matching 'kid' found in JWKS")
        key = jwt.PyJWK(jwk_data=jwk_data).key

        # Step 3: full validation — issuer list acts as an allowlist
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
            audience=issuer_config.audience,
            issuer=str(issuer_config.issuer),
            leeway=self.leeway,
        )

        return ValidatedOIDCClaims.model_validate(claims_dict)
