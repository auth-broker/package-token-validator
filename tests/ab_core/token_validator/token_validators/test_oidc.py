import time
from unittest.mock import AsyncMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from uuid_extensions import uuid7

from ab_core.token_validator.token_validators.oidc import OIDCTokenValidator


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def rsa_key_pair():
    """Generate a real RSA key pair once for the module."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture(scope="module")
def kid():
    return "test-kid-001"


@pytest.fixture(scope="module")
def jwks(rsa_key_pair, kid):
    """Build a real JWKS from the public key."""
    from jwt.algorithms import RSAAlgorithm
    _, public_key = rsa_key_pair
    # Pass the key object directly, not a PEM string
    jwk_dict = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    jwk_dict["kid"] = kid
    jwk_dict["use"] = "sig"
    return {"keys": [jwk_dict]}


def make_token(private_key, kid: str, overrides: dict = None) -> tuple[str, dict]:
    """Sign a realistic JWT with the given private key. Returns (token, claims)."""
    now = int(time.time())
    claims = {
        "iss": "https://issuer.example.com/",
        "sub": str(uuid7()),
        "aud": ["my-client-id"],
        "iat": now,
        "exp": now + 3600,
        "auth_time": now,
        "acr": "urn:mace:incommon:iap:silver",
        "email": "user@example.com",
        "email_verified": True,
        "name": "Test User",
        "given_name": "Test",
        "preferred_username": "tuser",
        "nickname": "tester",
        "groups": ["admins", "devs"],
        "entitlements": ["read:me", "read:token_issuer"],
    }
    if overrides:
        claims.update(overrides)

    token = jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )
    return token, claims


@pytest.fixture
def validator():
    return OIDCTokenValidator(
        issuer="https://issuer.example.com/",
        jwks_uri="https://issuer.example.com/.well-known/jwks.json",
        audience=["my-client-id"],
        algorithms=["RS256"],
        require_exp=True,
        require_iss=True,
        require_sub=True,
    )


# ── Tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_valid_token(validator, rsa_key_pair, jwks, kid):
    """A well-formed, signed token should decode and validate successfully."""
    private_key, _ = rsa_key_pair
    token, claims = make_token(private_key, kid)

    with patch.object(OIDCTokenValidator, "_get_jwks", new=AsyncMock(return_value=jwks)):
        validated = await validator.validate(token)

    assert validated.iss == claims["iss"]
    assert validated.sub == claims["sub"]
    assert validated.aud == claims["aud"]
    assert validated.email == claims["email"]
    assert validated.entitlements == claims["entitlements"]
    assert validated.groups == claims["groups"]


@pytest.mark.asyncio
async def test_expired_token(validator, rsa_key_pair, jwks, kid):
    """An expired token should raise ExpiredSignatureError."""
    private_key, _ = rsa_key_pair
    token, _ = make_token(private_key, kid, overrides={"exp": int(time.time()) - 10})

    with patch.object(OIDCTokenValidator, "_get_jwks", new=AsyncMock(return_value=jwks)):
        with pytest.raises(jwt.exceptions.ExpiredSignatureError):
            await validator.validate(token)


@pytest.mark.asyncio
async def test_wrong_audience(validator, rsa_key_pair, jwks, kid):
    """A token with a non-matching audience should raise InvalidAudienceError."""
    private_key, _ = rsa_key_pair
    token, _ = make_token(private_key, kid, overrides={"aud": ["wrong-client-id"]})

    with patch.object(OIDCTokenValidator, "_get_jwks", new=AsyncMock(return_value=jwks)):
        with pytest.raises(jwt.exceptions.InvalidAudienceError):
            await validator.validate(token)


@pytest.mark.asyncio
async def test_wrong_issuer(validator, rsa_key_pair, jwks, kid):
    """A token from a different issuer should raise InvalidIssuerError."""
    private_key, _ = rsa_key_pair
    token, _ = make_token(private_key, kid, overrides={"iss": "https://evil.example.com/"})

    with patch.object(OIDCTokenValidator, "_get_jwks", new=AsyncMock(return_value=jwks)):
        with pytest.raises(jwt.exceptions.InvalidIssuerError):
            await validator.validate(token)


@pytest.mark.asyncio
async def test_tampered_signature(validator, rsa_key_pair, jwks, kid):
    """A token with a tampered signature should raise DecodeError or InvalidSignatureError."""
    private_key, _ = rsa_key_pair
    token, _ = make_token(private_key, kid)
    header, payload, _ = token.split(".")
    tampered_token = f"{header}.{payload}.invalidsignature"

    with patch.object(OIDCTokenValidator, "_get_jwks", new=AsyncMock(return_value=jwks)):
        with pytest.raises((jwt.exceptions.DecodeError, jwt.exceptions.InvalidSignatureError)):
            await validator.validate(tampered_token)


@pytest.mark.asyncio
async def test_unknown_kid(validator, rsa_key_pair, jwks, kid):
    """A token whose kid doesn't match any key in the JWKS should raise PyJWKSetError."""
    private_key, _ = rsa_key_pair
    token, _ = make_token(private_key, "unknown-kid-999")

    with patch.object(OIDCTokenValidator, "_get_jwks", new=AsyncMock(return_value=jwks)):
        with pytest.raises(jwt.exceptions.PyJWKSetError):
            await validator.validate(token)


@pytest.mark.asyncio
async def test_token_signed_with_wrong_key(validator, jwks, kid):
    """A token signed with a different private key should fail signature verification."""
    different_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token, _ = make_token(different_private_key, kid)

    with patch.object(OIDCTokenValidator, "_get_jwks", new=AsyncMock(return_value=jwks)):
        with pytest.raises((jwt.exceptions.InvalidSignatureError, jwt.exceptions.DecodeError)):
            await validator.validate(token)
