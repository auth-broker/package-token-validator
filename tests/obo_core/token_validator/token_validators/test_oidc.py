from unittest.mock import AsyncMock, patch

import pytest
from uuid_extensions import uuid7  # just to generate a fake sub/id

from obo_core.token_validator.token_validators.oidc import OIDCTokenValidator


@pytest.mark.asyncio
async def test_oidc_token_validator():
    """Ensure `validate()` returns a typed claims model when everything lines up."""

    # ── Arrange ──────────────────────────────────────────────────────────
    validator = OIDCTokenValidator(
        issuer="https://issuer.example.com/",
        jwks_uri="https://issuer.example.com/jwks",
        audience=["my-client-id"],
        algorithms=["RS256"],
    )

    dummy_token = "header.payload.signature"
    dummy_claims = {
        "iss": "https://issuer.example.com/",
        "sub": str(uuid7()),
        "aud": ["my-client-id"],
        "iat": 1_700_000_000,
        "exp": 1_800_000_000,
        # required by ValidatedOIDCClaims
        "auth_time": 1_700_000_000,
        "acr": "urn:mace:incommon:iap:silver",
        # optional extras (not required, but realistic)
        "email": "user@example.com",
        "email_verified": True,
        "name": "Test User",
        "given_name": "Test",
        "preferred_username": "tuser",
        "nickname": "tester",
        "groups": ["admins", "devs"],
    }

    # ── Patch internals so no external call / crypto is performed ────────
    with (
        patch.object(
            OIDCTokenValidator,
            "_get_jwks",
            new=AsyncMock(return_value={"keys": [{"kid": "test-kid"}]}),
        ),
        patch(
            "obo_core.token_validator.token_validators.oidc.jwt.get_unverified_header",
            return_value={"kid": "test-kid"},
        ) as mock_get_header,
        patch(
            "obo_core.token_validator.token_validators.oidc.jwt.decode",
            return_value=dummy_claims,
        ) as mock_jwt_decode,
    ):
        # ── Act ─────────────────────────────────────────────────────────
        validated = await validator.validate(dummy_token)

        # ── Assert ──────────────────────────────────────────────────────
        mock_get_header.assert_called_once_with(dummy_token)
        mock_jwt_decode.assert_called_once()

        # `validate` should return the validated-claims Pydantic model
        assert validated.iss == "https://issuer.example.com/"
        assert validated.aud == ["my-client-id"]
        assert validated.sub == dummy_claims["sub"]
        assert validated.auth_time == dummy_claims["auth_time"]
        assert validated.acr == dummy_claims["acr"]
