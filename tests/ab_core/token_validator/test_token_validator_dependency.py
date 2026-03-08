"""Tests for token validator dependency injection."""

import os
from typing import Annotated
from unittest.mock import patch

from ab_core.dependency import Depends, inject
from ab_core.token_validator.token_validators import OIDCTokenValidator, TokenValidator

ISSUER_1 = "https://issuer.example.com/"
ISSUER_2 = "https://issuer-n8n.example.com/"

ISSUERS_JSON = (
    "["
    f'{{"issuer":"{ISSUER_1}","jwks_uri":"{ISSUER_1}jwks","audience":["my-client-id"]}},'
    f'{{"issuer":"{ISSUER_2}","jwks_uri":"{ISSUER_2}jwks","audience":["n8n-client-id"]}}'
    "]"
)


def test_token_validator_dependency():
    """Test that the token validator can be injected as a dependency."""
    with patch.dict(
        os.environ,
        {
            "TOKEN_VALIDATOR_TYPE": "OIDC",
            "TOKEN_VALIDATOR_OIDC_ISSUERS": ISSUERS_JSON,
            "TOKEN_VALIDATOR_OIDC_ALGORITHMS": '["RS256","ES256"]',
        },
        clear=False,
    ):

        @inject
        def some_func(
            token_validator: Annotated[TokenValidator, Depends(TokenValidator, persist=True)],
        ):
            return token_validator

        validator_instance = some_func()

        # Assert correct type
        assert isinstance(validator_instance, OIDCTokenValidator)

        # Assert issuers loaded correctly
        assert len(validator_instance.issuers) == 2

        issuer_1 = validator_instance.issuers[0]
        assert str(issuer_1.issuer) == ISSUER_1
        assert str(issuer_1.jwks_uri) == f"{ISSUER_1}jwks"
        assert issuer_1.audience == ["my-client-id"]

        issuer_2 = validator_instance.issuers[1]
        assert str(issuer_2.issuer) == ISSUER_2
        assert str(issuer_2.jwks_uri) == f"{ISSUER_2}jwks"
        assert issuer_2.audience == ["n8n-client-id"]

        # Assert issuer map is built correctly
        assert ISSUER_1 in validator_instance._issuer_map
        assert ISSUER_2 in validator_instance._issuer_map

        # Assert algorithms loaded correctly
        assert validator_instance.algorithms == ["RS256", "ES256"]

        # Assert defaults
        assert validator_instance.verify_signature is True
        assert validator_instance.verify_aud is True
        assert validator_instance.verify_exp is True
        assert validator_instance.require_aud is False
        assert validator_instance.leeway == 0
