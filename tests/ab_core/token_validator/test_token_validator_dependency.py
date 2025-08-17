import os
from typing import Annotated
from unittest.mock import patch

from ab_core.dependency import Depends, inject
from ab_core.token_validator.token_validators import OIDCTokenValidator, TokenValidator


def test_token_validator_dependency():
    with patch.dict(
        os.environ,
        {
            "TOKEN_VALIDATOR_TYPE": "OIDC",
            "TOKEN_VALIDATOR_OIDC_ISSUER": "https://issuer.example.com",
            "TOKEN_VALIDATOR_OIDC_JWKS_URI": "https://issuer.example.com/jwks",
            "TOKEN_VALIDATOR_OIDC_AUDIENCE": "my-client-id",
            "TOKEN_VALIDATOR_OIDC_ALGORITHMS": '["RS256","ES256"]',
        },
        clear=False,
    ):
        # test function
        @inject
        def some_func(
            token_validator: Annotated[TokenValidator, Depends(TokenValidator, persist=True)],
        ):
            return token_validator

        validator_instance = some_func()

        # Assert that the returned dependency is of the expected type
        assert isinstance(validator_instance, OIDCTokenValidator)
        # And that it loaded values from the env
        assert str(validator_instance.issuer) == "https://issuer.example.com/"
        assert str(validator_instance.jwks_uri) == "https://issuer.example.com/jwks"
        assert validator_instance.audience == ["my-client-id"]
        assert validator_instance.algorithms == ["RS256", "ES256"]
