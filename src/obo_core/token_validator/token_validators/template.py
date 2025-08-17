from typing import Literal

from ..schema.token_validator_type import TokenValidatorType
from ..schema.validated_token import ValidatedOIDCClaims
from .base import TokenValidatorBase


class TemplateTokenValidator(TokenValidatorBase[ValidatedOIDCClaims]):
    """
    Validates a JWT from an OIDC provider
    and returns a ValidatedOIDCClaims model.
    """

    type: Literal[TokenValidatorType.TEMPLATE] = TokenValidatorType.TEMPLATE

    async def validate(self, token: str) -> ValidatedOIDCClaims:
        raise NotImplementedError()
