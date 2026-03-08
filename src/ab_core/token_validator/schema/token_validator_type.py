"""Token validator type enumeration."""

from enum import StrEnum


class TokenValidatorType(StrEnum):
    """Enumeration of supported token validator types."""

    OIDC = "OIDC"
    TEMPLATE = "TEMPLATE"
