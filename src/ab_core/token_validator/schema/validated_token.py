"""Validated token models and schemas."""

from pydantic import BaseModel, ConfigDict, Field


class AKProxyUserAttributes(BaseModel):
    """Authentik proxy user attributes, typically set via user/group attribute policies."""

    model_config = ConfigDict(extra="allow")


class AKProxy(BaseModel):
    """Authentik-specific proxy metadata injected into tokens by the ak_proxy scope."""

    model_config = ConfigDict(extra="allow")

    user_attributes: AKProxyUserAttributes = Field(
        default_factory=AKProxyUserAttributes,
        title="User Attributes",
        description="Arbitrary key-value attributes from the Authentik user or group policy.",
    )
    is_superuser: bool = Field(
        default=False,
        title="Is Superuser",
        description="Whether the authenticated user has superuser/admin privileges in Authentik.",
    )


class ValidatedOIDCClaims(BaseModel):
    """Validated claims from an OIDC JWT issued by Authentik.

    Covers standard OIDC claims (RFC 7519 / OIDC Core 1.0) as well as
    Authentik-specific extensions such as `ak_proxy`, `entitlements`, and `roles`.
    """

    model_config = ConfigDict(extra="allow")

    # ── Standard JWT claims (RFC 7519) ────────────────────────────────────────

    iss: str = Field(
        title="Issuer",
        description="Identifies the principal that issued the JWT. Typically the Authentik application URL.",
    )
    sub: str = Field(
        title="Subject",
        description="Unique identifier for the authenticated user or service account within the issuer.",
    )
    aud: str | list[str] = Field(
        title="Audience",
        description="Intended recipient(s) of the token. Must match one of the configured client IDs.",
    )
    exp: int = Field(
        title="Expiration Time",
        description="Unix timestamp after which the token must not be accepted.",
    )
    iat: int = Field(
        title="Issued At",
        description="Unix timestamp at which the token was issued.",
    )

    # ── OIDC Core claims ──────────────────────────────────────────────────────

    auth_time: int = Field(
        title="Authentication Time",
        description="Unix timestamp when the end-user authentication occurred.",
    )
    acr: str = Field(
        title="Authentication Context Class Reference",
        description=(
            "Identifies the authentication context class. "
            "Authentik uses 'goauthentik.io/providers/oauth2/default' by default."
        ),
    )

    # ── OIDC profile claims (optional) ────────────────────────────────────────

    name: str | None = Field(
        default=None,
        title="Full Name",
        description="Full name of the authenticated user.",
    )
    given_name: str | None = Field(
        default=None,
        title="Given Name",
        description="Given (first) name of the authenticated user.",
    )
    preferred_username: str | None = Field(
        default=None,
        title="Preferred Username",
        description="Shorthand name the user prefers to be referred to, typically the Authentik username.",
    )
    nickname: str | None = Field(
        default=None,
        title="Nickname",
        description="Casual name of the user, may differ from preferred_username.",
    )

    # ── OIDC email claims (optional) ──────────────────────────────────────────

    email: str | None = Field(
        default=None,
        title="Email Address",
        description="Primary email address of the authenticated user.",
    )
    email_verified: bool | None = Field(
        default=None,
        title="Email Verified",
        description="Whether the user's email address has been verified. Authentik sets this to false by default.",
    )

    # ── Authorisation claims ──────────────────────────────────────────────────

    entitlements: list[str] = Field(
        default_factory=list,
        title="Entitlements",
        description=(
            "Application-level permissions granted to this token, populated via Authentik scope mappings. "
            "Follows RFC 9068 / SCIM schema conventions (e.g. 'read:me', 'write:token_issuer')."
        ),
    )
    roles: list[str] = Field(
        default_factory=list,
        title="Roles",
        description="Roles assigned to the user, as emitted by Authentik role/scope mappings.",
    )
    groups: list[str] = Field(
        default_factory=list,
        title="Groups",
        description=(
            "Authentik groups the user belongs to. Informational — authorisation should use entitlements or roles."
        ),
    )

    # ── Authentik-specific claims ─────────────────────────────────────────────

    ak_proxy: AKProxy | None = Field(
        default=None,
        title="Authentik Proxy Metadata",
        description=(
            "Authentik-specific metadata injected when using the ak_proxy scope, "
            "including user attributes and superuser status."
        ),
    )
