from typing import Annotated

from pydantic import Discriminator

from .oidc import OIDCTokenValidator
from .template import TemplateTokenValidator

TokenValidator = Annotated[
    OIDCTokenValidator | TemplateTokenValidator,
    Discriminator("type"),
]
