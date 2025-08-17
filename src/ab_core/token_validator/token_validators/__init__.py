from typing import Annotated, Union

from pydantic import Discriminator

from .oidc import OIDCTokenValidator
from .template import TemplateTokenValidator

TokenValidator = Annotated[
    Union[
        OIDCTokenValidator,
        TemplateTokenValidator,
    ],
    Discriminator("type"),
]
