from abc import ABC, abstractmethod
from typing import Generic, TypeVar

from pydantic import BaseModel

ValidatedType = TypeVar("ValidatedType")


class TokenValidatorBase(BaseModel, Generic[ValidatedType], ABC):
    """
    Abstract base for any token validator.

    Generic on the validated return type.
    Also a Pydantic model, so you get:
      - field validation on init
      - .model_dump(), .model_json(), etc
    """

    @abstractmethod
    async def validate(self, token: str) -> ValidatedType:
        """
        Validate a raw token string and return a structured result.
        Should raise on failure.
        """
        ...
