
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel


class BaseParseTool(ABC):
    @abstractmethod
    @classmethod
    def get_input_schema(cls) -> dict[str, Any]:
        ...

    @abstractmethod
    @classmethod
    def get_output_schema(cls) -> dict[str, Any]:
        ...

    @abstractmethod
    def execute(self, data: dict[str, Any]) -> BaseModel:
        ...
