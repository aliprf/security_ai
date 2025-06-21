from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ILLM(ABC):
    @abstractmethod
    def __init__(self, model_name: str, temperature: float = 0.2) -> None:
        """Initialize the LLM with a model name and temperature.

        :param model_name: Unique model identifier or enum.
        :param temperature: Sampling temperature for output generation.
        """

    @abstractmethod
    def generate(
        self,
        prompt: str,
        instruction: str,
        output_schema: dict[str, Any] | None,
    ) -> str:
        """Generate a completion from the given prompt.

        :param prompt: Input text prompt.
        :param kwargs: Model-specific optional arguments (e.g., max_tokens).
        :return: Generated response as a string.
        """
