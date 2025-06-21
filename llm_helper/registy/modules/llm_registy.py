from llm_helper.models.llama import LLaMA


class LLMRegistry:
    def __init__(self):
        self._llms = {
            "llama": LLaMA(),
        }

    def list_models(self) -> list[str]:
        """List all available models."""
        return list(self._llms.keys())

    def get(self, name: str)-> : 
        """Get a model by its name."""
        return self._llms[name]
