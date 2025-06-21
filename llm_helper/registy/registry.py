from llm_helper.registy.modules.chat_models_registry import ChatModelRegistry
from llm_helper.registy.modules.llm_registy import LLMRegistry
from llm_helper.registy.modules.mcp_registry import MCPRegistry
from llm_helper.registy.registry_interface import IRegistry


class Registry(IRegistry):
    def __init__(self):
        self._llm_registry = LLMRegistry()
        self._chat_registry = ChatModelRegistry()
        self._mcp_registry = MCPRegistry()

    def get_llm(self, name: str):
        return self._llm_registry.get(name)

    def get_chat_model(self, name: str):
        return self._chat_registry.get(name)

    def get_mcp(self, name: str):
        return self._mcp_registry.get(name)
