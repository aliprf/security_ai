from abc import ABC, abstractmethod


class IRegistry(ABC):
    @abstractmethod
    def get_llm(self, name: str): ...

    @abstractmethod
    def get_chat_model(self, name: str): ...

    @abstractmethod
    def get_mcp(self, name: str): ...
