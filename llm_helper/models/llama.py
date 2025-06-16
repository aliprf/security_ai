from enum import Enum
from typing import Any

from langchain_core.runnables import Runnable, RunnableLambda
from langchain_ollama.llms import OllamaLLM

from commons.logger import get_logger
from llm_helper.chat_model.conversational_chat_model import (
    AIChatMessages,
    AIChatModel,
    Role,
)

logger = get_logger(__name__)


class LlamaModel(str, Enum):
    llama3_1_8b_chat = "llama3.1:8b"


class LLaMA:
    def __init__(
        self,
        model_name: str = LlamaModel.llama3_1_8b_chat,
        temperature: float = 0.1,
    ) -> None:
        """_Create the model from name.

        Args:
            model_name (str, optional): _description
            Defaults to LlamaModel.llama3_1_8b_chat.
            temperature (float, optional): _description_. Defaults

        """
        self.model = OllamaLLM(model=model_name, temperature=temperature)

    def _create_template(self, prompt: str, instruction: str) -> str:
        """Create a template for the model.

        Args:
            prompt (str): _description_
            instruction (str): _description_

        Returns:
            str: _description_

        """
        template = AIChatMessages(
            messages=[
                AIChatModel(role=Role.human, message=prompt),
                AIChatModel(role=Role.system, message=instruction),
            ],
        )
        str_template = ""
        for temp in template.messages:
            str_template += f"{temp.role}: {temp.message}\n"
        return str_template

    def chat(self, prompt: str, instruction: str) -> str:
        """Generate a response from the model given prompt and instruction.

        Args:
            prompt (str): User prompt.
            instruction (str): Instruction to guide the response.

        Returns:
            str: Model-generated response.

        """
        template = self._create_template(prompt=prompt, instruction=instruction)

        input_chain: Runnable[dict[str, Any], str] = RunnableLambda(lambda _: template)
        chain: Runnable[dict[str, Any], str] = input_chain | self.model

        return chain.invoke({})


if __name__ == "__main__":
    llm = LLaMA(model_name=LlamaModel.llama3_1_8b_chat)
    answer = llm.chat(
        prompt="What is the capital of France?",
        instruction="""
        you are a helpful assistant. deeply think and answer the question.
        - answer must be consicent with the context provided in the prompt
        - if it does not match, please explain why and provide
        """,
    )
    logger.info(answer)
