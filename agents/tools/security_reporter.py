from langchain.tools import BaseTool
from langchain_openai import ChatOpenAI
from pydantic import PrivateAttr

from commons.logger import get_logger

logger = get_logger(__name__)


class SecurityReporterTool(BaseTool):
    name: str = "security_reporter"
    description: str = (
        "Summarizes analysis into issue summary, potential issues, and potential fixes."
    )
    _llm: ChatOpenAI = PrivateAttr()

    def __init__(self, llm: ChatOpenAI, **kwargs):
        super().__init__(**kwargs)
        self._llm = llm

    def _run(self, analysis_text: str) -> str:
        prompt = f"""
You are a cybersecurity reporting assistant.

Here is the full analysis from the SecurityAnalyzer:

{analysis_text}

From this, generate a professional report including:
1. Summary of the Incident
2. Potential Security Issues
3. Recommended Fixes or Mitigations
"""
        response = self._llm.invoke(prompt)
        return (
            response
            if isinstance(response, str)
            else "\n".join(str(r) for r in response)
            if isinstance(response, list)
            else str(response)
        )
