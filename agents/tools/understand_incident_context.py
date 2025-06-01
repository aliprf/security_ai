import json

from langchain.schema import AIMessage, HumanMessage
from langchain.tools import BaseTool
from langchain_openai import ChatOpenAI
from pydantic import PrivateAttr

from commons.incident_context import IncidentContext
from commons.logger import get_logger

logger = get_logger(__name__)


class UnderstandIncidentContextTool(BaseTool):
    name: str = "understand_incident_context"
    description: str = f"""
    Converts structured incident context into a human-friendly summary.
    Input should match the following JSON schema:
    {IncidentContext.model_json_schema()}
    """
    _llm: ChatOpenAI = PrivateAttr()

    def __init__(self, llm: ChatOpenAI, **kwargs):
        super().__init__(**kwargs)
        self._llm = llm

    def _run(self, raw_incident: str) -> str:
        try:
            js_incident = json.loads(raw_incident)
            incident = IncidentContext(**js_incident)

            prompt = f"""
You are a cybersecurity analyst.
Given the following structured incident context in JSON,
write a concise human-readable report explaining:

- The nature of the incident
- Affected assets and software
- Any observed TTPs or IOCs
- Summary and initial findings

Here is the structured data:
{incident.model_dump_json(indent=2)}
"""
            response = self._llm([HumanMessage(content=prompt)])

            if isinstance(response, AIMessage):
                return str(response.content)

        except json.JSONDecodeError as e:
            msg = f"Invalid JSON input: {e}"
            logger.warning(msg)
            return f"Unable to parse incident context JSON: {e}"
        except Exception as e:  # noqa: BLE001
            msg = (
                f"""UnderstandIncidentContextTool:
                failed to parse or generate summary: {e}""",
            )
            logger.warning(
                msg,
                exc_info=True,
            )
            return (
                f"Unable to understand incident context due to an internal error: {e}"
            )
        else:
            logger.warning("Unexpected LLM response format")
            return "Failed to generate a summary from the incident context."
