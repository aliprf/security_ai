from __future__ import annotations

import json

from langchain.schema import AIMessage, HumanMessage
from langchain.tools import BaseTool
from langchain_openai import ChatOpenAI
from pydantic import PrivateAttr

from commons.incident_context import IncidentContext
from commons.logger import get_logger
from utilities.embedding_search import search_intrusion_embedding

logger = get_logger(__name__)


class IdentifyRelevantInstructionsTool(BaseTool):
    name: str = "identify_relevant_instructions"
    description: str = f"""
    Identifies the most relevant response instructions for a cybersecurity incident.
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

            top_instructions = search_intrusion_embedding(
                query=incident.model_dump_json(),
            )
            if not top_instructions:
                return "No relevant instructions found."

            instruction_block = "\n\n".join(
                [
                    f"IntrusionSet #{i + 1} (score={score:.4f}):\n{inst}"
                    for i, (inst, score) in enumerate(top_instructions)
                ],
            )

            prompt = f"""
You are a cybersecurity analyst reviewing an incident.

Here is the structured incident context:
{incident.model_dump_json(indent=2)}

And here are candidate instructions retrieved from a semantic search:
{instruction_block}

From these, select the most relevant instructions (1 to 3)
that best respond to the incident.

**IMPORTANT**:
- Given the 'incident', and the relevant 'intrusion sets', deeply analyze if these
intrusions are relevant or not. Provide a human friendly report in a bullte format.
"""
            response = self._llm([HumanMessage(content=prompt)])

            if (
                isinstance(response, list)
                and response
                and isinstance(response[0], AIMessage)
            ):
                return str(response[0].content)
            if isinstance(response, AIMessage):
                return str(response.content)

        except json.JSONDecodeError as e:
            msg = f"Invalid JSON input: {e}"
            logger.warning(msg)
            return f"Unable to parse incident context JSON: {e}"
        except Exception as e:  # noqa: BLE001
            msg = f"IdentifyRelevantInstructionsTool failed: {e}"
            logger.warning(
                msg,
                exc_info=True,
            )
            return f"Unable to identify relevant instructions due to an error: {e}"
        else:
            logger.warning("Unexpected LLM response format")
            return "Failed to identify relevant instructions."
