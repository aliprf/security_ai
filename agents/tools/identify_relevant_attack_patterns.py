from __future__ import annotations

import json

from langchain.schema import AIMessage, HumanMessage
from langchain.tools import BaseTool
from langchain_openai import ChatOpenAI

from commons.incident_context import IncidentContext
from commons.logger import get_logger
from utilities.embedding_search import search_attack_embedding

logger = get_logger(__name__)


class IdentifyRelevantAttackPatternsTool(BaseTool):
    name = "identify_relevant_attack_patterns"
    description = f"""
    Identifies the most relevant ATT&CK patterns for a cybersecurity incident.
    Input should match the following JSON schema:
    {IncidentContext.model_json_schema()}
    """

    def __init__(self, llm: ChatOpenAI, **kwargs):
        super().__init__(**kwargs)
        self.llm = llm

    def _run(self, raw_incident: str) -> str:
        try:
            js_incident = json.loads(raw_incident)
            incident = IncidentContext(**js_incident)

            top_patterns = search_attack_embedding(
                query=incident.model_dump_json(),
            )
            if not top_patterns:
                return "No relevant attack patterns found."

            pattern_block = "\n\n".join(
                [
                    f"AttackPattern #{i + 1} (score={score:.4f}):\n{pattern}"
                    for i, (pattern, score) in enumerate(top_patterns)
                ],
            )

            prompt = f"""
You are a cybersecurity analyst reviewing an incident.

Here is the structured incident context:
{incident.model_dump_json(indent=2)}

And here are candidate attack patterns retrieved from a semantic search:
{pattern_block}

From these, select the most relevant ATT&CK patterns (1 to 3)
that best describe the tactics or techniques involved in this incident.

**IMPORTANT**:
- Analyze the alignment between the observed behavior and the ATT&CK patterns.
- Provide a bullet-point analysis explaining the relevance of each selected pattern.
"""
            response = self.llm([HumanMessage(content=prompt)])

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
            msg = f"IdentifyRelevantAttackPatternsTool failed: {e}"
            logger.warning(msg, exc_info=True)
            return f"Unable to identify relevant attack patterns due to an error: {e}"

        logger.warning("Unexpected LLM response format")
        return "Failed to identify relevant attack patterns."
