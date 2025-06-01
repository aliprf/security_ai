# security_analyzer_agent.py

from langchain.agents import Tool, initialize_agent
from langchain_openai import ChatOpenAI

from agents.tools.identify_relevant_attack_patterns import (
    IdentifyRelevantAttackPatternsTool,
)
from agents.tools.identify_relevant_cves import IdentifyRelevantCVEsTool
from agents.tools.identify_relevant_intrusions import IdentifyRelevantInstructionsTool
from agents.tools.parse_incident import ParseIncidentContextTool
from commons.logger import get_logger

logger = get_logger(__name__)


class SecurityAnalyzerAgent:
    def __init__(self, llm: ChatOpenAI):
        self.llm = llm
        self.agent = self._build_agent()

    def _build_agent(self):
        parse_tool = ParseIncidentContextTool()
        instruction_tool = IdentifyRelevantInstructionsTool(llm=self.llm)
        cve_tool = IdentifyRelevantCVEsTool(llm=self.llm)
        attack_pattern_tool = IdentifyRelevantAttackPatternsTool(llm=self.llm)

        tools = [
            Tool(
                name=parse_tool.name,
                func=parse_tool.run,
                description="""
                Use this tool FIRST.

                Input: A raw incident in JSON format.
                Output: A structured context object describing the incident
                        (assets, attack vector, scope).

                This prepares the input for all other analysis tools.
                """,
            ),
            Tool(
                name=instruction_tool.name,
                func=instruction_tool.run,
                description="""
                Use this tool AFTER parsing the incident.

                Input: Structured context of the incident.
                Output: A list of relevant intrusion set instructions
                        that match the incident context.
                """,
            ),
            Tool(
                name=cve_tool.name,
                func=cve_tool.run,
                description="""
                Use this tool AFTER parsing the incident.

                Input: Structured context of the incident.
                Output: A list of known CVEs (Common Vulnerabilities and Exposures)
                        relevant to the scenario.
                """,
            ),
            Tool(
                name=attack_pattern_tool.name,
                func=attack_pattern_tool.run,
                description="""
                Use this tool AFTER parsing the incident.

                Input: Structured context of the incident.
                Output: A list of relevant MITRE ATT&CK patterns (TTPs)
                        matching the attack behavior.
                """,
            ),
        ]

        return initialize_agent(
            tools=tools,
            llm=self.llm,
            agent_type="zero-shot-react-description",
            verbose=True,
        )

    def analyze(self, raw_incident: str) -> str:
        prompt = f"""
You are a Security Incident Analysis Agent.

You will receive a JSON-formatted incident report. Follow these steps:
1. Use the `parse_incident_context` tool to
    convert the raw input into structured context.
2. Use the structured context to:
    - Find relevant intrusion instructions.
    - Identify matching CVEs (known vulnerabilities).
    - Map the incident to known MITRE ATT&CK patterns.

Return a clear, professional explanation that summarizes:
- The structured understanding of the incident.
- Key vulnerabilities and likely techniques involved.
- Any associated threat actor behaviors.

Here is the incident to analyze:

{raw_incident}
"""
        return self.agent.run(prompt)
