# security_analysis_pipeline.py

from typing import TypedDict, cast

from langchain_core.runnables import RunnableLambda
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph

from agents.security_analyzer import SecurityAnalyzerAgent
from agents.tools.security_reporter import SecurityReporterTool
from commons.logger import get_logger
from config import Config

logger = get_logger(__name__)


class PipelineState(TypedDict):
    input: str


class SecurityAnalysisPipeline:
    def __init__(self, model_name: str, temperature: float = 0.2):
        self.llm = ChatOpenAI(model=model_name, temperature=temperature)
        self.analyzer = SecurityAnalyzerAgent(
            model_name=model_name,
            temperature=temperature,
        )
        self.reporter = SecurityReporterTool(llm=self.llm)
        self.graph = self._build_graph()

    def _build_graph(self):
        def run_analysis(state: PipelineState) -> PipelineState:
            return {"input": self.analyzer.analyze(state["input"])}

        def run_reporting(state: PipelineState) -> str:
            return self.reporter.run(state["input"])

        workflow = StateGraph(PipelineState)

        workflow.add_node("SecurityAnalysis", RunnableLambda(run_analysis))
        workflow.add_node("SecurityReport", RunnableLambda(run_reporting))
        workflow.set_entry_point("SecurityAnalysis")
        workflow.add_edge("SecurityAnalysis", "SecurityReport")
        workflow.set_finish_point("SecurityReport")

        return workflow.compile()

    def run(self, raw_incident: str) -> str:
        result = cast("dict", self.graph.invoke({"input": raw_incident}))
        return result["input"]


if __name__ == "__main__":
    analyzer = SecurityAnalyzerAgent(model_name=Config.get_model_name())
    raw_incident_json_string = """{
        "incident_id": "INC-2023-08-01-001",
        "timestamp": "2023-08-01T09:15:00Z",
        "title": "Unauthorized Access Attempt on VPN Gateway",
        "description": "Multiple failed login attempts followed by a successful
                        connection from an unusual geographic location
                        on the main VPN gateway.",
        "affected_assets": [
            {
            "hostname": "vpn-gateway-01",
            "ip_address": "203.0.113.1",
            "os": "Cisco IOS XE",
            "installed_software": [
                {"name": "Cisco IOS XE", "version": "17.3.4a"}
            ],
            "role": "VPN Gateway"
            }
        ],
        "observed_ttps": [
            {"framework": "MITRE ATT&CK", "id": "T1110", "name": "Brute Force"},
            {"framework": "MITRE ATT&CK", "id": "T1078", "name": "Valid Accounts"}
        ],
        "indicators_of_compromise": [
            {"type": "ip_address", "value": "172.91.8.123",
                "context": "Source IP of successful login"},
            {"type": "username", "value": "admin",
            "context": "Account used for successful login"}
        ],
        "initial_findings": "Credential stuffing or
                        brute force attack successful against VPN."
    }"""

    pipeline = SecurityAnalysisPipeline(model_name=Config.get_model_name())
    report = pipeline.run(raw_incident_json_string)
    logger.info(report)
