import json

from langchain.schema import AIMessage

from agents.tools.identify_relevant_intrusions import IdentifyRelevantInstructionsTool


# Minimal mock LLM for the test
class MockLLM:
    def __call__(self, messages):
        return [AIMessage(content="Mocked LLM response with relevant instructions")]


def test_identify_relevant_instructions_tool_with_mockllm():
    raw_incident_json_string = json.dumps({
        "incident_id": "INC-2025-05-31-002",
        "timestamp": "2025-05-31T15:00:00Z",
        "summary": "Unauthorized data exfiltration attempt",
        "description": "Unusual outbound traffic detected from critical database server.",
        "affected_assets": [
            {
                "name": "db-server-01",
                "ip": "10.0.0.5",
                "os": "Windows Server 2019",
                "software": [{"name": "SQL Server", "version": "2017"}],
                "role": "Database Server",
            },
        ],
        "observed_ttps": ["T1041", "T1071"],
        "ioc_ips": ["198.51.100.77"],
        "ioc_usernames": ["dbadmin"],
        "inferred_software": ["SQL Server", "Wireshark"],
        "inferred_cves": ["CVE-2018-1234"],
        "initial_findings": "Potential data exfiltration using unauthorized channels.",
    })

    tool = IdentifyRelevantInstructionsTool(llm=MockLLM())
    result = tool._run(raw_incident_json_string)

    assert result
