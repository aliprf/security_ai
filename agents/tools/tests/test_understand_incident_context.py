from agents.tools.tests.mocks import MockLLM
from agents.tools.understand_incident_context import UnderstandIncidentContextTool


def test_understand_incident_context_tool_with_mockllm():
    # Minimal valid JSON for IncidentContext based on your schema example
    raw_incident_json = """
    {
        "incident_id": "INC-0001",
        "timestamp": "2025-05-31T12:00:00Z",
        "summary": "Unauthorized access detected",
        "description": "Multiple login failures and a successful login from unknown IP.",
        "affected_assets": [
            {
                "name": "web-server-01",
                "ip": "192.168.1.10",
                "os": "Ubuntu 20.04",
                "software": [
                    {"name": "nginx", "version": "1.18.0"}
                ],
                "role": "web server"
            }
        ],
        "observed_ttps": ["T1078", "T1110"],
        "ioc_ips": ["203.0.113.5"],
        "ioc_usernames": ["unknown_user"],
        "inferred_software": ["nginx"],
        "inferred_cves": ["CVE-2021-1234"],
        "initial_findings": "Possible brute force attack."
    }
    """

    tool = UnderstandIncidentContextTool(llm=MockLLM())
    result = tool._run(raw_incident_json)

    assert result
