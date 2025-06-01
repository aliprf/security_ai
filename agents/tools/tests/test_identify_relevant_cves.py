import json

from agents.tools.identify_relevant_cves import IdentifyRelevantCVEsTool
from agents.tools.tests.mocks import MockLLM


def test_identify_relevant_cves_tool_with_mockllm():
    raw_incident_json_string = json.dumps({
        "incident_id": "INC-2025-05-31-001",
        "timestamp": "2025-05-31T12:00:00Z",
        "summary": "Suspicious login activity detected",
        "description": "Multiple failed login attempts from unusual IP addresses.",
        "affected_assets": [
            {
                "name": "server-01",
                "ip": "192.168.1.10",
                "os": "Ubuntu 20.04",
                "software": [
                    {"name": "OpenSSH", "version": "8.2p1"},
                ],
                "role": "Application Server",
            },
        ],
        "observed_ttps": ["T1110", "T1078"],
        "ioc_ips": ["203.0.113.55", "198.51.100.23"],
        "ioc_usernames": ["root", "admin"],
        "inferred_software": ["OpenSSH", "Fail2Ban"],
        "inferred_cves": ["CVE-2021-1234", "CVE-2022-5678"],
        "initial_findings": "Repeated brute force attempts detected.",
    })

    tool = IdentifyRelevantCVEsTool(llm=MockLLM())

    result = tool._run(raw_incident_json_string)

    assert result
