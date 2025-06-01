# test_identify_relevant_attack_patterns.py


from agents.tools.identify_relevant_attack_patterns import (
    IdentifyRelevantAttackPatternsTool,
)
from agents.tools.tests.mocks import MockLLM


def test_identify_relevant_attack_patterns_pipeline_with_mockllm():
    raw_incident_json_string = """{
    "incident_id": "INC-2023-08-01-001",
    "timestamp": "2023-08-01T09:15:00Z",
    "title": "Unauthorized Access Attempt on VPN Gateway",
    "description": "Multiple failed login attempts followed by a successful connection from an unusual geographic location on the main VPN gateway.",
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
        {
            "type": "ip_address",
            "value": "172.91.8.123",
            "context": "Source IP of successful login"
        },
        {
            "type": "username",
            "value": "admin",
            "context": "Account used for successful login"
        }
    ],
    "initial_findings": "Credential stuffing or brute force attack successful against VPN."
}"""

    tool = IdentifyRelevantAttackPatternsTool(llm=MockLLM())
    result = tool._run(raw_incident_json_string)

    assert result
