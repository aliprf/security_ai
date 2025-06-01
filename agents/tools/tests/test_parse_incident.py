import json

from agents.tools.parse_incident import ParseIncidentContextTool
from commons.incident_context import IncidentContext


def test_parse_incident_context_tool():
    dummy_incident_dict = {
        "incident_id": "INC001",
        "timestamp": "2024-06-01T12:00:00Z",
        "title": "Unauthorized Access Detected",
        "description": "Suspicious login activity was detected.",
        "affected_assets": [
            {
                "hostname": "db-server-01",
                "ip_address": "192.168.1.10",
                "os": "Ubuntu 20.04",
                "installed_software": [
                    {"name": "PostgreSQL", "version": "13.3"},
                    {"name": "Nginx", "version": "1.18.0"},
                ],
                "role": "database",
            },
        ],
        "observed_ttps": [{"id": "T1078"}, {"id": "T1021"}],
        "indicators_of_compromise": [
            {"type": "ip_address", "value": "192.168.1.100"},
            {"type": "username", "value": "attacker"},
        ],
        "initial_findings": "Suspicious login to the DB server from external IP.",
    }

    raw_incident_json = json.dumps(dummy_incident_dict)

    # Act
    tool = ParseIncidentContextTool()
    result_json = tool._run(raw_incident_json)
    result = IncidentContext.model_validate_json(result_json)

    # Assert
    assert result.incident_id == "INC001"
    assert result.affected_assets[0].name == "db-server-01"
    assert result.affected_assets[0].software[0].name == "PostgreSQL"
    assert result.observed_ttps == ["T1078", "T1021"]
    assert result.ioc_ips == ["192.168.1.100"]
    assert result.ioc_usernames == ["attacker"]
    assert result.inferred_software == ["PostgreSQL 13.3", "Nginx 1.18.0"]
