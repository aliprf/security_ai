from typing import Any

from pydantic import BaseModel

from commons.incident_context import AssetInfo, IncidentContext, SoftwareInfo
from tools.base_parse_tool import BaseParseTool


class ParseIncident(BaseParseTool):
    @classmethod
    def get_input_schema(cls) -> dict[str, Any]:
        return {}  # to do

    @classmethod
    def get_output_schema(cls) -> dict[str, Any]:
        return IncidentContext.model_json_schema()

    def execute(self, data: dict[str, Any]) -> BaseModel:
        return self._parse_incident(raw=data)

    def _parse_incident(self, raw: dict[str, Any]) -> IncidentContext:  # noqa: PLR6301
        assets = []
        inferred_software = []

        for asset in raw.get("affected_assets", []):
            software_list = [
                SoftwareInfo(name=sw["name"], version=sw.get("version"))
                for sw in asset.get("installed_software", [])
            ]
            inferred_software.extend([
                f"{sw.name} {sw.version}" for sw in software_list if sw.version
            ])

            assets.append(
                AssetInfo(
                    name=asset.get("hostname"),
                    ip=asset.get("ip_address"),
                    os=asset.get("os"),
                    software=software_list,
                    role=asset.get("role"),
                ),
            )

        return IncidentContext(
            incident_id=raw.get("incident_id", ""),
            timestamp=raw.get("timestamp"),
            summary=raw.get("title", ""),
            description=raw.get("description", ""),
            affected_assets=assets,
            observed_ttps=[ttp["id"] for ttp in raw.get("observed_ttps", [])],
            ioc_ips=[
                ioc["value"]
                for ioc in raw.get("indicators_of_compromise", [])
                if ioc["type"] == "ip_address"
            ],
            ioc_usernames=[
                ioc["value"]
                for ioc in raw.get("indicators_of_compromise", [])
                if ioc["type"] == "username"
            ],
            inferred_software=inferred_software,
            inferred_cves=[],  # Populated later
            initial_findings=raw.get("initial_findings", ""),
        )
