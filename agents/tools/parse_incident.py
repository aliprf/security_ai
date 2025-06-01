import json
from typing import Any, cast

from langchain.tools import BaseTool
from pydantic import BaseModel, Field

from commons.incident_context import AssetInfo, IncidentContext, SoftwareInfo
from commons.logger import get_logger

logger = get_logger(__name__)


class ParseIncidentContextArgs(BaseModel):
    raw_incident: str = Field(
        ...,
        description="""Raw JSON string representing the incident report.""",
    )


class ParseIncidentContextTool(BaseTool):
    name: str = "parse_incident_context"
    description: str = f"""
        This is the First tool you must use:
        This tool convert the input data, which is a raw incident in a json format to
            an instance of this JSON schema as follows:
            {IncidentContext.model_json_schema()}"""
    args_schema: Any = cast("Any", ParseIncidentContextArgs)

    def _run(self, raw_incident: str) -> str:  # noqa: PLR6301
        try:
            js_incident = json.loads(raw_incident)
            incident_context = parse_incident(js_incident)
            return incident_context.model_dump_json()
        except Exception as e:  # noqa: BLE001
            msg = f" UnderstandIncidentContextTool: failed to parse incidet: {e}"
            logger.warning(msg)
            return raw_incident


def parse_incident(raw: dict[str, Any]) -> IncidentContext:
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
