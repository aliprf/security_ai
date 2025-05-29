from __future__ import annotations

from pydantic import BaseModel, Field


# --- Description Section
class DescriptionData(BaseModel):
    lang: str = Field(...)
    value: str = Field(...)


class Description(BaseModel):
    description_data: list[DescriptionData] = Field(..., alias="description_data")


# --- Reference Section
class ReferenceData(BaseModel):
    url: str = Field(...)
    name: str = Field(...)
    refsource: str = Field(...)
    tags: list[str] = Field(...)


class References(BaseModel):
    reference_data: list[ReferenceData] = Field(..., alias="reference_data")


# --- ProblemType Section
class ProblemTypeDescription(BaseModel):
    lang: str | None = Field(default=None)
    value: str | None = Field(default=None)


class ProblemTypeData(BaseModel):
    description: list[ProblemTypeDescription] = Field(...)


class ProblemType(BaseModel):
    problemtype_data: list[ProblemTypeData] = Field(..., alias="problemtype_data")


# --- CVE Meta Info
class CVEDataMeta(BaseModel):
    id: str = Field(..., alias="ID")
    assigner: str = Field(..., alias="ASSIGNER")


# --- Main CVE Content
class CVE(BaseModel):
    data_type: str = Field(..., alias="data_type")
    data_format: str = Field(..., alias="data_format")
    data_version: str = Field(..., alias="data_version")
    cve_data_meta: CVEDataMeta = Field(..., alias="CVE_data_meta")
    problem_type: ProblemType = Field(..., alias="problemtype")
    references: References = Field(...)
    description: Description = Field(...)


# --- Configurations Section
class CPEMatch(BaseModel):
    vulnerable: bool = Field(...)
    cpe23_uri: str = Field(..., alias="cpe23Uri")
    version_start_including: str | None = Field(
        default=None, alias="versionStartIncluding",
    )
    version_end_including: str | None = Field(default=None, alias="versionEndIncluding")
    version_start_excluding: str | None = Field(
        default=None, alias="versionStartExcluding",
    )
    version_end_excluding: str | None = Field(default=None, alias="versionEndExcluding")
    cpe_name: list[str] | None = Field(default=None, alias="cpe_name")


class Node(BaseModel):
    operator: str | None = Field(default="OR")
    negate: bool | None = Field(default=False)
    children: list[Node] | None = Field(default=[])
    cpe_match: list[CPEMatch] = Field(..., alias="cpe_match")


class Configuration(BaseModel):
    cve_data_version: str = Field(..., alias="CVE_data_version")
    nodes: list[Node] = Field(...)


# --- Impact Section
class CVSSv3(BaseModel):
    version: str = Field(...)
    vector_string: str = Field(..., alias="vectorString")
    attack_vector: str = Field(..., alias="attackVector")
    attack_complexity: str = Field(..., alias="attackComplexity")
    privileges_required: str = Field(..., alias="privilegesRequired")
    user_interaction: str = Field(..., alias="userInteraction")
    scope: str = Field(...)
    confidentiality_impact: str = Field(..., alias="confidentialityImpact")
    integrity_impact: str = Field(..., alias="integrityImpact")
    availability_impact: str = Field(..., alias="availabilityImpact")
    base_score: float = Field(..., alias="baseScore")
    base_severity: str = Field(..., alias="baseSeverity")


class BaseMetricV3(BaseModel):
    cvss_v3: CVSSv3 = Field(..., alias="cvssV3")
    exploitability_score: float | None = Field(
        default=None, alias="exploitabilityScore",
    )
    impact_score: float | None = Field(default=None, alias="impactScore")


class Impact(BaseModel):
    base_metric_v3: BaseMetricV3 | None = Field(default=None, alias="baseMetricV3")


# --- Root CVE Item
class CVEItem(BaseModel):
    cve: CVE = Field(...)
    configurations: Configuration = Field(...)
    impact: Impact = Field(...)
    published_date: str = Field(..., alias="publishedDate")
    last_modified_date: str | None = Field(default=None, alias="lastModifiedDate")
