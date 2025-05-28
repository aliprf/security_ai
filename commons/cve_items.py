from __future__ import annotations

from pydantic import BaseModel, Field


# --- Description Section
class DescriptionData(BaseModel):
    lang: str = Field(...)
    value: str = Field(...)


class Description(BaseModel):
    description_data: list[DescriptionData] = Field(...)


# --- Reference Section
class ReferenceData(BaseModel):
    url: str = Field(...)
    name: str = Field(...)
    refsource: str = Field(...)
    tags: list[str] = Field(...)


class References(BaseModel):
    reference_data: list[ReferenceData] = Field(...)


# --- ProblemType Section
class ProblemTypeDescription(BaseModel):
    lang: str | None = Field(default=None)
    value: str | None = Field(default=None)


class ProblemTypeData(BaseModel):
    description: list[ProblemTypeDescription] = Field(...)


class ProblemType(BaseModel):
    problemtype_data: list[ProblemTypeData] = Field(...)


# --- CVE Meta Info
class CVEDataMeta(BaseModel):
    ID: str = Field(...)
    ASSIGNER: str = Field(...)


# --- Main CVE Content
class CVE(BaseModel):
    data_type: str = Field(...)
    data_format: str = Field(...)
    data_version: str = Field(...)
    CVE_data_meta: CVEDataMeta = Field(...)
    problemtype: ProblemType = Field(...)
    references: References = Field(...)
    description: Description = Field(...)


class CPEMatch(BaseModel):
    vulnerable: bool = Field(...)
    criteria: str = Field(...)
    match_criteria_id: str | None = Field(default=None)
    version_start_including: str | None = Field(default=None)
    version_start_excluding: str | None = Field(default=None)
    version_end_including: str | None = Field(default=None)
    version_end_excluding: str | None = Field(default=None)


class Node(BaseModel):
    operator: str | None = Field(default="OR")
    negate: bool | None = Field(default=False)
    cpe_match: list[CPEMatch] = Field(...)


class Configuration(BaseModel):
    CVE_data_version: str = Field(...)
    nodes: list[Node] = Field(...)


class CVSSv3(BaseModel):
    version: str = Field(...)
    vector_string: str = Field(...)
    attack_vector: str = Field(...)
    attack_complexity: str = Field(...)
    privileges_required: str = Field(...)
    user_interaction: str = Field(...)
    scope: str = Field(...)
    confidentiality_impact: str = Field(...)
    integrity_impact: str = Field(...)
    availability_impact: str = Field(...)
    base_score: float = Field(...)
    base_severity: str = Field(...)


class BaseMetricV3(BaseModel):
    cvss_v3: CVSSv3 = Field(...)
    exploitability_score: float | None = Field(default=None)
    impact_score: float | None = Field(default=None)


class Impact(BaseModel):
    base_metric_v3: BaseMetricV3 | None = Field(default=None)


# --- Root CVE Item
class CVEItem(BaseModel):
    cve: CVE = Field(...)
    configurations: Configuration = Field(...)
    impact: Impact = Field(...)
    published_date: str = Field(...)
    last_modified_date: str = Field(...)
