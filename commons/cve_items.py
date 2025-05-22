from pydantic import BaseModel, Field
from typing import List, Optional


# --- Description Section
class DescriptionData(BaseModel):
    lang: str = Field(...)
    value: str = Field(...)

class Description(BaseModel):
    description_data: List[DescriptionData] = Field(...)


# --- Reference Section
class ReferenceData(BaseModel):
    url: str = Field(...)
    name: str = Field(...)
    refsource: str = Field(...)
    tags: List[str] = Field(...)

class References(BaseModel):
    reference_data: List[ReferenceData] = Field(...)


# --- ProblemType Section
class ProblemTypeDescription(BaseModel):
    lang: Optional[str] = Field(default=None)
    value: Optional[str] = Field(default=None)

class ProblemTypeData(BaseModel):
    description: List[ProblemTypeDescription] = Field(...)

class ProblemType(BaseModel):
    problemtype_data: List[ProblemTypeData] = Field(...)


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
    matchCriteriaId: Optional[str] = Field(default=None)
    versionStartIncluding: Optional[str] = Field(default=None)
    versionStartExcluding: Optional[str] = Field(default=None)
    versionEndIncluding: Optional[str] = Field(default=None)
    versionEndExcluding: Optional[str] = Field(default=None)


class Node(BaseModel):
    operator: Optional[str] = Field(default="OR")
    negate: Optional[bool] = Field(default=False)
    cpe_match: List[CPEMatch] = Field(...)


class Configuration(BaseModel):
    CVE_data_version: str = Field(...)
    nodes: List[Node] = Field(...)



class CVSSv3(BaseModel):
    version: str = Field(...)
    vectorString: str = Field(...)
    attackVector: str = Field(...)
    attackComplexity: str = Field(...)
    privilegesRequired: str = Field(...)
    userInteraction: str = Field(...)
    scope: str = Field(...)
    confidentialityImpact: str = Field(...)
    integrityImpact: str = Field(...)
    availabilityImpact: str = Field(...)
    baseScore: float = Field(...)
    baseSeverity: str = Field(...)


class BaseMetricV3(BaseModel):
    cvssV3: CVSSv3 = Field(...)
    exploitabilityScore: Optional[float] = Field(default=None)
    impactScore: Optional[float] = Field(default=None)


class Impact(BaseModel):
    baseMetricV3: Optional[BaseMetricV3] = Field(default=None)
# --- Root CVE Item
class CVEItem(BaseModel):
    cve: CVE = Field(...)
    configurations: Configuration = Field(...)
    impact: Impact = Field(...)
    publishedDate: str = Field(...)
    lastModifiedDate: str = Field(...)
