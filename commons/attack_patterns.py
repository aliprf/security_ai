from typing import Optional
from pydantic import BaseModel, Field
from datetime import datetime


class ExternalReference(BaseModel):
    source_name: str = Field(..., description="Name of the source providing the reference")
    external_id: Optional[str] = Field(None, description="The MITRE ATT&CK external technique ID (e.g., T1255)")
    url: Optional[str] = Field(None, description="URL to the technique or external source")
    description: Optional[str] = Field(None, description="Additional context or citation")


class KillChainPhase(BaseModel):
    name: str = Field(..., description="Kill chain name (e.g., mitre-pre-attack)")
    phase: str = Field(..., description="Phase name in the kill chain")


class DefenseDetectability(BaseModel):
    status: Optional[str] = Field(None, description="Whether the technique is detectable by common defenses")
    explanation: Optional[str] = Field(None, description="Explanation of detection difficulty")


class AdversaryDifficulty(BaseModel):
    status: Optional[str] = Field(None, description="Whether the technique is difficult for an adversary")
    explanation: Optional[str] = Field(None, description="Explanation of adversary effort level")


class NormalizedAttackPattern(BaseModel):
    id: str = Field(..., description="STIX object ID for the attack pattern")
    name: str = Field(..., description="Name of the attack technique or pattern")
    description: Optional[str] = Field(None, description="Short description of the technique")
    
    external_id: Optional[str] = Field(None, description="ATT&CK external ID (e.g., T1255)")
    source_url: Optional[str] = Field(None, description="Link to the official ATT&CK page")
    
    kill_chain: Optional[KillChainPhase] = Field(None, description="Kill chain phase info")
    detectable_by_defense: Optional[DefenseDetectability] = Field(None, description="Detectability by common defenses")
    adversary_difficulty: Optional[AdversaryDifficulty] = Field(None, description="Difficulty level for an adversary")
    
    deprecated: bool = Field(False, description="Whether the technique is marked as deprecated")
    version: Optional[str] = Field(None, description="Version of the technique (e.g., 1.0)")
    
    created: Optional[datetime] = Field(None, description="Creation timestamp")
    modified: Optional[datetime] = Field(None, description="Last modification timestamp")
