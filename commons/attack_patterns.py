from __future__ import annotations

from pydantic import BaseModel, Field


class ExternalReference(BaseModel):
    source_name: str = Field(
        default="",
        description="Name of the source providing the reference",
    )
    external_id: str = Field(
        default="",
        description="The MITRE ATT&CK external technique ID (e.g., T1255)",
    )
    url: str = Field(default="", description="URL to the technique or external source")
    description: str = Field(default="", description="Additional context or citation")


class KillChainPhase(BaseModel):
    name: str = Field(
        default="",
        description="Kill chain name (e.g., mitre-pre-attack)",
    )
    phase: str = Field(default="", description="Phase name in the kill chain")


class DefenseDetectability(BaseModel):
    status: str = Field(
        default="",
        description="Whether the technique is detectable by common defenses",
    )
    explanation: str = Field(
        default="",
        description="Explanation of detection difficulty",
    )


class AdversaryDifficulty(BaseModel):
    status: str = Field(
        default="",
        description="Whether the technique is difficult for an adversary",
    )
    explanation: str = Field(
        default="",
        description="Explanation of adversary effort level",
    )


class NormalizedAttackPattern(BaseModel):
    id: str = Field(default="", description="STIX object ID for the attack pattern")
    name: str = Field(default="", description="Name of the attack technique or pattern")
    description: str = Field(
        default="",
        description="Short description of the technique",
    )
    external_id: str = Field(default="", description="ATT&CK external ID (e.g., T1255)")
    source_url: str = Field(default="", description="Link to the official ATT&CK page")

    kill_chain: KillChainPhase = Field(
        default_factory=KillChainPhase,
        description="Kill chain phase info",
    )
    detectable_by_defense: DefenseDetectability = Field(
        default_factory=DefenseDetectability,
        description="Detectability by common defenses",
    )
    adversary_difficulty: AdversaryDifficulty = Field(
        default_factory=AdversaryDifficulty,
        description="Difficulty level for an adversary",
    )

    deprecated: bool = Field(
        default=False,
        description="Whether the technique is marked as deprecated",
    )
    version: str = Field(default="", description="Version of the technique (e.g., 1.0)")

    created: str = Field(default="", description="Creation timestamp (ISO 8601 format)")
    modified: str = Field(
        default="",
        description="Last modification timestamp (ISO 8601 format)",
    )
