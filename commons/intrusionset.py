from __future__ import annotations

from pydantic import BaseModel, Field

from commons.attack_patterns import ExternalReference


class IntrusionSet(BaseModel):
    type: str = Field(default="", description="Object type, e.g., intrusion-set")
    id: str = Field(default="", description="STIX object ID")
    created: str = Field(default="", description="Creation timestamp (ISO 8601 format)")
    modified: str = Field(
        default="", description="Last modification timestamp (ISO 8601 format)",
    )
    name: str = Field(default="", description="Name of the intrusion set")
    description: str = Field(
        default="", description="Text description of the intrusion set",
    )

    aliases: list[str] = Field(
        default=[], description="Alternative names for the intrusion set",
    )
    revoked: bool = Field(
        default=False, description="Whether the object has been revoked",
    )
    created_by_ref: str = Field(
        default="", description="Reference to the creator (e.g., identity ID)",
    )

    external_references: list[ExternalReference] = Field(
        default=[], description="List of external references",
    )
    object_marking_refs: list[str] = Field(
        default=[], description="List of marking definition references",
    )

    x_mitre_deprecated: bool = Field(
        default=False, description="Whether the technique is deprecated",
    )
    x_mitre_version: str = Field(
        default="", description="Version of the technique or object",
    )
    x_mitre_contributors: list[str] = Field(
        default=[], description="List of contributors to the entry",
    )
    x_mitre_domains: list[str] = Field(
        default=[], description="Domains where this applies (e.g., enterprise-attack)",
    )
    x_mitre_attack_spec_version: str = Field(
        default="", description="ATT&CK spec version",
    )
    x_mitre_modified_by_ref: str = Field(
        default="", description="Reference to the identity that modified the object",
    )
