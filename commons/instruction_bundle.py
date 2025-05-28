from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from commons.attack_patterns import ExternalReference


class IntrusionSet(BaseModel):
    type: str = Field(..., description="Object type, e.g., intrusion-set")
    id: str = Field(..., description="STIX object ID")
    created: datetime | None= Field(..., description="Creation timestamp")
    modified: datetime | None = Field(..., description="Last modification timestamp")
    name: str = Field(..., description="Name of the intrusion set")
    description: str | None = Field(
        None, description="Text description of the intrusion set",
    )
    aliases: list[str] = Field(
        ..., description="Alternative names for the intrusion set",
    )
    revoked: bool = Field(..., description="Whether the object has been revoked")
    created_by_ref: str = Field(
        ..., description="Reference to the creator (e.g., identity ID)",
    )
    external_references: list[ExternalReference] = Field(
        ...,
        description="list of external references",
    )
    object_marking_refs: list[str] = Field(
        ...,
        description="list of marking definition references",
    )
    x_mitre_deprecated: bool = Field(
        ..., description="Whether the technique is deprecated",
    )
    x_mitre_version: str | None = Field(
        None, description="Version of the technique or object",
    )
    x_mitre_contributors: list[str] | None = Field(
        None,
        description="list of contributors to the entry",
    )
    x_mitre_domains: list[str] = Field(
        ..., description="Domains where this applies (e.g., enterprise-attack)",
    )
    x_mitre_attack_spec_version: str | None = Field(
        None, description="ATT&CK spec version",
    )
    x_mitre_modified_by_ref: str | None = Field(
        None,
        description="Reference to the identity that modified the object",
    )


class IstructionBundle(BaseModel):
    type: str = Field(..., description="Object type, e.g., bundle")
    id: str = Field(..., description="STIX bundle ID")
    spec_version: str = Field(..., description="STIX spec version")
    objects: list[IntrusionSet] = Field(
        ..., description="Contained STIX domain objects",
    )
