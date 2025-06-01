from __future__ import annotations

from pydantic import BaseModel, Field

from commons.attack_patterns import ExternalReference


class Relationship(BaseModel):
    id: str = Field(
        default="", description="Unique STIX ID for the relationship object",
    )
    type: str = Field(
        default="", description="STIX object type (should be 'relationship')",
    )
    relationship_type: str = Field(
        default="", description="Type of relationship (e.g., uses, indicates, etc.)",
    )
    source_ref: str = Field(default="", description="STIX ID of the source object")
    target_ref: str = Field(default="", description="STIX ID of the target object")
    description: str = Field(
        default="", description="Optional description of the relationship",
    )
    created_by_ref: str = Field(
        default="", description="Reference to the identity that created the object",
    )
    object_marking_refs: list[str] = Field(
        default_factory=list, description="List of marking definitions",
    )
    external_references: list[ExternalReference] = Field(
        default_factory=list, description="List of external references",
    )
    created: str = Field(
        default="", description="Timestamp of object creation (as ISO 8601 string)",
    )
    modified: str = Field(
        default="", description="Timestamp of last modification (as ISO 8601 string)",
    )
