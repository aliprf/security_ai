from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from commons.attack_patterns import ExternalReference


class Relationship(BaseModel):
    id: str = Field(..., description="Unique STIX ID for the relationship object")
    type: str = Field(..., description="STIX object type (should be 'relationship')")

    relationship_type: str = Field(
        ...,
        description="Type of relationship (e.g., uses, indicates, etc.)",
    )
    source_ref: str = Field(..., description="STIX ID of the source object")
    target_ref: str = Field(..., description="STIX ID of the target object")

    description: str | None = Field(
        default=None,
        description="Optional description of the relationship",
    )
    created_by_ref: str | None = Field(
        default=None,
        description="Reference to the identity that created the object",
    )
    object_marking_refs: list[str] | None = Field(
        default=None,
        description="List of marking definitions",
    )
    external_references: list[ExternalReference] | None = Field(
        default=None,
        description="List of external references",
    )
    created: datetime | None = Field(
        default=None,
        description="Timestamp of object creation",
    )
    modified: datetime | None = Field(
        default=None,
        description="Timestamp of last modification",
    )
